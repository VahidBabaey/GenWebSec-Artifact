#!/usr/bin/env python3
"""
Item 8 (XSS) Dalfox track -- CG-rule replay.

Replay the frozen 45 Dalfox CRS-bypassing winners against CG-Static (D2) and
CG-Adaptive (C2) XSS rule sets, eps0.3, seeds 1-10, on top of CRS. blocked <=> 403.
Each winner is sent to ITS OWN page (search.php?q= / calc.php?expr=).

Reuses pilot_A2 build_url + http_status; string-op rule parsing (no re).

Reads : xss_dalfox/crs/crs_bypassing.tsv
Writes: xss_dalfox/replay/{per_ruleset.csv, perattack.csv, summary.txt}
"""
import os
import sys
import statistics
import csv

ROOT = "/path/to/GenWebSec"
os.environ.setdefault("CXSS_PAGE", "search")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A2_customxss_attack_only_v2 as pilot          # noqa: E402
pilot.log_print = lambda *a, **k: None
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache   # noqa: E402

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results/xss_dalfox")
WINNERS = os.path.join(BASE, "crs", "crs_bypassing.tsv")
OUT = os.path.join(BASE, "replay")
os.makedirs(OUT, exist_ok=True)

WAF = pilot.WAF
EPS = "0.3"
SEEDS = list(range(1, 11))
XSS_PAGES = ["search", "calc"]
PAGE_CFG = {"search": ("search.php", "q"), "calc": ("calc.php", "expr")}


def rule_files(tech, seed):
    if tech == "CG-Adaptive":
        base = "%s/results/V2/CustomApp_C2/CustomXSS_C2_Token_eps%s_seed%d" % (ROOT, EPS, seed)
        return [(p, "%s/C2_customxss_%s_clustering_rules.txt" % (base, p)) for p in XSS_PAGES]
    base = "%s/results/V2/CustomApp_D2/CustomXSS_D2_eps%s_seed%d" % (ROOT, EPS, seed)
    return [(p, "%s/D2_customxss_%s_clustering_rules.txt" % (base, p)) for p in XSS_PAGES]


def reid(rule, newid):
    i = rule.find("id:")
    if i < 0:
        return rule
    j = i + 3
    k = j
    while k < len(rule) and rule[k].isdigit():
        k += 1
    return rule[:j] + str(newid) + rule[k:]


def build_ruleset(tech, seed):
    raw, missing = [], []
    for page, fp in rule_files(tech, seed):
        if not os.path.exists(fp):
            missing.append(os.path.basename(fp))
            continue
        with open(fp, encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("SecRule"):
                    raw.append((page, line.strip()))
    out, nid = [], 1000001
    for page, r in raw:
        out.append((page, reid(r, nid)))
        nid += 1
    return out, missing


def load_winners():
    rows = []
    with open(WINNERS, encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < len(header):
                parts += [""] * (len(header) - len(parts))
            rows.append(dict(zip(header, parts)))
    return rows


def set_waf(rules):
    write_rules(rules)
    ok, out = run_configtest()
    if ok:
        reload_apache(timeout=30.0)
    return ok, out


def waf_block(page, payload):
    pilot.PAGE, (pilot.PAGE_FILE, pilot.PARAM) = page, PAGE_CFG[page]
    url, _ = pilot.build_url(WAF, payload)
    return 1 if pilot.http_status(url) == 403 else 0


def main():
    winners = load_winners()
    N = len(winners)
    print("[replay] %d Dalfox XSS winners (CRS-bypassing)" % N, flush=True)

    configs = [("CRS-only", "CRS-only", 0, [])]
    for tech in ("CG-Adaptive", "CG-Static"):
        for seed in SEEDS:
            rules, missing = build_ruleset(tech, seed)
            if missing:
                print("[warn] %s seed%d missing: %s" % (tech, seed, missing), flush=True)
            configs.append(("%s_seed%d" % (tech, seed), tech, seed, rules))

    summary = []
    perattack = []
    for label, tech, seed, rules in configs:
        ok, out = set_waf([r for _, r in rules])
        if not ok:
            print("[%s] CONFIGTEST FAILED (%d rules)" % (label, len(rules)), flush=True)
            summary.append((tech, seed, len(rules), None))
            continue
        blk = 0
        for w in winners:
            b = waf_block(w["page"], w["final_payload"])
            blk += b
            perattack.append((tech, seed, w["page"], w.get("js_payload", ""), b, w["final_payload"]))
        summary.append((tech, seed, len(rules), blk))
        if label == "CRS-only":
            print("[CRS-only] blocked=%d/%d = %.1f%% (sanity ~0)" % (blk, N, 100.0 * blk / N), flush=True)
        else:
            print("[%s] rules=%2d blocked=%3d/%d = %5.1f%% bypassed=%d"
                  % (label, len(rules), blk, N, 100.0 * blk / N, N - blk), flush=True)

    set_waf([])
    print("[replay] WAF restored to CRS-only", flush=True)

    # ---- per_ruleset.csv ----
    with open(os.path.join(OUT, "per_ruleset.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "n_rules", "blocked", "total", "block_rate_pct", "bypassed"])
        for (tech, seed, nr, blk) in summary:
            rate = ("%.4f" % (100.0 * blk / N)) if blk is not None else ""
            w.writerow([tech, seed, nr, (blk if blk is not None else ""), N, rate,
                        (N - blk if blk is not None else "")])

    # ---- perattack.csv ----
    with open(os.path.join(OUT, "perattack.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "page", "js_payload", "blocked", "final_payload"])
        for row in perattack:
            w.writerow(row)

    # ---- summary.txt ----
    def agg(tech):
        rr = [r for r in summary if r[0] == tech and r[3] is not None]
        return rr, [100.0 * r[3] / N for r in rr], [r[2] for r in rr]

    base_blk = next(r[3] for r in summary if r[0] == "CRS-only")
    L = ["=" * 74,
         "Item 8 (XSS) Dalfox -- CG-rule replay  (45 non-LLM CRS-bypassing winners)",
         "=" * 74,
         "Frozen winners: %d distinct valid + CRS-bypassing Dalfox JS-context payloads" % N,
         "Rule sets: per-seed union of XSS pages (search+calc), C2/D2 eps0.3, re-IDed, on CRS",
         "blocked = WAF HTTP 403",
         "", "CRS-only baseline: blocked %d/%d = %.1f%%  (sanity: ~0 expected)" % (base_blk, N, 100.0 * base_blk / N), ""]
    for tech in ("CG-Adaptive", "CG-Static"):
        rr, rates, counts = agg(tech)
        L.append("%s  (n=%d seeds)" % (tech, len(rr)))
        for r in rr:
            L.append("    seed%2d: rules=%2d  blocked=%3d/%d = %5.1f%%  bypassed=%d"
                     % (r[1], r[2], r[3], N, 100.0 * r[3] / N, N - r[3]))
        if rates:
            m = statistics.mean(rates)
            sd = statistics.stdev(rates) if len(rates) > 1 else 0.0
            L.append("  block rate: %.1f+/-%.1f  (median %.1f [%.1f--%.1f])"
                     % (m, sd, statistics.median(rates), min(rates), max(rates)))
        L.append("")
    _, ra, _ = agg("CG-Adaptive")
    _, rs, _ = agg("CG-Static")
    if ra and rs:
        L.append("Adaptive mean %.1f%%  vs  Static mean %.1f%%   (delta = %+.1f pts)"
                 % (statistics.mean(ra), statistics.mean(rs), statistics.mean(ra) - statistics.mean(rs)))
    L.append("=" * 74)
    with open(os.path.join(OUT, "summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n" + "\n".join(L))
    print("\n[replay] wrote outputs under %s" % OUT)


if __name__ == "__main__":
    main()
