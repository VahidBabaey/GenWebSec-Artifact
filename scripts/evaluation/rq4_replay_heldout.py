#!/usr/bin/env python3
"""
RQ4 Phase-2 replay harness (freeze-then-replay) -- FULL DETAIL, per (attack-seed x page).

Replay a FROZEN held-out attack set (valid + CRS-bypassing) IDENTICALLY against each
per-seed CG rule set, on top of CRS, and record EVERYTHING:
  - per rule set: the exact re-IDed rules loaded
  - per rule set x per attack: blocked (HTTP 403) or bypassed, with WAF status
  - per rule set: the explicit list of bypassing payloads

Parameters (env): A1_TARGET=juice (default), A1_PAGE=login|search (default login), A1_SEED (default 1).
Reads frozen winners from
  results/V2/A1_HeldOut/A1_juice_heldout_seed{A1_SEED}/A1_juice_{A1_PAGE}_winners.txt
and writes ALL replay outputs into that seed folder's Defense_results/ subfolder, named by page.

Rule sets: {CG-Adaptive (C1), CG-Static (D1)} x seeds 1..10 (eps0.3, SQLi family; per-seed set =
union of login/search/product/filter, re-IDed above CRS's 900000-999999 band). Same SQLi rule sets
apply to any SQLi page (login or search).

Reuses the pilot's own WAF send path (byte-identical to generation); blocked <=> WAF returns HTTP 403.
"""
import os, sys, re, statistics, csv

ROOT = "/path/to/GenWebSec"
os.environ.setdefault("A1_TARGET", "juice")
os.environ.setdefault("A1_PAGE", "login")
os.environ.setdefault("A1_SEED", "1")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A1_sqli_attack_only_v2 as pilot
pilot.log_print = lambda *a, **k: None            # never touch the frozen result log
pilot.ensure_backend_up = lambda *a, **k: False   # replay is rule-driven (403 is pre-proxy) -> skip slow backend-recovery waits on a flapping backend
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache

WAF = pilot.WAF                                    # target-based: http://localhost/<target>
ATARGET = os.environ["A1_TARGET"]
APAGE = os.environ["A1_PAGE"]
ASEED = os.environ["A1_SEED"]
EPS = os.environ.get("RQ4_EPS", "0.3")             # clustering epsilon of the CG rule sets to test
RES = os.path.join(ROOT, "results", "V2", "A1_HeldOut", f"A1_{ATARGET}_heldout_seed{ASEED}")
DEF0 = os.path.join(RES, "Defense_results")
DEF = DEF0 if EPS == "0.3" else os.path.join(DEF0, f"eps{EPS}")   # 0.3 stays at Defense_results/ root; others in eps<E>/
WINNERS = os.path.join(RES, f"A1_{ATARGET}_{APAGE}_winners.txt")
RSDIR = os.path.join(DEF, "rq4_rulesets")
STEM = f"rq4_replay_{ATARGET}_{APAGE}_seed{ASEED}"

SEEDS = list(range(1, 11))
PAGES = ["login", "search", "product", "filter"]
SECRULE = re.compile(r"^\s*SecRule\b")
IDPAT = re.compile(r"id:\d+")


def rule_files(tech, seed):
    if tech == "CG-Adaptive":
        base = f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps{EPS}_seed{seed}"
        return [(p, f"{base}/C1_customapp_{p}_clustering_rules.txt") for p in PAGES]
    base = f"{ROOT}/results/V2/CustomApp_D1/CustomApp_D1_eps{EPS}_seed{seed}"
    return [(p, f"{base}/D1_customapp_{p}_clustering_rules.txt") for p in PAGES]


def build_ruleset(tech, seed):
    raw, missing = [], []
    for page, fp in rule_files(tech, seed):
        if not os.path.exists(fp):
            missing.append(os.path.basename(fp)); continue
        with open(fp, encoding="utf-8") as f:
            for line in f:
                if SECRULE.match(line):
                    raw.append((page, line.strip()))
    out, nid = [], 1000001
    for page, r in raw:
        out.append((page, IDPAT.sub(f"id:{nid}", r, count=1))); nid += 1
    return out, missing


def load_attacks():
    seen, atk = set(), []
    with open(WINNERS, encoding="utf-8") as f:
        for line in f:
            s = line.rstrip("\n")
            if not s or s.startswith("#"):
                continue
            if s not in seen:
                seen.add(s); atk.append(s)
    return atk


def set_waf(rules):
    write_rules(rules)
    ok, out = run_configtest()
    if ok:
        reload_apache(timeout=30.0)
    return ok, out


def run_ruleset(rules, attacks):
    ok, out = set_waf([r for _, r in rules])
    if not ok:
        return None, out
    recs = []
    for i, p in enumerate(attacks):
        st = pilot.send(WAF, p)[0]
        recs.append((i, p, st, 1 if st == 403 else 0))
    return recs, out


def main():
    os.makedirs(DEF, exist_ok=True)
    os.makedirs(RSDIR, exist_ok=True)
    attacks = load_attacks()
    N = len(attacks)
    print(f"[replay] page={APAGE} attack-seed={ASEED}  frozen distinct winners loaded: {N}", flush=True)

    configs = [("CRS-only", "CRS-only", 0, [])]
    for tech in ("CG-Adaptive", "CG-Static"):
        for seed in SEEDS:
            rules, missing = build_ruleset(tech, seed)
            if missing:
                print(f"[warn] {tech} seed{seed} missing: {missing}", flush=True)
            configs.append((f"{tech}_seed{seed}", tech, seed, rules))

    for label, tech, seed, rules in configs:
        if label == "CRS-only":
            continue
        with open(os.path.join(RSDIR, f"{label}.conf"), "w", encoding="utf-8") as f:
            f.write(f"# {tech} seed{seed}  eps0.3  SQLi  (union of {len(rules)} rules across pages, re-IDed)\n")
            for page, r in rules:
                f.write(f"# from page: {page}\n{r}\n")

    detail, order, summary_rows = {}, [], []
    for label, tech, seed, rules in configs:
        recs, out = run_ruleset(rules, attacks)
        detail[label] = (tech, seed, rules, recs)
        order.append(label)
        if recs is None:
            print(f"[{label}] CONFIGTEST FAILED ({len(rules)} rules)", flush=True)
            summary_rows.append((tech, seed, len(rules), None, N, None, "configtest_fail"))
            continue
        blk = sum(r[3] for r in recs)
        summary_rows.append((tech, seed, len(rules), blk, N, 100.0 * blk / N, "ok"))
        print(f"[{label}] rules={len(rules):2d}  blocked={blk:3d}/{N}  = {100.0*blk/N:5.1f}%  bypassed={N-blk}", flush=True)

    set_waf([])
    print("[replay] WAF restored to CRS-only baseline", flush=True)

    # ---------- (1) per-attack matrix CSV ----------
    with open(os.path.join(DEF, f"{STEM}_perattack.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "attack_idx", "waf_status", "blocked", "payload"])
        for label in order:
            tech, seed, rules, recs = detail[label]
            if recs is None:
                continue
            for i, p, st, b in recs:
                w.writerow([tech, seed, i, st, b, p])

    # ---------- (2) per-ruleset summary CSV ----------
    with open(os.path.join(DEF, f"{STEM}_per_ruleset.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "n_rules", "blocked", "total_attacks", "block_rate_pct", "bypassed", "status"])
        for (tech, seed, nr, blk, tot, rate, st) in summary_rows:
            w.writerow([tech, seed, nr, blk, tot, (f"{rate:.4f}" if rate is not None else ""),
                        (tot - blk if blk is not None else ""), st])

    # ---------- (3) DETAIL txt ----------
    with open(os.path.join(DEF, f"{STEM}_DETAIL.txt"), "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"RQ4 Phase-2 replay -- FULL DETAIL  |  {ATARGET} / {APAGE} / attacker-seed {ASEED}\n")
        f.write("=" * 80 + "\n")
        f.write(f"Frozen held-out set: {N} distinct valid+CRS-bypassing winners\n")
        f.write(f"  source: A1_{ATARGET}_{APAGE}_winners.txt (deduped)\n")
        f.write("blocked = WAF HTTP 403 ; bypassed = anything else (attack passed the WAF)\n\n")
        for label in order:
            tech, seed, rules, recs = detail[label]
            f.write("#" * 80 + "\n")
            if recs is None:
                f.write(f"{label}  |  CONFIGTEST FAILED ({len(rules)} rules)\n" + "#" * 80 + "\n\n")
                continue
            blk = sum(r[3] for r in recs)
            byp = [(i, p, st) for (i, p, st, b) in recs if b == 0]
            f.write(f"{label}  |  rules={len(rules)}  blocked={blk}/{N} ({100.0*blk/N:.1f}%)  bypassed={len(byp)}\n")
            f.write("#" * 80 + "\n")
            if label == "CRS-only":
                f.write("-- rules -- none (CRS baseline)\n")
                f.write(f"-- BYPASSED ({len(byp)}) -- all {N} bypass CRS by construction (= the frozen set); see winners file.\n\n")
                continue
            f.write("-- rules loaded (re-IDed, on top of CRS) --\n")
            for page, r in rules:
                f.write(f"  [{page}] {r}\n")
            if byp:
                f.write(f"-- BYPASSED ({len(byp)})  [idx | waf_status | payload] --\n")
                for i, p, st in byp:
                    f.write(f"  {i:>3} | {st:>3} | {p}\n")
            else:
                f.write("-- BYPASSED (0) -- none (100% blocked)\n")
            f.write("\n")

    # ---------- (4) summary txt ----------
    def agg(tech):
        rr = [r for r in summary_rows if r[0] == tech and r[6] == "ok"]
        return rr, [r[5] for r in rr], [r[2] for r in rr]

    def fmt_rate(rates):
        if not rates:
            return "n/a"
        m = statistics.mean(rates); sd = statistics.stdev(rates) if len(rates) > 1 else 0.0
        return f"{m:.1f}+/-{sd:.1f}  (median {statistics.median(rates):.1f} [{min(rates):.1f}--{max(rates):.1f}])"

    def fmt_cnt(counts):
        return "n/a" if not counts else f"median {int(statistics.median(counts))} [{min(counts)}--{max(counts)}]"

    base_blk = next(r[3] for r in summary_rows if r[0] == "CRS-only")
    L = ["=" * 78, f"RQ4 Phase-2 replay  |  {ATARGET} / {APAGE} / attacker-seed {ASEED}", "=" * 78,
         f"Frozen held-out set: {N} distinct valid+CRS-bypassing winners",
         f"  source: results/V2/A1_HeldOut/A1_{ATARGET}_heldout_seed{ASEED}/A1_{ATARGET}_{APAGE}_winners.txt",
         f"Replay: identical set via the pilot's WAF send (page={APAGE}) ; blocked = HTTP 403",
         "Rule sets: per-seed union of SQLi pages (login/search/product/filter), eps0.3, re-IDed, on CRS",
         "", f"CRS-only baseline (0 custom rules): blocked {base_blk}/{N} = {100.0*base_blk/N:.1f}%   (sanity: ~0 expected)", ""]
    for tech in ("CG-Adaptive", "CG-Static"):
        rr, rates, counts = agg(tech)
        L.append(f"{tech}  (n={len(rr)} seeds ok)")
        for r in rr:
            L.append(f"    seed{r[1]:>2}: rules={r[2]:>2}  blocked={r[3]:>3}/{r[4]}  = {r[5]:>5.1f}%  bypassed={r[4]-r[3]}")
        for r in [x for x in summary_rows if x[0] == tech and x[6] != "ok"]:
            L.append(f"    seed{r[1]:>2}: CONFIGTEST FAILED (rules={r[2]})")
        L.append(f"  block rate: {fmt_rate(rates)}")
        L.append(f"  rule count: {fmt_cnt(counts)}")
        L.append("")
    _, ra, _ = agg("CG-Adaptive"); _, rs, _ = agg("CG-Static")
    if ra and rs:
        L.append(f"Adaptive mean {statistics.mean(ra):.1f}%  vs  Static mean {statistics.mean(rs):.1f}%   "
                 f"(delta = {statistics.mean(ra)-statistics.mean(rs):+.1f} pts, Adaptive - Static)")
    L.append("=" * 78)
    with open(os.path.join(DEF, f"{STEM}_summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print(f"\n[replay] wrote outputs under results/V2/A1_HeldOut/A1_{ATARGET}_heldout_seed{ASEED}/Defense_results/", flush=True)


if __name__ == "__main__":
    main()
