#!/usr/bin/env python3
"""R2.3 PL2 replay (XSS) -- one (target, page, attacker-seed) per invocation.
   env: A2_TARGET (customxss|bwapp); customxss page via CXSS_PAGE (search|calc); bwapp via A2_PAGE; A2_SEED.

Like rq4_replay_xss.py but: (1) browser-like headers neutralize PL2 913101/920300 so blocking reflects the
payload, not the client; (2) outputs go under results/V2/RevisionNewResults/R2.3/PL2/xss/ (PL1 untouched);
(3) records waf_status per attack so non-403s can be split into status-200 bypass candidates (R1.1: same
payload + same backend + deny-only rules => same execution that was confirmed at validation) vs transport
errors. Run only while host CRS PL2 is active."""
import os, sys, re, csv

ROOT = "/home/vahid/Projects/GenWebSec"
os.environ.setdefault("A2_TARGET", "customxss")
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))
import pilot_A2_customxss_attack_only_heldout as pilot
pilot.log_print = lambda *a, **k: None
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache

pilot.OPENER.addheaders = [
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
]

if pilot.A2_TARGET == "bwapp":          # bwapp XSS pages need an authenticated session (cookie in OPENER)
    try:
        pilot.establish_session()
        print("[r23pl2-xss] bwapp session established", flush=True)
    except Exception as e:
        print(f"[warn] bwapp session failed: {e}", flush=True)
WAF = pilot.WAF; ATARGET = pilot.A2_TARGET; APAGE = pilot.PAGE; ASEED = os.environ.get("A2_SEED", "1")
EPS = "0.3"
WINNERS = str(pilot.WINNERS_FILE)
OUT = os.path.join(ROOT, "results", "V2", "RevisionNewResults", "R2.3", "PL2", "xss",
                   f"{ATARGET}_{APAGE}_seed{ASEED}")
STEM = f"r23pl2_xss_{ATARGET}_{APAGE}_seed{ASEED}"
SEEDS = list(range(1, 11)); XSS_PAGES = ["search", "calc"]
SECRULE = re.compile(r"^\s*SecRule\b"); IDPAT = re.compile(r"id:\d+")


def rule_files(tech, seed):
    if tech == "CG-Adaptive":
        base = f"{ROOT}/results/V2/CustomApp_C2/CustomXSS_C2_Token_eps{EPS}_seed{seed}"
        return [(p, f"{base}/C2_customxss_{p}_clustering_rules.txt") for p in XSS_PAGES]
    base = f"{ROOT}/results/V2/CustomApp_D2/CustomXSS_D2_eps{EPS}_seed{seed}"
    return [(p, f"{base}/D2_customxss_{p}_clustering_rules.txt") for p in XSS_PAGES]


def build_ruleset(tech, seed):
    raw, missing = [], []
    for page, fp in rule_files(tech, seed):
        if not os.path.exists(fp):
            missing.append(os.path.basename(fp)); continue
        for line in open(fp, encoding="utf-8"):
            if SECRULE.match(line):
                raw.append(line.strip())
    out, nid = [], 1000001
    for r in raw:
        out.append(IDPAT.sub(f"id:{nid}", r, count=1)); nid += 1
    return out, missing


def load_attacks():
    seen, atk = set(), []
    for line in open(WINNERS, encoding="utf-8", errors="replace"):
        s = line.rstrip("\n")
        if s and not s.startswith("#") and s not in seen:
            seen.add(s); atk.append(s)
    return atk


def set_waf(rules):
    write_rules(rules); ok, out = run_configtest()
    if ok:
        reload_apache(timeout=30.0)
    return ok, out


def run_config(rules, attacks):
    ok, out = set_waf(rules)
    if not ok:
        return None
    recs = []
    for i, p in enumerate(attacks):
        url, _ = pilot.build_url(WAF, p)
        st = pilot.http_status(url)
        blocked = 1 if st == 403 else 0
        cand = 1 if st == 200 else 0           # non-403 & 200 = execution-carrying bypass candidate (R1.1)
        recs.append((i, st, blocked, cand))
    return recs


def main():
    os.makedirs(OUT, exist_ok=True)
    attacks = load_attacks()
    N = len(attacks)
    print(f"[r23pl2-xss] {ATARGET}/{APAGE} seed{ASEED}: {N} frozen winners", flush=True)
    configs = [("CRS-only", "CRS-only", 0, [])]
    for tech in ("CG-Adaptive", "CG-Static"):
        for seed in SEEDS:
            rules, missing = build_ruleset(tech, seed)
            if missing:
                print(f"[warn] {tech} seed{seed} missing {missing}", flush=True)
            configs.append((f"{tech}_seed{seed}", tech, seed, rules))

    rows, perattack = [], []
    for label, tech, seed, rules in configs:
        recs = run_config(rules, attacks)
        if recs is None:
            print(f"[{label}] CONFIGTEST FAIL", flush=True)
            rows.append((tech, seed, len(rules), "", N, "", "", "configtest_fail")); continue
        blk = sum(r[2] for r in recs); cand = sum(r[3] for r in recs); other = N - blk - cand
        rows.append((tech, seed, len(rules), blk, N, cand, other, "ok"))
        for i, st, b, c in recs:
            perattack.append((tech, seed, i, st, b, c, attacks[i]))
        print(f"[{label}] rules={len(rules):2d} blocked={blk:3d}/{N} bypass200={cand} other={other}", flush=True)

    set_waf([])
    with open(os.path.join(OUT, f"{STEM}_per_config.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "n_rules", "blocked", "total", "bypass200", "other_nonblock", "status"])
        w.writerows(rows)
    with open(os.path.join(OUT, f"{STEM}_perattack.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "attack_idx", "waf_status", "blocked", "bypass200", "payload"])
        w.writerows(perattack)
    print(f"[r23pl2-xss] wrote {OUT}", flush=True)


if __name__ == "__main__":
    main()
