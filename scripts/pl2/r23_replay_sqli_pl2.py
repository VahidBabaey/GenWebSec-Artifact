#!/usr/bin/env python3
"""R2.3 PL2 replay (SQLi) -- one (target, page, attacker-seed) per invocation (env A1_TARGET/A1_PAGE/A1_SEED).

Same freeze-then-replay as rq4_replay_heldout.py, but:
  (1) the replay client sends browser-like headers so CRS PL2 scanner/header rules (913101 User-Agent,
      920300 missing Accept) score the CLIENT, not the payload -- this isolates the paranoia-level effect
      on the attack content and the generated rules;
  (2) outputs go under results/V2/RevisionNewResults/R2.3/PL2/sqli/ and NEVER touch the PL1 files;
  (3) each attack is scored with pilot.probe(): blocked = HTTP 403; a non-403 counts as a VERIFIED bypass
      only when the exploit oracle still fires (R1.1), and non-403-without-exploit is reported as a
      transport/other failure, not a bypass.

Paranoia level is set on the host (crs-setup.conf) OUTSIDE this script; run only while PL2 is active.
"""
import os, sys, re, csv

ROOT = "/home/vahid/Projects/GenWebSec"
os.environ.setdefault("A1_TARGET", "customapp")
os.environ.setdefault("A1_PAGE", "login")
os.environ.setdefault("A1_SEED", "1")
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A1_sqli_attack_only_v2 as pilot
pilot.log_print = lambda *a, **k: None
pilot.ensure_backend_up = lambda *a, **k: True   # bwapp/juice containers are up; probe recovers on -1/503
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache

# (1) browser-like headers -> neutralize PL2 913101 (scripting UA) and 920300 (missing Accept)
pilot.OPENER.addheaders = [
    ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
    ("Accept-Language", "en-US,en;q=0.9"),
]

WAF = pilot.WAF
ATARGET = os.environ["A1_TARGET"]; APAGE = os.environ["A1_PAGE"]; ASEED = os.environ["A1_SEED"]
EPS = "0.3"
RES = os.path.join(ROOT, "results", "V2", "A1_HeldOut", f"A1_{ATARGET}_heldout_seed{ASEED}")
WINNERS = os.path.join(RES, f"A1_{ATARGET}_{APAGE}_winners.txt")
OUT = os.path.join(ROOT, "results", "V2", "RevisionNewResults", "R2.3", "PL2", "sqli",
                   f"{ATARGET}_{APAGE}_seed{ASEED}")
STEM = f"r23pl2_{ATARGET}_{APAGE}_seed{ASEED}"
SEEDS = list(range(1, 11))
PAGES = ["login", "search", "product", "filter"]
SECRULE = re.compile(r"^\s*SecRule\b"); IDPAT = re.compile(r"id:\d+")


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


def run_config(rules):
    ok, out = set_waf(rules)
    if not ok:
        return None, out
    recs = []
    for i, p in enumerate(load_attacks.cache):
        pr = pilot.probe(WAF, p)
        st = pr["status"]
        recs.append((i, st, 1 if st == 403 else 0, 1 if (st != 403 and pr["valid"]) else 0))
    return recs, out


def main():
    os.makedirs(OUT, exist_ok=True)
    load_attacks.cache = load_attacks()
    N = len(load_attacks.cache)
    print(f"[r23pl2] {ATARGET}/{APAGE} seed{ASEED}: {N} frozen winners", flush=True)

    configs = [("CRS-only", "CRS-only", 0, [])]
    for tech in ("CG-Adaptive", "CG-Static"):
        for seed in SEEDS:
            rules, missing = build_ruleset(tech, seed)
            if missing:
                print(f"[warn] {tech} seed{seed} missing {missing}", flush=True)
            configs.append((f"{tech}_seed{seed}", tech, seed, rules))

    rows, perattack = [], []
    for label, tech, seed, rules in configs:
        recs, out = run_config(rules)
        if recs is None:
            print(f"[{label}] CONFIGTEST FAIL", flush=True)
            rows.append((tech, seed, len(rules), "", N, "", "", "configtest_fail")); continue
        blk = sum(r[2] for r in recs); vby = sum(r[3] for r in recs); other = N - blk - vby
        rows.append((tech, seed, len(rules), blk, N, vby, other, "ok"))
        for i, st, b, v in recs:
            perattack.append((tech, seed, i, st, b, v))
        print(f"[{label}] rules={len(rules):2d} blocked={blk:3d}/{N} verified_bypass={vby} other={other}", flush=True)

    set_waf([])  # restore CRS-only
    with open(os.path.join(OUT, f"{STEM}_per_config.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "n_rules", "blocked", "total", "verified_bypass", "other_nonblock", "status"])
        w.writerows(rows)
    with open(os.path.join(OUT, f"{STEM}_perattack.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique", "cg_seed", "attack_idx", "waf_status", "blocked", "verified_bypass"])
        w.writerows(perattack)
    print(f"[r23pl2] wrote {OUT}", flush=True)


if __name__ == "__main__":
    main()
