#!/usr/bin/env python3
"""Aggregate the RQ1 app re-replay (SQLi + XSS) and compare to the stored-records RQ1 figures."""
import csv, os
B = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq1_replay"
def rint(x):
    try: return int(float(x))
    except Exception: return 0
print("="*74)
print("R1.1 RQ1 APP RE-REPLAY — independent re-verification of every RQ1 bypass")
print("="*74)
for fam, fn, bcol in (("SQLi","rq1_sqli_replay_summary.csv","bypass_not403"),
                      ("XSS","rq1_xss_replay_summary.csv","bypass_not403")):
    p = f"{B}/{fn}"
    if not os.path.exists(p):
        print(f"[{fam}] (no file)"); continue
    rows = list(csv.DictReader(open(p)))
    nruns = len(rows)
    nw = sum(rint(r["n_winners"]) for r in rows)
    byp = sum(rint(r.get("bypass_not403",0)) for r in rows)
    exp = sum(rint(r["exploit_through_waf"]) for r in rows)
    false_b = sum(rint(r["false_bypass"]) for r in rows)
    print(f"[{fam}] runs={nruns}  winners={nw}  bypass(not403)={byp}  exploit_through_waf={exp}  FALSE_BYPASS={false_b}")
print("="*74)
