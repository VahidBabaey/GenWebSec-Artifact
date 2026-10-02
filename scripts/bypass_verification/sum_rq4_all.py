#!/usr/bin/env python3
"""Consolidated R1.1 RQ4 two-stage re-verification (residual bypasses, eps0.3).
Reads rq4_sqli_summary.csv + rq4_xss_summary.csv and reports, per target, the residual bypasses
re-probed, how many were re-confirmed as real exploits through the WAF, and false bypasses."""
import csv, os, collections
BASE = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq4"
def rint(x):
    try: return int(float(x))
    except Exception: return 0
print("="*78)
print("R1.1 RQ4 HELD-OUT FROZEN-REPLAY — two-stage re-verification of residual bypasses (eps0.3)")
print("="*78)
grand = collections.Counter()
for fam, fn in (("SQLi", "rq4_sqli_summary.csv"), ("XSS", "rq4_xss_summary.csv")):
    p = f"{BASE}/{fn}"
    if not os.path.exists(p):
        print(f"\n[{fam}] (no file yet: {fn})"); continue
    rows = list(csv.DictReader(open(p)))
    bytt = collections.defaultdict(lambda: collections.Counter())
    for r in rows:
        t = bytt[r["target"]]
        t["reported"] += rint(r["reported_bypasses"]); t["not403"] += rint(r["reprobe_not403"])
        t["exploit"] += rint(r["verified_exploit"]); t["false"] += rint(r["false_bypass"]); t["now403"] += rint(r["now_403"])
        t["groups"] += 1
    print(f"\n[{fam}]  ({len(rows)} ruleset-groups across targets/pages)")
    for tgt in sorted(bytt):
        c = bytt[tgt]
        print(f"  {tgt:<10} reported_bypasses={c['reported']:>6}  reprobe_not403={c['not403']:>6}  "
              f"real_exploit={c['exploit']:>6}  FALSE_BYPASS={c['false']:>3}  reclassified_now403={c['now403']:>3}")
        for k in ("reported","not403","exploit","false","now403"): grand[k]+=c[k]
print("\n" + "-"*78)
print(f"GRAND TOTAL  residual bypasses re-probed={grand['reported']}  "
      f"re-confirmed real exploits={grand['exploit']}  FALSE BYPASSES={grand['false']}  reclassified={grand['now403']}")
print("="*78)
