#!/usr/bin/env python3
"""Close two audit nits: (1) confirm customxss/search/CG-Adaptive/seed8 genuinely had 0 residual
bypasses at eps0.3 (so no row was dropped); (2) recompute the RQ1 headline from rq1_summary.csv."""
import csv, glob
from collections import Counter

print("=== nit 1: customxss residual bypasses by (page,technique,seed) at eps0.3 ===")
c = Counter()
for f in glob.glob("/home/vahid/Projects/GenWebSec/results/V2/A2_HeldOut/A2_customxss_heldout_seed*/Defense_results/rq4_replay_customxss_*_perattack.csv"):
    if "/eps0." in f:
        continue
    page = "calc" if "_calc_" in f else ("search" if "_search_" in f else "?")
    for r in csv.DictReader(open(f, encoding="utf-8", errors="replace")):
        if r["technique"] in ("CG-Adaptive", "CG-Static") and r["blocked"] == "0":
            c[(page, r["technique"], r["cg_seed"])] += 1
seed8 = [(k, v) for k, v in c.items() if k[0] == "search" and k[1] == "CG-Adaptive" and k[2] == "8"]
print("  customxss/search/CG-Adaptive/seed8 residuals:", (seed8[0][1] if seed8 else 0), "(expect 0 -> row legitimately absent)")
present = sorted(k for k in c if k[0] == "search" and k[1] == "CG-Adaptive")
print("  customxss/search/CG-Adaptive seeds WITH residuals:", [k[2] for k in present])

print("\n=== nit 2: recompute RQ1 from rq1_summary.csv ===")
p = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq1_summary.csv"
rows = list(csv.DictReader(open(p)))
print("  columns:", rows[0].keys() if rows else "(empty)")
for r in rows:
    print("   ", dict(r))
