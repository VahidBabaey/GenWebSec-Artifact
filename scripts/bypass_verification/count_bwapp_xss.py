#!/usr/bin/env python3
import csv, glob
from collections import Counter
c = Counter(); tot = 0
for f in glob.glob("/home/vahid/Projects/GenWebSec/results/V2/A2_HeldOut/A2_bwapp_heldout_seed*/Defense_results/rq4_replay_bwapp_xss_eval_seed*_perattack.csv"):
    if "/eps0." in f:
        continue
    for r in csv.DictReader(open(f, encoding="utf-8", errors="replace")):
        if r["technique"] in ("CG-Adaptive", "CG-Static") and r["blocked"] == "0":
            c[(r["technique"], r["cg_seed"])] += 1; tot += 1
print("groups:", len(c), " total residuals:", tot)
print("by group:", dict(c))
