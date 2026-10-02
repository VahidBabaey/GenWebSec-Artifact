#!/usr/bin/env python3
"""Remove the bogus bwApp rows (written while its DB was missing) from the RQ4 SQLi artifacts so the
resumable re-run redoes them correctly."""
import csv, os
BASE = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq4"
for fn in ("rq4_sqli_summary.csv", "rq4_sqli_false_bypasses.csv"):
    p = f"{BASE}/{fn}"
    if not os.path.exists(p):
        print("skip (absent):", fn); continue
    rows = list(csv.reader(open(p)))
    if not rows:
        print("skip (empty):", fn); continue
    header, body = rows[0], rows[1:]
    kept = [r for r in body if not (r and r[0] == "bwapp")]
    removed = len(body) - len(kept)
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(header); w.writerows(kept)
    print(f"{fn}: removed {removed} bwapp rows, kept {len(kept)}")
