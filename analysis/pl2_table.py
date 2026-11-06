#!/usr/bin/env python3
"""Paranoia-level-2 (PL2) robustness table, both CRS versions. Reproduces the
paper's two-version PL2 table (tab:r23-pl2): the frozen held-out attacks and the
benign corpora replayed at OWASP CRS paranoia level 2 under CRS 3.3.2 and, after
the revision, under CRS 4.29.0. Only the paranoia level and the CRS version change;
the generated rules, anomaly thresholds, and backends are held fixed (level-1-trained
rules, not retrained at PL2).

Reads the released payload-free summaries only:
  results/pl2/pl2_block_rates.csv        (CRS 3.3.2 block rate + FP summary)
  results/pl2/pl2_benign_fp.csv          (CRS 3.3.2 benign FP breakdown)
  results/pl2/crs429_pl2_block_rates.csv (CRS 4.29.0 block rate + FP summary)
  results/pl2/crs429_pl2_benign_fp.csv   (CRS 4.29.0 benign FP breakdown)
Paths are resolved relative to the repository root. No arguments.
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PL2 = ROOT / "results" / "pl2"

VERSIONS = [("CRS 3.3.2", "pl2_block_rates.csv"), ("CRS 4.29.0", "crs429_pl2_block_rates.csv")]
FAMILIES = [("sqli", "SQLi"), ("xss", "XSS")]
CONFIGS = ["CRS-only", "CG-Static", "CG-Adaptive"]


def load_block(fname):
    d = {}
    with open(PL2 / fname, newline="") as f:
        for r in csv.DictReader(f):
            d[(r["family"], r["configuration"])] = r
    return d


def main():
    block = {ver: load_block(fname) for ver, fname in VERSIONS}

    print("=" * 94)
    print("PL2 robustness (tab:r23-pl2): frozen held-out attacks replayed at CRS paranoia level 2")
    print("Block rate = mean over held-out attack sets x defense seeds; range = [min, max] over runs")
    print("=" * 94)
    print("%-6s %-12s %24s %24s %7s %8s" %
          ("Family", "Config", "CRS 3.3.2 block%", "CRS 4.29.0 block%", "n_sets", "n_runs"))
    print("%-6s %-12s %24s %24s %7s %8s" %
          ("", "", "mean [min  - max ]", "mean [min  - max ]", "", ""))
    print("-" * 94)
    for fam, flabel in FAMILIES:
        for cfg in CONFIGS:
            cells = []
            nsets = nruns = ""
            for ver, _ in VERSIONS:
                r = block[ver].get((fam, cfg))
                if not r:
                    cells.append("%24s" % "n/a"); continue
                cells.append("%7.2f [%6.2f-%6.2f]" %
                             (float(r["block_rate_mean_pct"]), float(r["block_rate_min_pct"]),
                              float(r["block_rate_max_pct"])))
                nsets, nruns = r["n_held_out_sets"], r["n_runs"]
            print("%-6s %-12s %24s %24s %7s %8s" % (flabel, cfg, cells[0], cells[1], nsets, nruns))
        print("-" * 94)

    print()
    print("=" * 72)
    print("Benign false positives at PL2 (%), CRS 3.3.2 vs CRS 4.29.0")
    print("CSIC-2012 is CRS-determined (rule 920230); custom-app shows the rules' own FP")
    print("=" * 72)
    print("%-6s %-12s %18s %18s" % ("Family", "Config", "CSIC-2012 FP%", "Custom-app FP%"))
    print("%-6s %-12s %18s %18s" % ("", "", "3.3.2   4.29.0", "3.3.2   4.29.0"))
    print("-" * 72)
    for fam, flabel in FAMILIES:
        for cfg in CONFIGS:
            csic = []
            cust = []
            for ver, _ in VERSIONS:
                r = block[ver].get((fam, cfg))
                csic.append("%.2f" % float(r["csic_fp_pct"]) if r else "n/a")
                cust.append("%.2f" % float(r["customapp_fp_pct"]) if r else "n/a")
            print("%-6s %-12s %8s %9s %8s %9s" %
                  (flabel, cfg, csic[0], csic[1], cust[0], cust[1]))
        print("-" * 72)


if __name__ == "__main__":
    main()
