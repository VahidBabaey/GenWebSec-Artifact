#!/usr/bin/env python3
"""Paranoia-level-2 (PL2) robustness table. Reproduces the paper's PL2 table
(tab:r23-pl2): the frozen held-out attacks and the benign corpora replayed at
OWASP CRS paranoia level 2 under CRS 4.29.0. Only the paranoia level changes;
the generated rules, anomaly thresholds, and backends are held fixed
(level-1-trained rules, not retrained at PL2).

Reads the released payload-free summaries only:
  results/pl2/crs429_pl2_block_rates.csv (block rate + FP summary)
  results/pl2/crs429_pl2_benign_fp.csv   (benign FP breakdown)
Paths are resolved relative to the repository root. No arguments.
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PL2 = ROOT / "results" / "pl2"

BLOCK_CSV = "crs429_pl2_block_rates.csv"
FAMILIES = [("sqli", "SQLi"), ("xss", "XSS")]
CONFIGS = ["CRS-only", "CG-Static", "CG-Adaptive"]


def load_block(fname):
    d = {}
    with open(PL2 / fname, newline="") as f:
        for r in csv.DictReader(f):
            d[(r["family"], r["configuration"])] = r
    return d


def main():
    block = load_block(BLOCK_CSV)

    print("=" * 80)
    print("PL2 robustness (tab:r23-pl2): frozen held-out attacks replayed at CRS paranoia level 2, CRS 4.29.0")
    print("Block rate = mean over held-out attack sets x defense seeds; range = [min, max] over runs")
    print("=" * 80)
    print("%-6s %-12s %24s %7s %8s" % ("Family", "Config", "CRS 4.29.0 block%", "n_sets", "n_runs"))
    print("%-6s %-12s %24s %7s %8s" % ("", "", "mean [min  - max ]", "", ""))
    print("-" * 80)
    for fam, flabel in FAMILIES:
        for cfg in CONFIGS:
            r = block.get((fam, cfg))
            if not r:
                print("%-6s %-12s %24s %7s %8s" % (flabel, cfg, "n/a", "", ""))
                continue
            cell = "%7.2f [%6.2f-%6.2f]" % (
                float(r["block_rate_mean_pct"]), float(r["block_rate_min_pct"]),
                float(r["block_rate_max_pct"]))
            print("%-6s %-12s %24s %7s %8s" % (flabel, cfg, cell, r["n_held_out_sets"], r["n_runs"]))
        print("-" * 80)

    print()
    print("=" * 58)
    print("Benign false positives at PL2 (%), CRS 4.29.0")
    print("CSIC-2012 is CRS-determined (rule 920230); custom-app shows the rules' own FP")
    print("=" * 58)
    print("%-6s %-12s %14s %14s" % ("Family", "Config", "CSIC-2012 FP%", "Custom-app FP%"))
    print("-" * 58)
    for fam, flabel in FAMILIES:
        for cfg in CONFIGS:
            r = block.get((fam, cfg))
            csic = "%.2f" % float(r["csic_fp_pct"]) if r else "n/a"
            cust = "%.2f" % float(r["customapp_fp_pct"]) if r else "n/a"
            print("%-6s %-12s %14s %14s" % (flabel, cfg, csic, cust))
        print("-" * 58)


if __name__ == "__main__":
    main()
