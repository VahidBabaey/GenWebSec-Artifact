#!/usr/bin/env python3
"""Attack-diversity appendix tables. Reproduces the paper's two diversity tables:
tab:div-baseline (Table B7, attacks against baseline CRS 3.3.2) and
tab:div-crs429 (Table B8, attacks generated directly against CRS 4.29.0).

Each table reports, per custom-application entry point, the share of generated
attacks whose exact text is unique ("Distinct (%)") and the number of distinct
evasion methods the set uses ("Tech.", out of 15 for SQLi and 12 for XSS).

Reads results/diversity/attack_diversity.csv (derived values only; attack strings
are not published). The stored distinct_pct is the source-reported percentage;
the one-decimal figures below are that percentage rounded half-up, matching the
manuscript. Standard library only; no arguments. Paths relative.
"""
import csv
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "results" / "diversity" / "attack_diversity.csv"

SETS = [
    ("baseline", "Baseline CRS 3.3.2  (Table B7 / tab:div-baseline)"),
    ("crs429", "Direct against CRS 4.29.0  (Table B8 / tab:div-crs429)"),
]


def one_dp(pct_str):
    """Half-up rounding of the source percentage to one decimal (paper convention)."""
    return Decimal(pct_str).quantize(Decimal("0.1"), ROUND_HALF_UP)


def main():
    rows = list(csv.DictReader(open(CSV, newline="")))

    for key, title in SETS:
        sub = [r for r in rows if r["attack_set"] == key]
        print("=" * 62)
        print("Attack diversity -- " + title)
        print("=" * 62)
        print("%-7s %-14s %13s %6s" % ("Family", "Entry point", "Distinct (%)", "Tech."))
        print("-" * 62)
        prev_fam = None
        for r in sub:
            fam = r["family"] if r["family"] != prev_fam else ""
            prev_fam = r["family"]
            print("%-7s %-14s %13s %6d" %
                  (fam, r["entry_point"], one_dp(r["distinct_pct"]), int(r["n_techniques"])))
        print()

    # Provenance detail: the counts and leading methods behind each row.
    print("=" * 62)
    print("Per-entry-point detail (attack count and leading methods)")
    print("=" * 62)
    print("%-9s %-5s %-14s %9s   %s" %
          ("Set", "Fam.", "Entry point", "Attacks", "Leading methods (method:count)"))
    print("-" * 62)
    for key, _ in SETS:
        for r in [x for x in rows if x["attack_set"] == key]:
            print("%-9s %-5s %-14s %9s   %s" %
                  (key, r["family"], r["entry_point"], r["n_attacks"], r["techniques"]))


if __name__ == "__main__":
    main()
