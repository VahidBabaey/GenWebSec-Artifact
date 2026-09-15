#!/usr/bin/env python3
"""RQ2 fixed-corpus aggregation: reproduce the per-page effectiveness and budget
tables (PP-Static, RG, CG-Static at eps=0.3) from the released payload-free matrix.

Reads results/rq2/rq2_static_matrix.csv. Rates are mean +/- SD over the 10 seeds;
counts (|R|, rounds) are the median with [min, max]. Paths are relative to this
file, so it runs from a clean checkout.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "rq2" / "rq2_static_matrix.csv"
SQLI = ["login", "search", "product", "filter"]
XSS = ["search", "calc"]
LABEL = {"login": "Login form", "search": "Search", "product": "URL parameter",
         "filter": "Product filter", "calc": "Calculator (eval sink)"}


def rows():
    return list(csv.DictReader(open(MATRIX)))


def sel(rs, fam, page, strat):
    return [r for r in rs if r["family"] == fam and r["page"] == page and r["strategy"] == strat]


def ms(v):
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)


def mr(v):
    m = st.median(v); lo, hi = min(v), max(v)
    mm = ("%.0f" % m) if m == int(m) else ("%.1f" % m)
    return mm if lo == hi else "%s [%d-%d]" % (mm, lo, hi)


def main():
    rs = rows()
    print("=" * 92)
    print("RQ2 effectiveness (rates mean+/-SD; |R| and rounds median[min-max]; 10 seeds; eps=0.3)")
    print("=" * 92)
    print("%-6s %-16s %-4s %12s %14s %12s %12s" %
          ("Family", "Page", "Str", "Block%", "|R|", "AddedFP%", "Rounds"))
    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            for strat in ["PP", "RG", "CG"]:
                d = sel(rs, fam, page, strat)
                if not d:
                    continue
                bl = ms([float(r["block_pct"]) for r in d])
                fp = ms([float(r["added_fp_pct"]) for r in d])
                Rc = mr([int(r["accepted_rules"]) for r in d])
                rd = mr([int(r["rounds"]) for r in d])
                print("%-6s %-16s %-4s %6.1f+/-%-4.1f %14s %6.2f+/-%-4.2f %12s" %
                      (fam if strat == "PP" else "", LABEL.get(page, page) if strat == "PP" else "",
                       strat, bl[0], bl[1], Rc, fp[0], fp[1], rd))
            print("-" * 92)

    print("\n" + "=" * 92)
    print("RQ2 budget (median[min-max] counts; tokens median; 10 seeds; eps=0.3)")
    print("=" * 92)
    print("%-6s %-16s %-4s %12s %12s %12s %12s %10s" %
          ("Family", "Page", "Str", "|R|", "Rejected", "Calls", "Tokens", "Cost c"))
    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            for strat in ["PP", "RG", "CG"]:
                d = sel(rs, fam, page, strat)
                if not d:
                    continue
                Rc = mr([int(r["accepted_rules"]) for r in d])
                rej = mr([int(r["rejected"]) for r in d])
                calls = mr([int(r["defense_calls"]) for r in d])
                tok = st.median([int(r["input_tokens"]) + int(r["output_tokens"]) for r in d])
                cost = st.median([float(r["est_cost_usd"]) * 100 for r in d])  # US cents
                print("%-6s %-16s %-4s %12s %12s %12s %12.0f %10.2f" %
                      (fam if strat == "PP" else "", LABEL.get(page, page) if strat == "PP" else "",
                       strat, Rc, rej, calls, tok, cost))
            print("-" * 92)


if __name__ == "__main__":
    main()
