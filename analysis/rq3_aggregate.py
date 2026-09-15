#!/usr/bin/env python3
"""RQ3 adaptive co-evolution: reproduce the effectiveness and budget tables
(PP-Adaptive vs CG-Adaptive at eps=0.3) from the released payload-free matrix.

Reads results/rq3/rq3_adaptive_matrix.csv. Converged is shown as X/10; held-out
block %, |R|, and rounds are the median with [min, max] (held-out is bimodal, so a
median is reported rather than a mean); added FP % is mean +/- SD. Paths relative.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "rq3" / "rq3_adaptive_matrix.csv"
SQLI = ["login", "search", "product", "filter"]
XSS = ["search", "calc"]
LABEL = {"login": "Login form", "search": "Search", "product": "URL parameter",
         "filter": "Product filter", "calc": "Calculator (eval sink)"}


def sel(rs, fam, page, strat):
    return [r for r in rs if r["family"] == fam and r["page"] == page and r["strategy"] == strat]


def fnum(rows, col):
    return [float(r[col]) for r in rows if r[col] not in ("", "None")]


def inum(rows, col):
    return [int(float(r[col])) for r in rows if r[col] not in ("", "None")]


def mr(v, flt=False):
    m = st.median(v); lo, hi = min(v), max(v)
    fmt = (lambda x: "%.1f" % x) if flt else (lambda x: "%.0f" % x if x == int(x) else "%.1f" % x)
    return fmt(m) if lo == hi else "%s [%s-%s]" % (fmt(m), fmt(lo), fmt(hi))


def ms(v):
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)


def main():
    rs = list(csv.DictReader(open(MATRIX)))
    print("=" * 98)
    print("RQ3 adaptive effectiveness (Converged X/10; block%/|R|/Rounds median[min-max]; FP mean+/-SD)")
    print("=" * 98)
    print("%-6s %-16s %-12s %10s %20s %12s %12s %10s" %
          ("Family", "Page", "Strategy", "Converged", "Held-out block%", "|R|", "AddedFP%", "Rounds"))
    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            for strat in ["PP", "CG"]:
                d = sel(rs, fam, page, strat)
                if not d:
                    continue
                conv = sum(int(r["converged"]) for r in d)
                # recompute held-out block % from raw counts (higher precision than the
                # log-printed value): block = (valid - residual) / valid
                hbv = [100.0 * (int(float(r["heldout_valid"])) - int(float(r["heldout_residual"])))
                       / int(float(r["heldout_valid"]))
                       for r in d if r["heldout_valid"] not in ("", "None") and float(r["heldout_valid"]) > 0]
                hb = mr(hbv, flt=True)
                Rc = mr(inum(d, "accepted_rules"))
                fp = ms(fnum(d, "added_fp_pct"))
                rd = mr(inum(d, "rounds"))
                sname = "PP-Adaptive" if strat == "PP" else "CG-Adaptive"
                print("%-6s %-16s %-12s %8d/10 %20s %12s %6.2f+/-%-4.2f %12s" %
                      (fam if strat == "PP" else "", LABEL.get(page, page) if strat == "PP" else "",
                       sname, conv, hb, Rc, fp[0], fp[1], rd))
            print("-" * 98)

    print("\n" + "=" * 98)
    print("RQ3 adaptive budget (Rules/100 bypasses; median counts; cost incl. attacker+defender)")
    print("=" * 98)
    print("%-6s %-16s %-12s %12s %10s %12s %10s" %
          ("Family", "Page", "Strategy", "|R|", "Rejected", "Calls", "Cost c"))
    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            for strat in ["PP", "CG"]:
                d = sel(rs, fam, page, strat)
                if not d:
                    continue
                sname = "PP-Adaptive" if strat == "PP" else "CG-Adaptive"
                Rc = mr(inum(d, "accepted_rules"))
                rej = mr(inum(d, "rejected"))
                calls = mr(inum(d, "defense_calls"))
                cost = st.median([c * 100 for c in fnum(d, "est_cost_usd")])
                print("%-6s %-16s %-12s %12s %10s %12s %10.2f" %
                      (fam if strat == "PP" else "", LABEL.get(page, page) if strat == "PP" else "",
                       sname, Rc, rej, calls, cost))
            print("-" * 98)


if __name__ == "__main__":
    main()
