#!/usr/bin/env python3
"""RQ3 co-evolution epsilon sweep: reproduce the per-page CG-Adaptive outcome table
over eps in {0.1..0.5} from the released payload-free matrix.

Reads results/rq3/rq3_eps_sweep.csv. Converged is X/10; held-out block %, |R|,
Rounds, and Residual are the median with [min, max] over the 10 seeds. eps=0.3 is
the operating point. Paths relative.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "results" / "rq3" / "rq3_eps_sweep.csv"
EPSES = ["0.1", "0.2", "0.3", "0.4", "0.5"]
SQLI = ["login", "search", "product", "filter"]
XSS = ["search", "calc"]


def fnum(rows, col):
    return [float(r[col]) for r in rows if r[col] not in ("", "None")]


def inum(rows, col):
    return [int(float(r[col])) for r in rows if r[col] not in ("", "None")]


def mr(v, flt=False):
    if not v:
        return "-"
    m = st.median(v); lo, hi = min(v), max(v)
    fmt = (lambda x: "%.1f" % x) if flt else (lambda x: "%.0f" % x if x == int(x) else "%.1f" % x)
    return fmt(m) if lo == hi else "%s[%s-%s]" % (fmt(m), fmt(lo), fmt(hi))


def main():
    rs = list(csv.DictReader(open(SWEEP)))
    print("RQ3 CG-Adaptive epsilon sweep (Converged X/10; block%/|R|/Rounds/Residual median[min-max])")
    print("%-5s %-8s %-6s %10s %18s %10s %10s %10s" %
          ("Fam", "Page", "eps", "Converged", "Held-out block%", "|R|", "Rounds", "Residual"))
    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            for eps in EPSES:
                d = [r for r in rs if r["family"] == fam and r["page"] == page and r["epsilon"] == eps]
                if not d:
                    continue
                conv = sum(int(r["converged"]) for r in d)
                mark = "*" if eps == "0.3" else " "
                print("%-5s %-8s %-6s %8d/10 %18s %10s %10s %10s" %
                      (fam if eps == "0.1" else "", page if eps == "0.1" else "", eps + mark,
                       conv, mr(fnum(d, "heldout_block_pct"), flt=True),
                       mr(inum(d, "accepted_rules")), mr(inum(d, "rounds")),
                       mr(inum(d, "heldout_residual"))))
            print("-" * 86)


if __name__ == "__main__":
    main()
