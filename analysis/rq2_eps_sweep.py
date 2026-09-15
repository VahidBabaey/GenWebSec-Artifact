#!/usr/bin/env python3
"""RQ2 epsilon sweep: reproduce the per-page CG sensitivity table over
eps in {0.1,0.2,0.3,0.4,0.5} from the released payload-free matrix.

Reads results/rq2/rq2_eps_sweep.csv. Block% and Added FP% are mean +/- SD;
|R|, clusters, singleton%, median/max cluster size, and LLM calls are the median
with [min, max], over the 10 seeds. Operating point eps=0.3. Paths relative here.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "results" / "rq2" / "rq2_eps_sweep.csv"
EPSES = ["0.1", "0.2", "0.3", "0.4", "0.5"]
SQLI = ["login", "search", "product", "filter"]
XSS = ["search", "calc"]


def ms(v):
    return st.mean(v), (st.stdev(v) if len(v) > 1 else 0.0)


def mr(v):
    m = st.median(v); lo, hi = min(v), max(v)
    mm = ("%.0f" % m) if m == int(m) else ("%.1f" % m)
    return mm if lo == hi else "%s[%d-%d]" % (mm, lo, hi)


def main():
    rs = list(csv.DictReader(open(SWEEP)))
    print("RQ2 epsilon sweep (CG; block/FP mean+/-SD; counts median[min-max]; 10 seeds)")
    print("%-5s %-8s %-5s %10s %8s %10s %8s %8s %8s %10s" %
          ("Fam", "Page", "eps", "Block%", "|R|", "Clusters", "Sngl%", "MedSz", "MaxSz", "Calls"))
    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            for eps in EPSES:
                d = [r for r in rs if r["family"] == fam and r["page"] == page and r["epsilon"] == eps]
                if not d:
                    continue
                bl = ms([float(r["block_pct"]) for r in d])
                mark = "*" if eps == "0.3" else " "
                print("%-5s %-8s %-5s %6.1f+/-%-3.1f %8s %10s %8.0f %8s %8s %10s" %
                      (fam if eps == "0.1" else "", page if eps == "0.1" else "", eps + mark,
                       bl[0], bl[1],
                       mr([int(r["accepted_rules"]) for r in d]),
                       mr([int(r["clusters"]) for r in d]),
                       st.median([float(r["singleton_pct"]) for r in d]),
                       mr([int(float(r["median_cluster_size"])) for r in d]),
                       mr([int(r["max_cluster_size"]) for r in d]),
                       mr([int(r["defense_calls"]) for r in d])))
            print("-" * 96)


if __name__ == "__main__":
    main()
