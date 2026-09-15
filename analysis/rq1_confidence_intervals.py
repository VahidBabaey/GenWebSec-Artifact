#!/usr/bin/env python3
"""RQ1 confidence intervals: 95% Student-t CI of the CRS bypass % per condition,
from the 5 per-seed run-level rates (not pooled payloads).

Per-seed rate = 100 * sum(waf_bypassed_n) / sum(backend_valid_n) over that run's
rounds. With 5 seeds, df = 4 and t_{0.975,4} = 2.776.

Reads only the released, payload-free metrics under results/rq1/metrics/. Paths
are relative to this file. Adapted from WorkFlowV2/_rq1_ci.py.
"""
import csv, os, statistics as st, math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MBASE = ROOT / "results" / "rq1" / "metrics"
SEEDS = range(1, 6)
T = 2.776   # t_{0.975, df=4}

FAMS = [
    ("SQLi", "A1_customapp",
     [("login", "Login form"), ("search", "Product search"),
      ("product", "URL parameter"), ("filter", "Product filter")]),
    ("XSS", "A2_customxss",
     [("search", "Search (JS-string)"), ("calc", "Calculator (eval sink)")]),
]


def rate(path):
    rows = list(csv.DictReader(open(path)))
    byp = sum(float(r["waf_bypassed_n"]) for r in rows)
    val = sum(float(r["backend_valid_n"]) for r in rows)
    return 100.0 * byp / val if val else 0.0


def main():
    print("%-4s %-22s %-38s %6s %5s %18s"
          % ("Fam", "Page", "per-seed bypass rates (5)", "mean", "SD", "95% CI"))
    for fam, key, pages in FAMS:
        for pk, lbl in pages:
            r = []
            for s in SEEDS:
                p = MBASE / key / ("seed%d" % s) / ("%s_metrics.csv" % pk)
                if os.path.exists(p):
                    r.append(rate(p))
            m = st.mean(r); sd = st.stdev(r); h = T * sd / math.sqrt(len(r))
            rs = "[" + ", ".join("%.1f" % x for x in r) + "]"
            print("%-4s %-22s %-38s %6.2f %5.2f   [%5.1f, %5.1f]"
                  % (fam, lbl, rs, m, sd, m - h, m + h))


if __name__ == "__main__":
    main()
