#!/usr/bin/env python3
"""Deployed WAF request latency. Reproduces the paper's latency table (plain
workload) from the released latency summary: p50/p95/p99, throughput, Apache CPU,
and overhead vs CRS, at 1/10/50 concurrent clients for the six configurations.

Reads results/latency/latency_summary.csv. Paths relative.
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "latency" / "latency_summary.csv"
ORDER = ["direct", "crs_only", "cg_adaptive_sqli", "cg_static_sqli",
         "cg_adaptive_xss", "cg_static_xss"]
LABEL = {"direct": "Direct (no WAF)", "crs_only": "CRS only",
         "cg_adaptive_sqli": "CRS + CG-Adaptive SQLi", "cg_static_sqli": "CRS + CG-Static SQLi",
         "cg_adaptive_xss": "CRS + CG-Adaptive XSS", "cg_static_xss": "CRS + CG-Static XSS"}


def main():
    rows = [r for r in csv.DictReader(open(SUMMARY)) if r["workload"] == "plain"]
    print("Deployed WAF request latency (plain benign workload; median of 5 x 10,000 requests)")
    print("%-26s %8s %8s %10s %10s %9s %12s" %
          ("Configuration", "p50 ms", "p95 ms", "p99 ms", "req/s", "CPU %", "Ovh vs CRS"))
    for c in ["1", "10", "50"]:
        print("-- %s concurrent client(s)" % c)
        for cfg in ORDER:
            m = [r for r in rows if r["config"] == cfg and r["concurrency"] == c]
            if not m:
                continue
            r = m[0]
            ovh = "---" if cfg == "direct" else r["overhead_vs_crs_pct"]
            print("%-26s %8s %8s %10s %10s %9.0f %12s" %
                  (LABEL[cfg], r["p50_ms"], r["p95_ms"], r["p99_ms"], r["req_per_sec"],
                   float(r["cpu_pct"]), ovh))


if __name__ == "__main__":
    main()
