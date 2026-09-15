#!/usr/bin/env python3
"""Non-LLM external-validity funnel and Dalfox replay. Reproduces the paper's
nonllm-funnel and nonllm-xss-replay tables from the released payload-free data.

Reads results/nonllm/nonllm_funnel.csv and results/nonllm/nonllm_dalfox_replay.csv.
Paths relative.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNNEL = ROOT / "results" / "nonllm" / "nonllm_funnel.csv"
REPLAY = ROOT / "results" / "nonllm" / "nonllm_dalfox_replay.csv"


def main():
    print("=" * 74)
    print("Non-LLM validation funnel")
    print("=" * 74)
    print("%-20s %-6s %11s %9s %14s %14s" %
          ("Source", "Type", "Candidates", "Distinct", "Backend-valid", "CRS-bypassing"))
    for r in csv.DictReader(open(FUNNEL)):
        print("%-20s %-6s %11s %9s %14s %14s" %
              (r["source"], r["family"], r["candidates"], r["distinct"],
               r["backend_valid"], r["crs_bypassing"]))

    print("\n" + "=" * 74)
    print("Dalfox replay: block rate on the 45 CRS-bypassing payloads (10 seeds, eps=0.3)")
    print("=" * 74)
    rows = list(csv.DictReader(open(REPLAY)))
    print("%-12s %14s %10s %14s" % ("Rule set", "Block % mean+/-SD", "Median", "Range"))
    for tech in ["CRS-only", "CG-Static", "CG-Adaptive"]:
        v = [float(r["block_rate_pct"]) for r in rows if r["technique"] == tech]
        if not v:
            continue
        if tech == "CRS-only":
            print("%-12s %14s %10s %14s" % (tech, "%.1f" % v[0], "-", "-"))
        else:
            m, sd = st.mean(v), st.stdev(v)
            print("%-12s %10.1f+/-%-3.1f %10.1f %14s" %
                  (tech, m, sd, st.median(v), "%.1f-%.0f" % (min(v), max(v))))


if __name__ == "__main__":
    main()
