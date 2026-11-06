#!/usr/bin/env python3
"""Non-LLM external-validity funnel, Dalfox XSS replay, and FuzzDB SQLi replay.
Reproduces the paper's non-LLM funnel and replay tables (tab:nonllm) from the
released payload-free data (sqlmap, CSIC/Torpeda, FuzzDB, WAF-A-MoLE, Dalfox).

Reads results/nonllm/nonllm_funnel.csv, nonllm_dalfox_replay.csv, and
nonllm_fuzzdb_replay.csv. Paths relative.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNNEL = ROOT / "results" / "nonllm" / "nonllm_funnel.csv"
REPLAY = ROOT / "results" / "nonllm" / "nonllm_dalfox_replay.csv"
FUZZDB_REPLAY = ROOT / "results" / "nonllm" / "nonllm_fuzzdb_replay.csv"


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

    print("\n" + "=" * 74)
    print("FuzzDB replay: block rate on the 2 CRS-bypassing SQLi payloads (10 seeds, eps=0.3)")
    print("=" * 74)
    frows = list(csv.DictReader(open(FUZZDB_REPLAY)))
    print("%-12s %14s %10s %14s" % ("Rule set", "Block % mean+/-SD", "Median", "Range"))
    for tech in ["CRS-only", "CG-Static", "CG-Adaptive"]:
        fv = [float(r["block_rate_pct"]) for r in frows if r["technique"] == tech]
        if not fv:
            continue
        if tech == "CRS-only":
            print("%-12s %14s %10s %14s" % (tech, "%.1f" % fv[0], "-", "-"))
        else:
            m, sd = st.mean(fv), st.stdev(fv)
            print("%-12s %10.1f+/-%-3.1f %10.1f %14s" %
                  (tech, m, sd, st.median(fv), "%.1f-%.0f" % (min(fv), max(fv))))


if __name__ == "__main__":
    main()
