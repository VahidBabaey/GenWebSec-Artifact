#!/usr/bin/env python3
"""Run every analysis script in order and report which succeeded.

Each script regenerates one or more paper tables from the released structured data.
From a clean checkout:  python analysis/run_all.py
"""
import subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = [
    "rq1_aggregate.py", "rq1_confidence_intervals.py",
    "rq2_aggregate.py", "rq2_rg_paired.py", "rq2_eps_sweep.py",
    "rq3_aggregate.py", "rq3_eps_sweep.py", "rq3_round_trace.py",
    "rq4_primary.py", "rq4_eps_sweep.py", "rq4_significance.py", "rq4_fp.py",
    "budget_aggregate.py", "nonllm_funnel.py", "latency_table.py",
]


def main():
    ok, fail = [], []
    for s in SCRIPTS:
        print("\n" + "#" * 78)
        print("# " + s)
        print("#" * 78)
        r = subprocess.run([sys.executable, str(HERE / s)])
        (ok if r.returncode == 0 else fail).append(s)
    print("\n" + "=" * 40)
    print("SUMMARY: %d ok, %d failed" % (len(ok), len(fail)))
    if fail:
        print("FAILED:", ", ".join(fail))
        sys.exit(1)


if __name__ == "__main__":
    main()
