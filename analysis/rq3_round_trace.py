#!/usr/bin/env python3
"""RQ3 round-by-round trace of a single co-evolution run (the "login journey").

Prints the per-round hardening trace for one run from the released payload-free
round-trace file. Defaults to the paper's example: SQLi Login, CG, eps=0.3, the
slowest seed (5 rounds). Override with: rq3_round_trace.py <family> <page> <strategy> <eps> <seed>

Reads results/rq3/rq3_round_traces.csv. Paths relative.
"""
import csv, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "results" / "rq3" / "rq3_round_traces.csv"


def main():
    fam = sys.argv[1] if len(sys.argv) > 1 else "SQLi"
    page = sys.argv[2] if len(sys.argv) > 2 else "login"
    strat = sys.argv[3] if len(sys.argv) > 3 else "CG"
    eps = sys.argv[4] if len(sys.argv) > 4 else "0.3"
    seed = sys.argv[5] if len(sys.argv) > 5 else None

    rows = [r for r in csv.DictReader(open(TRACE))
            if r["family"] == fam and r["page"] == page and r["strategy"] == strat
            and (strat == "PP" or r["epsilon"] == eps)]
    if seed is None:
        # default: the run with the most rounds (the slowest seed), as in the paper
        by_seed = {}
        for r in rows:
            by_seed.setdefault(r["seed"], []).append(r)
        seed = max(by_seed, key=lambda s: len(by_seed[s]))
    rows = [r for r in rows if r["seed"] == seed]
    rows.sort(key=lambda r: int(r["iter"]))

    print("Round-by-round trace: %s %s %s eps=%s seed=%s  (%d rounds)"
          % (fam, page, strat, eps, seed, len(rows)))
    print("%5s %10s %8s %8s %8s %9s %8s %9s %11s %11s" %
          ("Round", "Bypassing", "Clusters", "Retries", "Rules+", "Total|R|", "StillByp",
           "Block%", "DefTokens", "RuleEval_s"))
    for r in rows:
        deftok = int(float(r["defense_in_tokens"] or 0)) + int(float(r["defense_out_tokens"] or 0))
        print("%5s %10s %8s %8s %8s %9s %8s %9s %11d %11s" %
              (r["iter"], r["bypassed_n"], r["num_clusters"], r.get("retries", ""),
               r["rules_added"], r["num_rules"], r["num_hard"], r["block_after_pct_byp"],
               deftok, r["rule_eval_s"]))


if __name__ == "__main__":
    main()
