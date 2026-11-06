#!/usr/bin/env python3
"""CRS-4.29 attack-generation table (tab:crs429-gen). Reproduces the paper's
per-page attack-generation result against the updated CRS 4.29.0: for each of the
six custom-application injection contexts, the mean generated and execution-valid
attack counts and the CRS-4.29 bypass rate, over five independent runs of ten
rounds each, with zero false bypasses.

Reads the released payload-free data:
  results/crs429_generation/crs429_generation_summary.csv   (per-page mean/SD/CI)
  results/crs429_generation/crs429_generation_rounds.csv    (per-round counts)
The summary gives the paper numbers directly; the per-round file is used as an
independent cross-check that recomputes each bypass rate from the raw counts.
Paths relative. Standard library only.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "crs429_generation" / "crs429_generation_summary.csv"
ROUNDS = ROOT / "results" / "crs429_generation" / "crs429_generation_rounds.csv"

ORDER = [("SQLi", "Login"), ("SQLi", "Search"), ("SQLi", "URL parameter"),
         ("SQLi", "Filter"), ("XSS", "Search"), ("XSS", "Calculator")]


def load_summary():
    d = {}
    for r in csv.DictReader(open(SUMMARY)):
        d[(r["family"], r["entry_point"])] = r
    return d


def rounds_by_page_seed():
    """Return {(family, entry_point): {seed: (sum_valid, sum_bypass, sum_gen,
    sum_false, n_rounds)}} from the per-round counts."""
    agg = {}
    for r in csv.DictReader(open(ROUNDS)):
        key = (r["family"], r["entry_point"])
        s = int(r["seed"])
        cell = agg.setdefault(key, {}).setdefault(s, [0, 0, 0, 0, 0])
        cell[0] += int(r["validated_step1"])
        cell[1] += int(r["waf_bypass_non403_step2"])
        cell[2] += int(r["generated"])
        cell[3] += int(r["false_bypass"])
        cell[4] += 1
    return agg


def main():
    S = load_summary()
    R = rounds_by_page_seed()

    print("=" * 96)
    print("CRS-4.29.0 attack generation: per-page bypass rate (5 independent runs x 10 rounds)")
    print("=" * 96)
    hdr = ("%-5s %-14s %13s %13s %15s %15s %6s" %
           ("Fam", "Context", "Generated", "Exec-valid", "CRS-4.29 bypass%",
            "95% CI", "FalseB"))
    print(hdr)
    print("-" * 96)
    tot_gen = tot_val = tot_byp = tot_false = 0
    n_runs = 0
    for fam, ep in ORDER:
        r = S[(fam, ep)]
        gen = "%s+/-%s" % (r["generated_mean"], r["generated_sd"])
        val = "%s+/-%s" % (r["valid_mean"], r["valid_sd"])
        byp = "%s+/-%s" % (r["bypass_pct_mean"], r["bypass_pct_sd"])
        ci = "[%s, %s]" % (r["ci_lo"], r["ci_hi"])
        print("%-5s %-14s %13s %13s %15s %15s %6s" %
              (fam, ep, gen, val, byp, ci, r["false_bypass_total"]))
        for s, cell in R[(fam, ep)].items():
            tot_val += cell[0]; tot_byp += cell[1]; tot_gen += cell[2]
            tot_false += cell[3]; n_runs += 1
    print("-" * 96)
    print("Six custom-application pages, %d independent runs, %d total rounds; "
          "false bypasses: %d" % (n_runs, n_runs * 10, tot_false))
    print("Pooled over all runs: generated=%d, execution-valid=%d, "
          "confirmed CRS-4.29 bypasses=%d" % (tot_gen, tot_val, tot_byp))

    # ---- independent cross-check: recompute each bypass rate from raw counts ----
    print("\n" + "=" * 96)
    print("Cross-check: bypass% recomputed from per-round counts "
          "(sum bypass / sum exec-valid per run, mean+/-SD over runs)")
    print("=" * 96)
    print("%-5s %-14s %18s %18s %8s" %
          ("Fam", "Context", "summary mean+/-SD", "recomputed mean+/-SD", "match"))
    print("-" * 96)
    all_ok = True
    for fam, ep in ORDER:
        per_seed = [100.0 * c[1] / c[0] for c in R[(fam, ep)].values() if c[0]]
        m, sd = st.mean(per_seed), st.stdev(per_seed)
        sm = float(S[(fam, ep)]["bypass_pct_mean"])
        ssd = float(S[(fam, ep)]["bypass_pct_sd"])
        ok = (round(m, 1) == round(sm, 1)) and (round(sd, 1) == round(ssd, 1))
        all_ok = all_ok and ok
        print("%-5s %-14s %18s %18s %8s" %
              (fam, ep, "%.1f+/-%.1f" % (sm, ssd), "%.1f+/-%.1f" % (m, sd),
               "OK" if ok else "DIFF"))
    print("-" * 96)
    print("All per-page bypass rates reproduced from raw round counts:",
          "YES" if all_ok else "NO")


if __name__ == "__main__":
    main()
