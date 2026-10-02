# Denominators and uncertainty for Tables 6-8 and Dalfox (R1.6)

Per-seed numerator/denominator data behind the blocking percentages, attacker-seed and defense-seed kept
separate, with exact Clopper-Pearson binomial 95% intervals. Tabulated from the saved funnels/replays; no
new runs. Supports reviewer comment R1.6 of the Frontiers revision.

- `results/denominators/rq4_perseed.csv` - RQ4 per (context, strategy, attacker_seed, defense_seed): eligible, blocked, rate.
- `results/denominators/rq4_summary.csv` - pooled rate + defense-seed spread + attack-set spread + Clopper-Pearson intervals.
- `results/denominators/rq3_cg_adaptive_perseed.csv` - RQ3 per seed: generated, backend-valid, CRS-bypasses, blocked, rate, interval.
- `results/denominators/dalfox_perseed.csv` / `dalfox_summary.csv` - Dalfox per defense seed and the two-valued summary.
- `results/denominators/README.md` - overview. Generator: `scripts/denominators/r16_tables.py`.

Counts and intervals only; no raw attack payloads.
