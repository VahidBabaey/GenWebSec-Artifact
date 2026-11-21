# Paranoia-level-2 (PL2) robustness

Maps the PL2 robustness evaluation to its files. Supports reviewer comment R2.3 and the manuscript
PL2 table (`tab:r23-pl2`). Frozen held-out attacks and benign corpora are replayed at CRS paranoia
level 2, all else held fixed. The table reports PL2 under CRS 4.29.0; the frozen rules face the held-out attacks that bypass CRS 4.29.0
at PL1. `analysis/pl2_table.py` reproduces the table.

## Summary tables (`tab:r23-pl2`)
- `results/pl2/crs429_pl2_block_rates.csv`, `crs429_pl2_benign_fp.csv` -- per family and configuration,
  mean/min/max block rate and CSIC / custom-application false positives, computed from the held-out
  CRS-4.29-bypassing attacks.
- `analysis/pl2_table.py` reads these and prints the block-rate and FP table.

## Per-held-out-set block rates
- `results/pl2/per_config/sqli/` (40 sets), `results/pl2/per_config/xss/` (15 sets) -- one row per
  configuration (CRS-only; CG-Static and CG-Adaptive for defense seeds 1-10): blocked, total, and
  execution-confirmed bypasses (verified_bypass for SQLi, bypass200 for XSS).

## Benign false positives (per seed)
- `results/pl2/benign/` -- A1 (per-backend SQLi + CSIC-2012), A2 (bWAPP calculator XSS + CSIC-2012),
  customapp (custom-application SQLi and XSS).

## Scripts
- `scripts/pl2/` -- PL2 replay and benign drivers and the resumable run loops.

## Key numbers (from the files above)
CRS 4.29.0 at PL2:
- SQLi block rate: CRS-only 100%, CRS + CG 100%. XSS: CRS-only 98.8%, CRS + CG 100%.
- CSIC-2012 FP: 10.5% (CRS-determined). Custom-application FP: SQLi 0.85% CRS-only -> 1.13% with CG;
  XSS 0.90% for both (the newer CRS, not the generated rules, is the main FP source at PL2).

## Notes
- Raw attack payloads are withheld (consistent with the rest of the artifact); the per-attack XSS
  replay files carry generated payloads and are not published. Per-held-out-set outcomes are in
  `per_config/`.
- PL2 is non-default and was reverted after the evaluation; main results use PL1 (Appendix A).
- The CRS-4.29.0 side releases only aggregate block/FP CSVs (no per-attack rows); the underlying
  CRS-4.29-bypassing attack corpora are withheld.
