# Paranoia-level-2 (PL2) robustness

Maps the PL2 robustness evaluation to its files. Supports reviewer comment R2.3 and manuscript
Section 5.6 (Table 11). Frozen held-out attacks and benign corpora are replayed at CRS paranoia
level 2, all else held fixed.

## Summary tables (Table 11)
- `results/pl2/pl2_block_rates.csv` -- per family and configuration: mean/min/max block rate, CSIC
  and custom-application false positives. Reproduces Table 11.
- `results/pl2/pl2_benign_fp.csv` -- benign false-positive breakdown (family, technique, corpus).

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
- SQLi block rate: CRS-only 99.8% (96.3-100), CRS + CG 100%.
- XSS block rate: CRS-only 75.2% (42-99), CRS + CG 99.98% (99.7-100).
- CSIC-2012 FP: 10.3% for CRS-only and CRS + CG (generated rules add none).
- Custom-application FP: SQLi 0.18% static / 0.11% adaptive; XSS 0; per-backend 0.

## Notes
- Raw attack payloads are withheld (consistent with the rest of the artifact); the per-attack XSS
  replay files carry generated payloads and are not published. Per-held-out-set outcomes are in
  `per_config/`.
- PL2 is non-default and was reverted after the evaluation; main results use PL1 (Appendix A).
