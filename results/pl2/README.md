# Paranoia-level-2 (PL2) robustness evaluation

Supports reviewer comment R2.3 and manuscript Section 5.6 (Table 11). The frozen held-out attacks
and the benign corpora are replayed at OWASP CRS paranoia level 2, holding CRS 3.3.2, the anomaly
thresholds, the backends, and the frozen generated rules fixed and raising only the paranoia level.
This measures the existing, level-1-trained rules under a stricter CRS, not a defense retrained at PL2.

## Summary (reproduces Table 11)
- `pl2_block_rates.csv` -- per family (SQLi, XSS) and configuration (CRS-only, CRS + CG-Static,
  CRS + CG-Adaptive): mean / min / max held-out block rate, CSIC-2012 false positive, and
  custom-application false positive. Block rate is the mean over held-out sets and defense seeds.
- `pl2_benign_fp.csv` -- full benign false-positive breakdown per family, technique, and corpus.

## Per-held-out-set detail
`per_config/sqli/` (40 sets = 8 contexts x 5 attack seeds), `per_config/xss/` (15 sets = 3 contexts
x 5 attack seeds). Each file has one row per configuration (CRS-only; CG-Static and CG-Adaptive for
defense seeds 1-10) with `blocked`, `total`, and the execution-confirmed bypass count
(`verified_bypass` for SQLi, `bypass200` for XSS). Block rate = blocked / total.

## Benign false positives (per seed)
`benign/` -- `r23pl2_benign_sqli_*` (A1: per-backend SQLi corpora + CSIC-2012),
`r23pl2_benign_xss_*` (A2: bWAPP calculator + CSIC-2012), `r23pl2_benign_customapp_*`
(custom-application SQLi and XSS). At PL2 CRS alone blocks 10.30% of CSIC-2012 (rule 920230,
multiple URL encoding); the generated rules add none on top (CSIC identical for CRS-only and
CRS + CG). The generated SQLi rules add a small custom-application false positive (0.18% static,
0.11% adaptive); all other benign corpora stay at 0.

## Key numbers (computed from the files above)
- SQLi block rate: CRS-only 99.8% (96.3-100), CRS + CG 100%.
- XSS block rate: CRS-only 75.2% (42-99), CRS + CG 99.98% (99.7-100).
- CSIC-2012 FP: 10.3% for both CRS-only and CRS + CG.
- Custom-application FP: SQLi 0.18% (static) / 0.11% (adaptive); XSS 0; per-backend 0.

## Scripts
`../../scripts/pl2/` -- the PL2 replay and benign drivers (`r23_replay_*`, `r23_benign_*`) and the
resumable run loops (`r23_run_*.sh`). Like the other drivers in this artifact they import withheld
attack modules and read the frozen held-out attack files at run time.

## Notes
- Raw attack payloads are not published, consistent with the rest of this artifact. The per-attack
  XSS replay files carry generated payloads and are withheld; per-held-out-set outcomes are
  summarized in `per_config/`.
- The benign A1/A2 source files carried a spurious `eps` column in their header; the released files
  use the corrected 10-column header that matches the data.
- PL2 is a non-default configuration applied only for this evaluation and reverted afterward; the
  study's main results use the default paranoia level 1 (Appendix A).
