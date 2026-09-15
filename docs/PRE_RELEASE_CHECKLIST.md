# Final pre-release checklist

Status of every item in the artifact specification's final checklist. Done items
name the evidence; pending items are release-time steps or author decisions.

| # | Item | Status | Evidence / note |
| --- | --- | --- | --- |
| 1 | Exact software, model, CRS, browser, hardware, execution-date identifiers | done | `environment/software-versions.txt`, `hardware.md`, `execution-dates.md`; all read from the live host |
| 2 | Freeze the code commit corresponding to the paper | **pending** | code was not under version control at run time; the tagged release of this repo is the reference (see `manifests/README.md`) |
| 3 | Machine-readable experiment manifests | done | `manifests/run_manifests.csv` (1,085 runs) + `manifests/paper_runs.csv` (top-level: each submitted-paper table -> its backing runs) |
| 4 | Redacted defense-agent prompts | done | `prompts/defense/` (4 files, examples redacted) |
| 5 | Attack-agent prompts absent from all files and logs | done | audit: 0 attack-prompt hits across 209 files (`docs/SECURITY_AUDIT.md`) |
| 6 | Remove credentials and private infrastructure data | done | audit: 0 keys/passwords; machine paths neutralized in 27 files |
| 7 | All final per-seed rulesets | done | `rules/final_rulesets/` (40 frozen `.conf`) |
| 8 | Full RQ1-RQ4 structured results | done | `results/rq1` .. `results/rq4` |
| 9 | Full epsilon-sweep outputs | done | `results/rq2/rq2_eps_sweep.csv`, `results/rq3/rq3_eps_sweep.csv`, `results/rq4` (all eps) |
| 10 | Detailed synthesis-cost and timing results | done | `results/budget/budget_matrix.csv` |
| 11 | False-positive incident artifacts | done | `results/rq4_fp/` (matrix + incidents) |
| 12 | Non-LLM validation artifacts | done | `results/nonllm/` (funnel, Dalfox replay, scripts) |
| 13 | Scripts that regenerate all paper tables and figures | done | `analysis/` (15 scripts) + `analysis/run_all.py`; all table data and the RQ1 trajectory figure's data are regenerated, the schematic diagrams are not data-derived (see `README.md`) |
| 14 | Document third-party dataset acquisition | done | `data/third-party/csic-torpeda-2012.md` |
| 15 | Checksums for released corpora and final artifacts | done | `SHA256SUMS` (all files) + `manifests/provenance_checksums.csv` |
| 16 | Run reproduction scripts from a clean checkout | done | `python analysis/run_all.py` -> 15 ok, 0 failed |
| 17 | Tag the exact repository release referenced by the paper | **pending** | done at publication, together with item 2 |

## Remaining before the repository is made public

Three things, all requiring an author decision or a publication-time action:

1. **`LICENSE`** -- currently a placeholder; a public repository needs a real
   license (the file suggests MIT/Apache-2.0 for code, CC BY 4.0 for data). This is
   the one hard blocker.
2. **Release identifiers** -- fill the repository URL, DOI, and release date in
   `CITATION.cff`, and replace `[INSERT DATA-REPOSITORY LINK BEFORE SUBMISSION.]` in
   the paper appendix, once the repo is public and (optionally) a Zenodo DOI is minted.
3. **Final integrity pass** -- freeze/tag the release (items 2 and 17), then re-run
   the audit and regenerate `SHA256SUMS` as the last step so the checksums cover the
   exact published tree.

Everything else is complete and verified.
