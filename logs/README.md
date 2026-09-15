# Logs

Structured experiment logs, sanitized.

## Why the raw logs are not released verbatim

The raw run logs record every attack candidate inline: the per-candidate attack
lines, the DBSCAN cluster listings, and the adaptive confirmation batches all
contain attack payloads. Releasing them verbatim would publish those payloads,
which this artifact does not do (see `data/attack-corpora.md`). This directory
therefore holds the **sanitized structured form** of the log: the same per-event
records, with every payload replaced by an ordinal candidate identifier.

## `rq1_attack_events.csv`

One row per attack candidate from the RQ1 generation runs (15,000 events), fully
payload-free:

| Column | Meaning |
| --- | --- |
| `run_id`, `family`, `target`, `page`, `seed` | which run |
| `iter` | generation round |
| `candidate_id` | ordinal id of the candidate (`<run>_i<iter>_c<n>`); never the payload |
| `reached_route`, `attempted_sql` | funnel progress flags |
| `backend_valid`, `backend_status` | application-oracle validity result |
| `waf_tested`, `waf_status`, `waf_blocked`, `waf_bypassed` | WAF replay result |
| `category` | final status (`backend_valid`, `backend_invalid`, `sql_failed`, `non_executable`) |

The candidate id is a sequential index, not a hash, so it carries no information
about the payload it stands for.

## Where the other logged fields live

The specification's log fields are spread across the structured artifacts already
released; this table says where each one is, so nothing is duplicated:

| Logged field | Location |
| --- | --- |
| run identifier, random seed | this file; every `results/*` matrix |
| candidate identifier | `candidate_id` here |
| validity result | `backend_valid` here |
| WAF result | `waf_*` here |
| grouping result | cluster/group sizes in `results/rq2`, `results/rq3` (`num_clusters`) |
| candidate-rule identifier | `rules/accepted_rules.csv` (`rule_id`) |
| admission result | `rules/accepted_rules.csv` (accepted) and `rules/rejected_summary.csv` |
| rejection reason | `rules/rejected_summary.csv` |
| benign-replay result | `added_fp_pct` in the RQ2/RQ3 matrices; `results/rq4_fp` |
| token accounting, timing | `results/budget/budget_matrix.csv`; per-round in `results/rq3/rq3_round_traces.csv` |
| final status | `category` here; run-level `converged`/final in the RQ3 matrix |
| model identifier | `configs/experiment/common.yaml` (gpt-4.1-mini); also `model`/`attacker_model` in the run manifests |
| configuration hash | `config_hash` in `manifests/run_manifests.csv` (SHA-256 of the run's config files; recipe in the manifests README) |
| timestamps | `start_ts`/`end_ts` in the run manifests (repository section 18) |

## Sanitization performed

The released log is built by extracting only a fixed whitelist of numeric and label
fields from the raw records; the payload, the exact request, and the raw SQL are
never read into the output. The result was scanned for payload-like content (0 hits)
and, by construction, contains no attack prompts, API keys, provider credentials,
private endpoints, environment secrets, or machine-specific identifiers. Timestamps
and host paths from the raw logs are not carried over; run dates are in
`environment/execution-dates.md` and per-run metadata is in the manifests
(repository section 18).
