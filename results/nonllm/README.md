# Non-LLM external-validity evaluation

Independent, non-LLM attack sources (sqlmap, CSIC/Torpeda 2012, Dalfox) run through
the same execution-validation funnel as the LLM attacks, and the frozen rules
replayed against the ones that reach the replay stage. Payload-free: counts,
outcomes, and per-seed block rates only.

## Contents

```
nonllm/
├── nonllm_funnel.csv         per source: candidates -> distinct -> backend-valid -> CRS-bypassing
├── nonllm_funnel_detail.csv  the same, broken down per page and per technique
├── nonllm_dalfox_replay.csv  per-seed block rate of the frozen rules on the 45 Dalfox CRS bypasses
├── nonllm_sqlmap_crs_outcomes.csv      per-payload outcome (payload hashed): sqlmap, Route A + CRS
├── nonllm_csic_crs_outcomes.csv        per-payload outcome (payload hashed): CSIC/Torpeda
├── nonllm_dalfox_crs_outcomes.csv      per-payload outcome (payload hashed): Dalfox, execution + CRS
├── nonllm_dalfox_replay_perattack.csv  per-(payload,config) replay outcome (payload hashed)
├── scripts/                  the funnel/replay processing code (10 scripts; 2 redacted)
└── README.md
```

## The funnel (`nonllm_funnel.csv`)

| Source | Type | Candidates | Distinct | Backend-valid | CRS-bypassing |
| --- | --- | --- | --- | --- | --- |
| sqlmap | SQLi | 1,316 | 329 | 31 | 0 |
| CSIC/Torpeda 2012 | SQLi | 57,812 | 15,796 | 224 | 0 |
| Dalfox | XSS | 117 | 39 | 59 | 45 |

The two SQL-injection tools produce real exploits (31 and 224 backend-valid), but
CRS with libinjection blocks every one, so none reaches the replay stage. This is
the expected outcome and confirms the exploit oracle is sound. The XSS tool is the
substantive external-validity case: 45 of Dalfox's JavaScript-context payloads both
fire a browser dialog and bypass CRS, reaching the replay stage as a genuine
held-out set. Per-page and per-technique breakdowns are in
`nonllm_funnel_detail.csv`.

## Dalfox replay (`nonllm_dalfox_replay.csv`)

The 45 CRS-bypassing Dalfox payloads replayed against each per-seed frozen ruleset
at eps=0.3. Columns: `technique`, `cg_seed`, `n_rules`, `blocked`, `total` (45),
`block_rate_pct`, `bypassed`.

Reproduced result (`analysis/nonllm_funnel.py`):

| Rule set | Block rate | Median | Range |
| --- | --- | --- | --- |
| CRS-only | 0.0 | - | - |
| CG-Static | 95.3 +/- 3.2 | 93.3 | 93.3-100 |
| CG-Adaptive | 96.0 +/- 3.4 | 93.3 | 93.3-100 |

Rules hardened only on LLM attacks block ~96% of a different tool's payloads; the
two strategies are statistically indistinguishable here, consistent with RQ4.

## Tool versions, method, budgets, and commands (R2.1 / R2.4 reproducibility)

**Tools and versions (pinned).**

- sqlmap: git commit `a184c89a6bdb007502aed50f3d86862c4055f3b3`; payloads read statically
  from `tools/sqlmap/data/xml/payloads` (six families: boolean_blind, error_based,
  inline_query, stacked_queries, time_blind, union_query).
- Dalfox: git commit `ad2888756d87972acd021bc82adb44cf85698132`; JS-context payloads read
  statically from `tools/dalfox/src/payload/xss_javascript.rs` (arrays `XSS_JAVASCRIPT_PAYLOADS`
  and `XSS_JAVASCRIPT_PAYLOADS_SMALL`).
- CSIC/Torpeda 2012: third-party corpus; retrieval, checksums, and counts in
  `data/third-party/csic-torpeda-2012.md`.
- XSStrike is *not* used; the XSS non-LLM source is Dalfox.

**Method / configuration.** These are *static payload-database extractions*, not live tool runs
against the application. Each tool's shipped payloads are read, instantiated deterministically
(fixed placeholder table), and wrapped in each compatible application context (per-page breakout;
the breakout templates are redacted in the public scripts). Every candidate then passes through the
same execution-validation funnel: Route A (backend, no WAF) decides execution-validity, and Route B
(CRS-only baseline) splits CRS-blocked (HTTP 403) from CRS-bypassing. Only execution-valid,
CRS-bypassing attacks reach the frozen-ruleset replay. sqlmap's UNION family is excluded by design
(its payloads are built dynamically from the target column count, and a column-matched union is
outside this oracle's goal of auth-bypass or full-table dump).

**Fixed budgets (deterministic; same inputs produce byte-identical output).** The budget is the
complete shipped payload set of each tool, not a sampled search:

| Source | Candidates | Distinct | Execution-valid | CRS-bypassing |
| --- | --- | --- | --- | --- |
| sqlmap | 1,316 | 329 | 31 | 0 |
| CSIC/Torpeda 2012 | 57,812 | 15,796 | 224 | 0 |
| Dalfox | 117 | 39 | 59 | 45 |

**Frozen-ruleset replay (configuration).** The 45 Dalfox CRS-bypassing winners are replayed against
the frozen per-seed rule sets at eps=0.3, seeds 1-10, for both CG-Static (from the saved
`CustomApp_D2/` runs) and CG-Adaptive (from `CustomApp_C2/`), re-identified and loaded on top of CRS;
blocked means HTTP 403, and each winner is sent to its own page (`search.php?q=` / `calc.php?expr=`).
Outcomes are in `nonllm_dalfox_replay.csv`: CRS-only 0 percent, CG-Static 95.3 +/- 3.2 percent
(median 93.3, range 93.3-100), CG-Adaptive 96.0 +/- 3.4 percent.

**Commands (run order).**

- sqlmap: `scripts/01_extract_sqlmap_corpus.py` -> `02_routeA_validate.py` -> `03_routeB_crs.py`.
- CSIC: `scripts/11_extract_csic_sqli.py` -> `12_routeA_csic.py` -> `13_routeB_crs_csic.py`.
- Dalfox: `scripts/21_extract_dalfox_xss.py` -> `22_routeA_dalfox_xss.py` ->
  `23_routeB_crs_dalfox_xss.py` -> `24_replay_dalfox_xss.py`.

Each script's header documents its exact reads and writes.

**Raw search outcomes (payloads hashed).** Per-payload outcome records are released with every
attack-string column removed and the payload identified only by a SHA-1 hash (`payload_sha1`):

- `nonllm_sqlmap_crs_outcomes.csv` -- 31 execution-valid sqlmap payloads: page, family, Route A
  category, backend status, `backend_valid`, `waf_status`, `crs_blocked`.
- `nonllm_csic_crs_outcomes.csv` -- 224 CSIC/Torpeda payloads: page, parameter, technique tag, Route A
  category, `backend_valid`, `waf_status`, `crs_blocked`.
- `nonllm_dalfox_crs_outcomes.csv` -- 59 Dalfox payloads: page, variant, source array, `reached`,
  `executed`, `backend_valid`, `waf_status`, `crs_blocked`.
- `nonllm_dalfox_replay_perattack.csv` -- the 45 Dalfox CRS-bypassers across 21 configurations
  (CRS-only plus CG-Static and CG-Adaptive, seeds 1-10): `technique`, `cg_seed`, `page`, `blocked`.

Each file keeps only outcome flags and coarse technique/context labels; the raw payload strings and the
per-context breakout templates are not published (dual-use policy). The intermediate corpora
(`candidates.tsv`) and the un-hashed run-tree files carry the tool payloads and are not redistributed.
The aggregate funnel (`nonllm_funnel.csv`) and per-seed replay (`nonllm_dalfox_replay.csv`) remain.

## Reproduce

```
python analysis/nonllm_funnel.py
```

## Scripts and what was redacted

`scripts/` holds the funnel and replay processing code: sqlmap/CSIC/Dalfox
extraction, the Route A (backend execution) validators, the Route B (CRS) checks,
and the Dalfox replay. Seven scripts are verbatim. Three carry redactions:

- `01_extract_sqlmap_corpus.py`: the per-page injection-breakout templates
  (the prefix/comment each sqlmap payload is wrapped in) are replaced with
  `[breakout redacted]`; the query-structure comments and the mapping logic are
  kept.
- `21_extract_dalfox_xss.py`: the per-page XSS injection-breakout templates (the
  quote-escaping wrapper applied to each Dalfox JS payload) and the worked sample
  payloads are replaced with `[breakout redacted]` / `[redacted for safety]`; the
  extraction and mapping logic, the sink/context comments, and the counts are kept.
- `22_routeA_dalfox_xss.py`: the browser-oracle smoke-test payload is replaced with
  `[smoke-test payload redacted]`.

## Third-party payloads

sqlmap and Dalfox payloads are generated by those tools; the CSIC/Torpeda 2012 set
is third-party (see `data/third-party/csic-torpeda-2012.md` for retrieval,
checksums, and counts). None of these payload sets is redistributed here; only the
funnel counts and replay outcomes are released, consistent with
`data/attack-corpora.md`.
