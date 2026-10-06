# Benign-traffic diversity supplement (nested JSON, rich text)

Supports the response to reviewer comment **R2.5** (benign-traffic diversity). The reviewer noted that
the admission corpora are static and may not represent complex production inputs such as nested JSON,
GraphQL, and rich text. This supplement adds two benign corpora in those formats that the existing
corpora did not cover, and replays them through the frozen rules to measure whether the co-evolved
rules introduce any false positive beyond the CRS baseline.

It is additional to, not a replacement for, the main benign false-positive evaluation (CSIC 2012 and
the per-backend corpora) in `results/rq4_fp/` and `data/benign/`, summarized in the manuscript's
false-positive incident table (`tab:fp-incidents`).

## Result

At the operating point (eps = 0.3, paranoia level 1), on the backend-valid, baseline-passing corpus,
the co-evolved rules add **no** false positives on either format:

| Corpus | Requests | Rules deployed | CRS-only FP | CRS+CG-Static FP | CRS+CG-Adaptive FP |
| --- | --- | --- | --- | --- | --- |
| nested JSON (Juice sign-ups) | 500 | SQLi co-evolved | 0/500 | 0/500 (10 seeds) | 0/500 (10 seeds) |
| rich text (XSS search) | 500 | XSS co-evolved | 0/500 | 0/500 (10 seeds) | 0/500 (10 seeds) |

GraphQL is **not** represented: none of the evaluated applications exposes a GraphQL endpoint, so a
faithful test was not possible; it is reported as an untested format rather than sending a body to an
endpoint that would ignore it.

## Contents

```
benign_diversity/
├── benign_nested_json.jsonl     500 benign Juice sign-ups as nested JSON (transport records)
├── benign_rich_text.jsonl       500 benign rich-text search queries (transport records)
├── per_seed_fp.csv              per (corpus x configuration x seed) false-positive outcome
├── crs_baseline_rejections.csv  the 18 legitimate rich-text candidates the CRS baseline rejected, with the rule that fired
├── scripts/                     corpus builders, the replay driver, the reused FP engine, the aggregator
└── README.md
```

## How each request was validated as legitimate

Every request in both corpora is confirmed to be accepted by the application backend **before** it is
used; the transport `url` then targets the WAF (`http://localhost/...`) for the replay.

- **Nested JSON** (`benign_nested_json.jsonl`, 500): each is a real account sign-up
  `POST /api/Users` to Juice Shop, carrying a multi-field JSON body with a nested `securityQuestion`
  object. The builder (`scripts/r25_build_corpora.py`) sends each to the Juice backend
  (`127.0.0.1:3000`, no WAF) and keeps only those the backend accepts with **HTTP 201**. ModSecurity
  parses `application/json` bodies into request arguments, so the rules inspect every field.
- **Rich text** (`benign_rich_text.jsonl`, 500): each is a review-style search query
  (`GET search.php?q=...`) with punctuation, symbols, and HTML-like fragments. The builder
  (`scripts/r25_build_richtext500.py`) generates distinct candidates, keeps only those the custom-XSS
  backend (`127.0.0.1:8094`, no WAF) serves with **HTTP 200**, and then keeps only those that also
  **pass the CRS baseline** (not 403, CRS-only), matching how the paper's other benign corpora are
  built. Of **518** backend-valid candidates generated, the CRS baseline rejected **18**, leaving
  **500** (518 = 500 kept + 18 rejected). The 18 rejected are **not** part of the 500.

## Per-seed false-positive outcomes (`per_seed_fp.csv`)

One row per `(corpus, configuration, seed)`: `corpus`, `family` (rule family deployed: `sqli` for
nested JSON, `xss` for rich text), `technique` (`CRS-only`, `CG-Static`, `CG-Adaptive`), `seed`
(defense seed 1-10; blank for CRS-only), `n_rules`, `blocked` (HTTP 403 = false positive),
`total` (500), `fp_pct`, `status`. CRS-only is one row per corpus; each CG strategy is ten rows
(seeds 1-10). Every `blocked` value is 0.

## Representative rule / audit matches (`crs_baseline_rejections.csv`)

The 18 legitimate rich-text candidates the CRS baseline rejected during construction, each with the
triggering rule read from the Apache error log: columns `benign_rich_text`, `crs_rule_id`,
`crs_rule_msg`. All 18 carry an HTML-tag-like fragment (`<link in bio>`) and are blocked by CRS rule
**941100** ("XSS Attack Detected via libinjection"), which reads the benign fragment as a tag. This is
a CRS-baseline false positive, not caused by the co-evolved rules; it is reported as the kind of
false positive the recommended shadow-mode tuning step is meant to catch.

## Tools, versions, seeds, and configuration

- **WAF / environment:** Apache 2.4.52, ModSecurity 2.9.5 (blocking mode), OWASP CRS 3.3.2,
  paranoia level 1, inbound/outbound anomaly thresholds 5/4, `SecRequestBodyAccess On` with the JSON
  body processor enabled. Full versions in `environment/software-versions.txt`; CRS/ModSecurity
  configuration in `configs/crs/` and `configs/modsecurity/`.
- **Applications:** OWASP Juice Shop `bkimminich/juice-shop` 20.2.0 (nested-JSON sign-ups); the custom
  PHP XSS application (rich-text search). Python 3.10.12.
- **Rules replayed:** the frozen per-seed co-evolved rule sets at **eps = 0.3**, seeds 1-10, for both
  CG-Static and CG-Adaptive, loaded on top of CRS (the same rule sets released under
  `rules/final_rulesets/`); nested JSON uses the SQLi family, rich text the XSS family. No new rule
  synthesis occurs in this supplement.
- **Determinism:** both builders seed the generator (`random.seed(20261006)`), so the corpora
  regenerate identically.

## Reproduce

Paranoia level 1, CRS-only baseline loaded, backends up:

```
# build + backend-validate the corpora
python3 scripts/r25_build_corpora.py           # nested JSON (Juice sign-ups)
python3 scripts/r25_build_richtext500.py       # rich text (XSS search) + CRS-baseline rejections

# replay each corpus through CRS-only / CG-Static / CG-Adaptive (seeds 1-10)
CORP=nested_json TECH=CRS-only   python3 scripts/r25_replay.py
CORP=nested_json TECH=CG-Static  SEED=<s> python3 scripts/r25_replay.py   # s in 1..10
CORP=nested_json TECH=CG-Adaptive SEED=<s> python3 scripts/r25_replay.py
CORP=rich_text   TECH=CRS-only   python3 scripts/r25_replay.py
CORP=rich_text   TECH=CG-Static  SEED=<s> python3 scripts/r25_replay.py
CORP=rich_text   TECH=CG-Adaptive SEED=<s> python3 scripts/r25_replay.py

python3 scripts/r25_agg.py                      # summary over per_seed outcomes
```

The scripts carry the original WSL paths (`/home/vahid/...`); adjust them to the local checkout. The
replay reuses `scripts/benign_fp_sweep.py` (the main benign-FP engine) for rule-set construction and
false-positive measurement.

## Scope and redaction

Both corpora are **benign** and released in full (no attack payloads), consistent with the released
benign corpora under `data/benign/`. The co-evolved rule sets they are replayed against are the
released final rule sets. Nothing here is a withheld attack artifact.
