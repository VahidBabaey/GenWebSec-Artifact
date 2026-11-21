# Attack-diversity evaluation

Diversity of the LLM-generated attack set, per custom-application entry point, for
the attack campaign reported in the appendix: attacks generated directly against
OWASP CRS 4.29.0 (Table B8, `tab:div-crs429`). Payload-free:
only per-set counts, the distinct-text share, the method count, and the leading
method tags are released; the attack strings themselves are not.

## Contents

```
diversity/
├── attack_diversity.csv   per attack set and entry point: n_attacks, distinct_pct,
│                          n_techniques, and the leading method:count breakdown
└── README.md
```

Columns of `attack_diversity.csv`:

- `attack_set` -- `crs429` (against CRS 4.29.0).
- `family` -- `SQLi` or `XSS`.
- `entry_point` -- the custom-application page under test (Login, Search, URL
  parameter, Filter, Calculator).
- `n_attacks` -- number of generated attacks in the set.
- `distinct_pct` -- share of attacks whose exact text appears only once, as reported
  by the source tagger (two decimals).
- `n_techniques` -- number of distinct evasion methods present across the set, out of
  a fixed catalog of 15 for SQLi and 12 for XSS.
- `techniques` -- the leading methods by attack count, as `method:count` pairs
  separated by `; `. These are method/technique names (for example `quote_breakout`,
  `case_when`, `subselect`, `sink_call`), not payloads. The source catch-all tag is
  written here as `other`.

## Reproduced tables (`analysis/attack_diversity.py`)

The Distinct (%) column is `distinct_pct` rounded half-up to one decimal, which is the
figure the manuscript prints. The Tech. column is `n_techniques`.

### Table B8 -- direct against CRS 4.29.0 (`tab:div-crs429`)

| Family | Entry point | Distinct (%) | Tech. |
| --- | --- | ---: | ---: |
| SQLi | Login | 99.0 | 8 |
| SQLi | Search | 100.0 | 11 |
| SQLi | URL parameter | 100.0 | 11 |
| SQLi | Filter | 100.0 | 12 |
| XSS | Search | 90.5 | 3 |
| XSS | Calculator | 99.2 | 6 |

Between 90.5 and 100 percent of the attacks are distinct on every page, and each set
draws on 3 to 12 independent evasion methods, so the large attack counts are not
inflated by exact duplicates or by a single repeated method.

## Reproduce

```
python analysis/attack_diversity.py
```

## Scope and provenance

- Only the six custom-application entry points are tabulated, matching the appendix
  table. The CRS 4.29.0 set is the attack campaign of Table `tab:crs429-gen`.
- `distinct_pct` is the source-reported percentage. The one-decimal value printed by
  the analysis script and shown above is that percentage rounded half-up, so it can
  differ in the last place from a fresh `distinct / n_attacks` ratio (for example the
  CRS 4.29.0 XSS Calculator row, source 99.15, prints 99.2).
- The method tagger labels each attack with every method it contains, so the per-method
  counts in `techniques` sum to more than `n_attacks`, and the listed methods are the
  most frequent ones rather than the full catalog (`n_techniques` gives the full count).

## Redaction

No attack strings, breakout templates, or attack-agent prompts are published. Each row
carries only derived counts, the distinct-text percentage, the method count, and the
leading method tags. This is consistent with the dual-use policy applied across the
artifact (`data/attack-corpora.md`).
