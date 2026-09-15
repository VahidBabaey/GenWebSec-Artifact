# Generated rules and rule-admission artifacts

Every defensive rule GenWebSec synthesized, with the metadata to map each one back
to its experiment. These are ModSecurity rules (detection signatures), not attack
material; all 14,949 accepted rules were scanned and none contains an attack
payload.

## Contents

```
rules/
├── accepted_rules.csv     every accepted rule, all conditions, with metadata
├── rejected_summary.csv   per-run rejected-candidate counts, by reason
├── final_rulesets/        the frozen, deployable per-seed rulesets used in RQ4 (eps=0.3)
│   ├── sqli_eps0.3/  CG-Adaptive_seed{1..10}.conf, CG-Static_seed{1..10}.conf
│   └── xss_eps0.3/   CG-Adaptive_seed{1..10}.conf, CG-Static_seed{1..10}.conf
└── README.md
```

## `accepted_rules.csv`

One row per accepted rule (14,949 rows across every condition):

| Column | Meaning |
| --- | --- |
| `family` | SQLi or XSS |
| `context` | injection context (login, search, product, filter, calc) |
| `strategy` | PP-Static, RG, CG-Static, PP-Adaptive, or CG-Adaptive |
| `eps` | DBSCAN threshold (blank for per-payload, which does not cluster) |
| `seed` | defense seed |
| `rule_id` | ModSecurity rule id |
| `phase`, `action`, `transforms`, `msg` | the rule's phase, enforcement, transform list, and message |
| `rule_text` | the full `SecRule` |

This is the complete accepted-rule set, separated by family and context, with
static/adaptive origin, epsilon, and seed, so any rule maps unambiguously to its
run.

## `rejected_summary.csv`

Per run (family, context, strategy, eps, seed): the number of rejected candidate
rules, split by reason.

- `rejected_no_coverage`: the candidate, on its own, did not block the target
  attack (`blocks_attack=False`). This is the reason for essentially every
  rejection (3,049 of 3,050 across all runs).
- `rejected_other`: any rejection for another reason, such as the benign
  false-positive gate or a failed configuration test (1 across all runs).

Rejected candidate rules are logged by id and reason; their full rule text is not
persisted (only accepted rules print their `SecRule`), so it is not reconstructable
from the results. The run-level candidate and rejected counts are also in the RQ2
and RQ3 matrices (`results/rq2`, `results/rq3`).

A note this data makes concrete: candidates were dropped almost entirely for not
adding coverage, not for raising false positives. The false-positive gate rarely
triggered because the synthesized rules were specific; the few rules that did
over-block an *external* corpus are the RQ4 incidents in `results/rq4_fp`.

## `final_rulesets/` (the deployable frozen rulesets)

The per-seed rulesets frozen for the RQ4 generalization evaluation, at the operating
threshold eps=0.3. Each `.conf` is one defense seed's rules for a whole attack
family, combined across that family's contexts and re-numbered, exactly as replayed
against the held-out attacks and external backends. 40 files: SQLi and XSS, each
CG-Adaptive and CG-Static, seeds 1-10.

These are the artifacts to load into ModSecurity to reproduce the RQ4 block rates in
`results/rq4`. The per-context accepted rules that compose them are in
`accepted_rules.csv`.

## Configuration test

Every accepted rule passed the Apache/ModSecurity configuration test and reload
before deployment; a candidate that failed the config test was discarded during
synthesis (counted under `rejected_other`). The rules here are therefore all
load-clean.
