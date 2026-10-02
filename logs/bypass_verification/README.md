# R1.1 item 5 — WAF logs (blocking vs other responses)

The reviewer asked us to use WAF logs to distinguish blocking from other responses, and to re-run a
representative replay with `SecAuditEngine On` to obtain audit entries showing the inspected request
fields for blocked and passed requests. ModSecurity's audit log was inactive during the original runs.

## What was done
`scripts/r11_audit_capture.py` enables ModSecurity audit logging (`SecAuditEngine On`, Serial log,
`SecAuditLogParts ABHZ`) via the vahid-writable `sft_rule.conf` (no root), with CRS + a CG-Adaptive
customapp rule set (eps0.3, seed 10) loaded, then replays a representative set of requests through the
WAF and parses the Serial audit log. `SecAuditEngine` is restored to `Off` afterward.

The Serial audit log is opened by the Apache master (root); writing it to a path under `/home/vahid`
(which the root master can traverse) and pre-creating the file as vahid keeps it vahid-readable. (`/tmp`
fails under the service's `PrivateTmp`; `/var/cache/modsecurity` ends up `root:root 0640`.)

## Files
- `audit_summary.csv` — one row per representative request: HTTP status, whether ModSecurity denied it,
  the matched CRS rule ids, the matched custom rule ids, message count, a redacted request line, and
  sample rule messages. Raw payloads removed.
- `audit_H_parts_redacted.txt` — the audit trailer (part H: matched rules, messages, action) per
  request, with matched payload data and the URI stripped.
- `access_log_excerpt_redacted.txt` — the same representative requests in the Apache access log (status
  field kept, query redacted), corroborating the audit outcomes.

## Result (demonstrates the log distinguishes blocking from other responses)
| Request | HTTP | ModSec denied | Matched rule(s) |
|---|---|---|---|
| benign SQLi (product) | 200 | no | none |
| benign XSS (calc) | 200 | no | none |
| classic SQLi | 403 | yes | CRS 942100 (libinjection) + 949110 anomaly |
| classic XSS | 403 | yes | CRS 941100/941110/941160 (NoScript) + 949110 |
| eval-sink `alert(1)` | 200 | no | none — a **non-403 bypass**, re-verified to execute (the reviewer's exact case) |
| held-out winners (×6) | 403 | yes | **custom rule 1000001** (COMMENT-BREAKOUT), no CRS rule |

Passed requests carry no matched rule and no deny action; blocked requests carry the matching rule id,
the rule message, and the deny action. CRS blocks (9xxxxx rule ids) and our co-evolved rules (10000xx)
are both visible and distinct; the held-out winners bypass CRS but are blocked by our rule, which is
exactly the distinction the bypass rates depend on.

## Access-log note
Contrary to the initial assessment, the Apache access log is readable by this account (member of the
`adm` group), so status-per-request corroboration needs no root copy. Every request counted as a bypass
in the replays returned HTTP 200 (see `access_log_excerpt_redacted.txt` and the RQ1/RQ3/RQ4 artifacts).
