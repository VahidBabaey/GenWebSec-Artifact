# Bypass-criterion verification (exploit-confirmation through the WAF)

Maps the bypass-criterion re-verification to the files that support it. This evidence shows that an
attack counted as a successful WAF bypass is a genuine exploit delivered through the WAF (a two-stage
check: backend exploit oracle, then the exploit re-confirmed on the WAF-returned response), not merely a
non-403 response. It supports the manuscript's execution-grounded validation and the response to
reviewer comment R1.1 of the Frontiers revision.

## Per-request replay outcomes (HTTP status + exploit-oracle result; payloads hashed)
`results/bypass_verification/`
- `rq1_per_request_outcomes.csv` (15,000 rows) and `rq1_summary.csv` -- attack generation (RQ1); 9,159/9,159 SQLi and 2,892/2,892 XSS non-403 bypasses exploit-confirmed, all HTTP 200.
- `rq1_replay/` -- independent app re-replay of every RQ1 bypass (9,159 SQLi + 2,892 XSS; 0 non-exploits).
- `rq3/rq3_sqli_perattack.csv` (24,000) and `rq3_xss/rq3_xss_perattack.csv` (5,392) -- held-out replay (RQ3); 207/207 SQLi residual bypasses re-confirmed, no residual XSS bypass, 0 false.
- `rq4/rq4_sqli_perrequest.csv` (13,167) and `rq4/rq4_xss_perrequest.csv` (3,073) -- frozen replay (RQ4), all four targets; 16,240 residual bypasses, all exploit-confirmed, 0 false, 0 reclassified.
- `rq3_verification_summary.txt`, `rq4/rq4_verification_summary.txt`, `rq1_replay/rq1_replay_summary.txt` -- consolidated summaries. Overview in `README.md`.

## Representative audit-log records (blocks vs other responses)
`logs/bypass_verification/`
- `audit_summary.csv` -- per representative request: HTTP status, ModSecurity deny action, matched CRS vs custom rule IDs, rule messages.
- `audit_H_parts_redacted.txt` -- audit trailer (matched rules + action) per request, matched data redacted.
- `access_log_excerpt_redacted.txt` -- Apache access-log statuses for the same requests (query redacted).
- `README.md` -- how the audit replay was run (`SecAuditEngine On`).

## Generating scripts
`scripts/bypass_verification/` -- the replay drivers, re-probers, audit-capture, aggregators, and runners.

## Notes
- Raw attack payloads and attack prompts are not published: per-request files identify payloads only by
  `payload_sha1`; audit and access-log excerpts are redacted.
- Two scripts (`setup_xss_env.py`, `r11_audit_capture.py`) contain canonical, textbook example payloads
  (`alert(1)`, `' OR '1'='1`) used as representative probes; these are not from the generated corpus.
- Environment: Apache 2.4.52 + ModSecurity 2.9.5 + OWASP CRS 3.3.2; custom SQLi/XSS apps, bWAPP, Juice Shop.
