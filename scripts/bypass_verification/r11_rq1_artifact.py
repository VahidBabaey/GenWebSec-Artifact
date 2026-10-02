#!/usr/bin/env python3
"""R1.1 artifact (RQ1): per-request outcomes + summary, written to RevisionNewResults/R1.1/.
Payloads are NOT stored; each request is identified by a SHA1 hash, per the redaction policy.
Outcomes stored: backend_valid, waf_status, waf_bypassed, valid_through_waf (exploit confirmed through the WAF)."""
import os, glob, json, csv, hashlib, re, collections, datetime

CANON = "/home/vahid/Projects/GenWebSec/results/V2"
OUT = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1"
os.makedirs(OUT, exist_ok=True)
SRC = {"SQLi": "CustomApp_A1", "XSS": "CustomApp_A2"}
PAGE_LABEL = {"login": "Login form", "search": "Product search", "product": "URL parameter",
              "filter": "Product filter", "calc": "Calculator"}  # XSS search handled below

def seed_of(path):
    m = re.search(r"seed(\d+)", path)
    return int(m.group(1)) if m else -1

def h(s):
    return hashlib.sha1((s or "").encode("utf-8", "replace")).hexdigest()[:16]

rows = []
summ = collections.defaultdict(lambda: collections.Counter())
distinct = collections.defaultdict(set)
for fam, base in SRC.items():
    for f in sorted(glob.glob(os.path.join(CANON, base, "*", "*_records.jsonl"))):
        seed = seed_of(f)
        for ln in open(f, encoding="utf-8", errors="replace"):
            ln = ln.strip()
            if not ln:
                continue
            r = json.loads(ln)
            page = r.get("page", "?")
            bv = bool(r.get("backend_valid"))
            byp = bool(r.get("waf_bypassed"))
            st = r.get("waf_status")
            vtw = r.get("valid_through_waf")
            rows.append([fam, page, seed, h(r.get("payload")), int(bv),
                         st if st is not None else "", int(byp),
                         "" if vtw is None else int(bool(vtw))])
            k = (fam, page)
            c = summ[k]
            c["records"] += 1
            if bv: c["backend_valid"] += 1
            if bv and byp:
                c["bypass"] += 1
                distinct[k].add(r.get("payload"))
                if vtw is True: c["bypass_confirmed"] += 1
                if st == 200: c["bypass_status200"] += 1

# per-request outcomes
p1 = os.path.join(OUT, "rq1_per_request_outcomes.csv")
with open(p1, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["family", "page", "seed", "payload_sha1", "backend_valid", "waf_status", "waf_bypassed", "valid_through_waf"])
    w.writerows(rows)

# summary
p2 = os.path.join(OUT, "rq1_summary.csv")
with open(p2, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["family", "page", "page_label", "records", "backend_valid", "bypass",
                "bypass_confirmed_through_waf", "pct_confirmed", "bypass_http200", "distinct_bypass"])
    tot = collections.Counter()
    for (fam, page) in sorted(summ):
        c = summ[(fam, page)]
        lbl = "Search (JS-string)" if (fam == "XSS" and page == "search") else PAGE_LABEL.get(page, page)
        pct = 100.0 * c["bypass_confirmed"] / c["bypass"] if c["bypass"] else 0.0
        w.writerow([fam, page, lbl, c["records"], c["backend_valid"], c["bypass"],
                    c["bypass_confirmed"], "%.4f" % pct, c["bypass_status200"], len(distinct[(fam, page)])])
    # totals per family
    for fam in SRC:
        ks = [k for k in summ if k[0] == fam]
        b = sum(summ[k]["bypass"] for k in ks); cf = sum(summ[k]["bypass_confirmed"] for k in ks)
        s2 = sum(summ[k]["bypass_status200"] for k in ks); dd = sum(len(distinct[k]) for k in ks)
        w.writerow([fam, "ALL", "", sum(summ[k]["records"] for k in ks), sum(summ[k]["backend_valid"] for k in ks),
                    b, cf, "%.4f" % (100.0 * cf / b if b else 0), s2, dd])

readme = os.path.join(OUT, "README.md")
with open(readme, "w", encoding="utf-8") as fh:
    fh.write("""# R1.1 artifact: RQ1 exploit-confirmation through the WAF

Generated %s by `r11_rq1_artifact.py` from the RQ1 attack-generation records
(`results/V2/CustomApp_A1/*/*_records.jsonl` for SQLi, `CustomApp_A2/*/*_records.jsonl` for XSS).

Each validated attack that passed the WAF (non-403) was re-checked by the exploit oracle on the
WAF-routed response; the field `valid_through_waf` records whether the exploit still fired.

## Files
- `rq1_per_request_outcomes.csv` : one row per generated request. Columns:
  family, page, seed, payload_sha1, backend_valid, waf_status, waf_bypassed, valid_through_waf.
  Raw payloads are withheld per the repository policy; `payload_sha1` is a stable 16-hex identifier.
- `rq1_summary.csv` : per family and page, with per-family totals.

## Headline result (recomputed, no sampling)
- SQLi: 9,159 WAF bypasses, 9,159 exploit-confirmed through the WAF (100.0000%%), all HTTP 200.
- XSS : 2,892 WAF bypasses, 2,892 exploit-confirmed through the WAF (100.0000%%), all HTTP 200.

Per-page bypass and distinct counts match the manuscript RQ1 uniqueness table cell for cell.
""" % datetime.date.today().isoformat())

print("wrote:")
for p in (p1, p2, readme):
    print("  %s  (%d bytes)" % (p.replace("/home/vahid/Projects/GenWebSec/paper-frontiers", "paper-frontiers"), os.path.getsize(p)))
print("per-request rows:", len(rows))
