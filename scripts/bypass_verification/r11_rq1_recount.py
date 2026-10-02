#!/usr/bin/env python3
"""R1.1 step 1: recompute the RQ1 exploit-through-WAF result from EVERY attack record.
No sampling. Reports, per family and page: validated attacks, WAF bypasses (non-403),
and of those how many were exploit-confirmed through the WAF (valid_through_waf==True),
plus the HTTP-status distribution of the bypasses and any anomalies.
Payload strings are never printed."""
import os, glob, json, collections

CANON = "/home/vahid/Projects/GenWebSec/results/V2"
SRC = {"SQLi": "CustomApp_A1", "XSS": "CustomApp_A2"}

def records(base):
    for f in sorted(glob.glob(os.path.join(CANON, base, "*", "*_records.jsonl"))):
        seed = next((p for p in f.split(os.sep) if "seed" in p), "?")
        for ln in open(f, encoding="utf-8", errors="replace"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                yield f, seed, json.loads(ln)
            except Exception:
                yield f, seed, None  # count parse failures

grand = collections.Counter()
for fam, base in SRC.items():
    print("=" * 100)
    print("%s  (%s)" % (fam, base))
    print("=" * 100)
    nfiles = len(glob.glob(os.path.join(CANON, base, "*", "*_records.jsonl")))
    per_page = collections.defaultdict(lambda: collections.Counter())
    status_of_bypass = collections.Counter()
    vtw_of_bypass = collections.Counter()      # True / False / None among bypasses
    bypass_payloads = collections.defaultdict(set)
    anomalies = []
    total = parse_fail = 0
    for f, seed, r in records(base):
        total += 1
        if r is None:
            parse_fail += 1
            continue
        page = r.get("page", "?")
        pc = per_page[page]
        pc["records"] += 1
        bv = bool(r.get("backend_valid"))
        if bv:
            pc["backend_valid"] += 1
        byp = bool(r.get("waf_bypassed"))
        st = r.get("waf_status")
        # a "bypass" as the paper counts it = a validated attack that passes the WAF
        if bv and byp:
            pc["bypass"] += 1
            status_of_bypass[st] += 1
            vtw = r.get("valid_through_waf")
            vtw_of_bypass[vtw] += 1
            if vtw is True:
                pc["bypass_confirmed"] += 1
            bypass_payloads[page].add(r.get("payload"))
            if st == 403:
                anomalies.append("waf_bypassed=True but waf_status=403 (page=%s seed=%s)" % (page, seed))
    # print per page
    print("%-10s %9s %9s %9s %12s %12s" % ("page", "records", "valid", "bypass", "confirmed", "distinctByp"))
    fam_byp = fam_conf = fam_valid = fam_rec = 0
    for page in sorted(per_page):
        c = per_page[page]
        print("%-10s %9d %9d %9d %12d %12d" % (page, c["records"], c["backend_valid"], c["bypass"], c["bypass_confirmed"], len(bypass_payloads[page])))
        fam_rec += c["records"]; fam_valid += c["backend_valid"]; fam_byp += c["bypass"]; fam_conf += c["bypass_confirmed"]
    distinct_byp = sum(len(s) for s in bypass_payloads.values())
    print("-" * 64)
    print("%-10s %9d %9d %9d %12d %12d" % ("TOTAL", fam_rec, fam_valid, fam_byp, fam_conf, distinct_byp))
    print("\n  files read: %d | records: %d | parse failures: %d" % (nfiles, total, parse_fail))
    print("  bypasses (validated + passed WAF): %d" % fam_byp)
    print("  of those exploit-confirmed through the WAF (valid_through_waf==True): %d (%.4f%%)" % (fam_conf, 100.0 * fam_conf / fam_byp if fam_byp else 0))
    print("  valid_through_waf value counts among bypasses:", dict(vtw_of_bypass))
    print("  HTTP status of bypasses:", dict(status_of_bypass))
    if anomalies:
        print("  ANOMALIES:", anomalies[:10], "..." if len(anomalies) > 10 else "")
    else:
        print("  anomalies: none")
    grand["byp_" + fam] = fam_byp
    grand["conf_" + fam] = fam_conf
    grand["distinct_" + fam] = distinct_byp
print("\n" + "=" * 100)
print("SUMMARY")
print("=" * 100)
for fam in SRC:
    print("  %s: %d WAF bypasses, %d exploit-confirmed (%.4f%%), %d distinct bypassing payloads" % (
        fam, grand["byp_" + fam], grand["conf_" + fam],
        100.0 * grand["conf_" + fam] / grand["byp_" + fam] if grand["byp_" + fam] else 0, grand["distinct_" + fam]))
