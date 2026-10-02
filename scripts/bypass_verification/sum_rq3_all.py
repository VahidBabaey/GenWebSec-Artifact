#!/usr/bin/env python3
"""Consolidated R1.1 RQ3 held-out replay verification, both families.
SQLi: full-funnel two-stage replay (rq3/rq3_sqli_summary.csv).
XSS : valid+bypassed scope (rq3_xss/rq3_xss_summary.csv).
Prints, per family: runs, funnel-faithfulness, residual bypasses, how many were re-confirmed real
exploits through the WAF, and the false-bypass count (bypasses that are NOT real exploits)."""
import csv, os
BASE = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1"
SQLI = f"{BASE}/rq3/rq3_sqli_summary.csv"
XSS = f"{BASE}/rq3_xss/rq3_xss_summary.csv"

def rint(x):
    try: return int(float(x))
    except Exception: return 0

print("="*78)
print("R1.1 RQ3 HELD-OUT REPLAY — two-stage bypass-criterion re-verification")
print("="*78)

if os.path.exists(SQLI):
    rows = list(csv.DictReader(open(SQLI)))
    print(f"\n[SQLi] full-funnel two-stage replay — {len(rows)} runs")
    by = {}
    for r in rows: by.setdefault((r["strategy"], r["page"]), 0); by[(r["strategy"], r["page"])] += 1
    print("  runs per (strategy,page):", dict(by))
    unf = [r for r in rows if r["faithful"] != "1"]
    print("  UNFAITHFUL runs (replay funnel != logged funnel):", len(unf))
    for r in unf[:10]:
        print("    ", r["strategy"], r["page"], "seed", r["seed"],
              "log v/cb/blk/res=%s/%s/%s/%s"%(r["log_valid"],r["log_crsbyp"],r["log_blocked"],r["log_resid"]),
              "rep=%s/%s/%s/%s"%(r["rep_valid"],r["rep_crsbyp"],r["rep_blocked"],r["rep_resid"]))
    resid = sum(rint(r["rep_resid"]) for r in rows)
    residx = sum(rint(r["ver_resid_exploit"]) for r in rows)
    fb = sum(rint(r["false_bypass"]) for r in rows)
    print(f"  residual bypasses (reported, 403-only):            {resid}")
    print(f"  residuals re-confirmed as real exploits (2-stage): {residx}")
    print(f"  FALSE bypasses (not-403 but NOT a real exploit):   {fb}")
    diff = [r for r in rows if r["rep_block%"] != r["ver_block%"]]
    print(f"  runs where verified block%% != reported block%%:    {len(diff)}")

if os.path.exists(XSS):
    rows = list(csv.DictReader(open(XSS)))
    print(f"\n[XSS] valid+bypassed scope — {len(rows)} runs")
    by = {}
    for r in rows: by.setdefault((r["strategy"], r["page"]), 0); by[(r["strategy"], r["page"])] += 1
    print("  runs per (strategy,page):", dict(by))
    unf = [r for r in rows if r["faithful_funnel"] != "1"]
    print("  runs whose replayed funnel != logged funnel:", len(unf))
    for r in unf[:10]:
        print("    ", r["strategy"], r["page"], "seed", r["seed"],
              "log cb/blk/res=%s/%s/%s"%(r["log_crsbyp"],r["log_blocked"],r["log_resid"]),
              "rep=%s/%s/%s"%(r["rep_crsbyp"],r["rep_blocked"],r["rep_resid"]))
    val_log = sum(rint(r["log_valid"]) for r in rows)
    val_conf = sum(rint(r["reA_valid_confirmed"]) for r in rows)
    resid = sum(rint(r["rep_resid"]) for r in rows)
    residx = sum(rint(r["resid_exploit_confirmed"]) for r in rows)
    fb = sum(rint(r["false_bypass"]) for r in rows)
    print(f"  valid held-out attacks (log):                      {val_log}")
    print(f"  of those re-confirmed executing on the backend:    {val_conf}")
    print(f"  residual bypasses (reported, 403-only):            {resid}")
    print(f"  residuals re-confirmed as real exploits (browser): {residx}")
    print(f"  FALSE bypasses (not-403 but NOT a real exploit):   {fb}")

print("\n" + "="*78)
