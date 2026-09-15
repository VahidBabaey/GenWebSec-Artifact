#!/usr/bin/env python3
"""
Item 8 (SQLi) -- step 5: Route B vs CRS-only.

Load the WAF with CRS-only (empty generated-rule file), send the backend-valid
payloads through it, and split: HTTP 403 = CRS-blocked ; else = CRS-bypassing.
The CRS-bypassing set is the frozen non-LLM "winners" -> input to step 6.

Reuses pilot.send (WAF path) + the per-page config, and
helpers.modsec_helpers (write_rules / run_configtest / reload_apache).

Reads : routeA/backend_valid.tsv
Writes: crs/crs_results.tsv       (all 31 + waf_status + crs_blocked)
        crs/crs_bypassing.tsv     (the winners -> step 6)
        crs/counts.txt
"""
import os
import sys

ROOT = "/path/to/GenWebSec"
os.environ.setdefault("A1_TARGET", "customapp")
os.environ.setdefault("A1_PAGE", "login")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A1_sqli_attack_only_v2 as pilot          # noqa: E402
pilot.log_print = lambda *a, **k: None
pilot.ensure_backend_up = lambda *a, **k: True
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache   # noqa: E402

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results")
INP = os.path.join(BASE, "routeA", "backend_valid.tsv")
OUT = os.path.join(BASE, "crs")
os.makedirs(OUT, exist_ok=True)

PAGE_CFG = {
    "login":   ("username", "POST", {"password": "x"}),
    "search":  ("q",        "GET",  {}),
    "product": ("id",       "GET",  {}),
    "filter":  ("category", "GET",  {}),
}
PAGES = ["login", "search", "product", "filter"]
FAMS = ["boolean_blind", "error_based", "inline_query", "stacked_queries", "time_blind"]


def set_page(page):
    param, method, extra = PAGE_CFG[page]
    pilot.PAGE, pilot.PARAM, pilot.METHOD, pilot.EXTRA = page, param, method, extra


def set_crs_only():
    write_rules([])
    ok, out = run_configtest()
    if ok:
        reload_apache(timeout=30.0)
    return ok, out


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < len(header):
                parts += [""] * (len(header) - len(parts))
            rows.append(dict(zip(header, parts)))
    return rows, header


def main():
    rows, header = load(INP)
    ok, out = set_crs_only()
    print("[waf] CRS-only loaded: ok=%s" % ok, flush=True)
    if not ok:
        print("configtest failed:\n" + str(out))
        return

    out_cols = header + ["waf_status", "crs_blocked"]
    results = []
    for page in PAGES:
        set_page(page)
        for r in rows:
            if r["page"] != page:
                continue
            st = pilot.send(pilot.WAF, r["final_payload"])[0]
            r2 = dict(r)
            r2["waf_status"] = st
            r2["crs_blocked"] = "1" if st == 403 else "0"
            results.append(r2)

    with open(os.path.join(OUT, "crs_results.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(out_cols) + "\n")
        for r in results:
            f.write("\t".join(str(r.get(c, "")) for c in out_cols) + "\n")

    byp = [r for r in results if r["crs_blocked"] == "0"]
    with open(os.path.join(OUT, "crs_bypassing.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(out_cols) + "\n")
        for r in byp:
            f.write("\t".join(str(r.get(c, "")) for c in out_cols) + "\n")

    # ---- counts ----
    L = []
    L.append("Item 8 (SQLi) -- step 5: Route B vs CRS-only")
    L.append("crs_blocked = WAF HTTP 403 (CRS/libinjection caught it) ; else = CRS-bypassing")
    L.append("=" * 68)
    L.append("Backend-valid tested: %d" % len(results))
    nblk = sum(1 for r in results if r["crs_blocked"] == "1")
    L.append("CRS-blocked : %d" % nblk)
    L.append("CRS-bypassing (winners -> step 6): %d" % len(byp))
    L.append("")
    L.append("Per page  [valid, CRS-blocked, CRS-bypassing]:")
    for p in PAGES:
        v = [r for r in results if r["page"] == p]
        b = sum(1 for r in v if r["crs_blocked"] == "1")
        L.append("  %-8s  %2d  %2d  %2d" % (p, len(v), b, len(v) - b))
    L.append("")
    L.append("Per family  [valid, CRS-blocked, CRS-bypassing]:")
    for fam in FAMS:
        v = [r for r in results if r["family"] == fam]
        if not v:
            continue
        b = sum(1 for r in v if r["crs_blocked"] == "1")
        L.append("  %-16s  %2d  %2d  %2d" % (fam, len(v), b, len(v) - b))
    L.append("")
    if byp:
        L.append("CRS-bypassing payloads (page | family | payload):")
        for r in byp:
            L.append("  %-8s | %-14s | %s" % (r["page"], r["family"], r["final_payload"]))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[routeB-crs] WAF left on CRS-only. %d winners -> %s"
          % (len(byp), os.path.join(OUT, "crs_bypassing.tsv")))


if __name__ == "__main__":
    main()
