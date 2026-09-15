#!/usr/bin/env python3
"""
Item 8 (SQLi) CSIC/Torpeda track -- step: Route B vs CRS-only.

Load the WAF with CRS-only, send the CSIC backend-valid payloads through it,
split HTTP 403 = CRS-blocked ; else = CRS-bypassing. The CRS-bypassing set is
the frozen non-LLM "winners" -> input to the CG-rule replay.

Reads : csic/routeA/backend_valid.tsv
Writes: csic/crs/crs_results.tsv, csic/crs/crs_bypassing.tsv, csic/crs/counts.txt
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
pilot.HTTP_TIMEOUT = 5.0
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache   # noqa: E402

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results")
INP = os.path.join(BASE, "csic", "routeA", "backend_valid.tsv")
OUT = os.path.join(BASE, "csic", "crs")
os.makedirs(OUT, exist_ok=True)

PAGE_CFG = {
    "login":   ("username", "POST", {"password": "x"}),
    "search":  ("q",        "GET",  {}),
    "product": ("id",       "GET",  {}),
    "filter":  ("category", "GET",  {}),
}
PAGES = ["login", "search", "product", "filter"]
TAGS = ["or_tautology", "and_based", "union", "error", "time", "stacked", "other"]


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

    L = []
    L.append("Item 8 (SQLi) CSIC/Torpeda -- Route B vs CRS-only")
    L.append("=" * 66)
    L.append("Backend-valid tested: %d" % len(results))
    nblk = sum(1 for r in results if r["crs_blocked"] == "1")
    L.append("CRS-blocked : %d" % nblk)
    L.append("CRS-bypassing (winners -> CG replay): %d" % len(byp))
    L.append("")
    L.append("Per page  [valid, CRS-blocked, CRS-bypassing]:")
    for p in PAGES:
        v = [r for r in results if r["page"] == p]
        b = sum(1 for r in v if r["crs_blocked"] == "1")
        L.append("  %-8s  %3d  %3d  %3d" % (p, len(v), b, len(v) - b))
    L.append("")
    L.append("Per technique tag  [valid, CRS-blocked, CRS-bypassing]:")
    for t in TAGS:
        v = [r for r in results if r.get("tech_tag") == t]
        if not v:
            continue
        b = sum(1 for r in v if r["crs_blocked"] == "1")
        L.append("  %-14s  %3d  %3d  %3d" % (t, len(v), b, len(v) - b))
    L.append("")
    if byp:
        L.append("CRS-bypassing payloads (page | tag | payload):")
        for r in byp[:60]:
            L.append("  %-8s | %-13s | %s" % (r["page"], r.get("tech_tag", ""), r["final_payload"][:120]))
        if len(byp) > 60:
            L.append("  ... (%d more; see crs_bypassing.tsv)" % (len(byp) - 60))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[routeB-crs] WAF left on CRS-only. %d winners -> %s"
          % (len(byp), os.path.join(OUT, "crs_bypassing.tsv")))


if __name__ == "__main__":
    main()
