#!/usr/bin/env python3
"""
Item 8 (XSS) Dalfox track -- Route B vs CRS-only.

Load the WAF with CRS-only, send the backend-valid XSS payloads through the WAF
path (http://127.0.0.1/customxss/<page>.php), split HTTP 403 = CRS-blocked ; else
= CRS-bypassing. No browser needed (403 is decided at the WAF).

Reuses pilot_A2.http_status + build_url + helpers.modsec_helpers.

Reads : xss_dalfox/routeA/backend_valid.tsv
Writes: xss_dalfox/crs/crs_results.tsv, crs_bypassing.tsv, counts.txt
"""
import os
import sys

ROOT = "/path/to/GenWebSec"
os.environ.setdefault("CXSS_PAGE", "search")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A2_customxss_attack_only_v2 as pilot          # noqa: E402
pilot.log_print = lambda *a, **k: None
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache   # noqa: E402

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results/xss_dalfox")
INP = os.path.join(BASE, "routeA", "backend_valid.tsv")
OUT = os.path.join(BASE, "crs")
os.makedirs(OUT, exist_ok=True)

WAF = pilot.WAF                                    # http://127.0.0.1/customxss
PAGE_CFG = {"search": ("search.php", "q"), "calc": ("calc.php", "expr")}


def set_page(page):
    pilot.PAGE, (pilot.PAGE_FILE, pilot.PARAM) = page, PAGE_CFG[page]


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
    # sanity: is the WAF path serving customxss?
    set_page("calc")
    probe_url, _ = pilot.build_url(WAF, "1")
    print("[waf] customxss probe status = %s" % pilot.http_status(probe_url), flush=True)

    out_cols = header + ["waf_status", "crs_blocked"]
    results = []
    for page in ("search", "calc"):
        set_page(page)
        for r in rows:
            if r["page"] != page:
                continue
            url, _ = pilot.build_url(WAF, r["final_payload"])
            st = pilot.http_status(url)
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
    L.append("Item 8 (XSS) Dalfox -- Route B vs CRS-only")
    L.append("=" * 66)
    L.append("Backend-valid tested: %d" % len(results))
    nblk = sum(1 for r in results if r["crs_blocked"] == "1")
    L.append("CRS-blocked : %d" % nblk)
    L.append("CRS-bypassing (winners -> CG replay): %d" % len(byp))
    L.append("")
    L.append("Per page  [valid, CRS-blocked, CRS-bypassing]:")
    for p in ("search", "calc"):
        v = [r for r in results if r["page"] == p]
        b = sum(1 for r in v if r["crs_blocked"] == "1")
        L.append("  %-7s  %3d  %3d  %3d" % (p, len(v), b, len(v) - b))
    L.append("")
    if byp:
        L.append("CRS-bypassing payloads (page | js_payload | final):")
        for r in byp:
            L.append("  %-7s | %-45s | %s" % (r["page"], r.get("js_payload", "")[:45], r["final_payload"][:70]))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[routeB-crs] WAF left on CRS-only. %d winners -> %s"
          % (len(byp), os.path.join(OUT, "crs_bypassing.tsv")))


if __name__ == "__main__":
    main()
