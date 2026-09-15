#!/usr/bin/env python3
"""
Item 8 (SQLi) -- step 4: Route A validity on the WAF-free backend (:8080).

Reuses pilot_A1_sqli_attack_only_v2.probe() and its per-page validity oracle
VERBATIM (login -> login_ok; data pages -> rows >= TOTAL_PRODUCTS). We only
switch the module's page config per page. Hits the backend only: NO WAF, NO rules.

Reads : corpus/candidates.tsv
Writes: routeA/routeA_results.tsv   (every candidate + Route-A category + status)
        routeA/backend_valid.tsv    (the survivors, with provenance) -> input to step 5
        routeA/counts.txt           (funnel per page / per family)
"""
import os
import sys

ROOT = "/path/to/GenWebSec"
os.environ.setdefault("A1_TARGET", "customapp")
os.environ.setdefault("A1_PAGE", "login")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A1_sqli_attack_only_v2 as pilot          # noqa: E402
pilot.log_print = lambda *a, **k: None                # do not touch the pilot's own logs
pilot.ensure_backend_up = lambda *a, **k: True        # backend started separately (restart_app.sh)

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results")
CORPUS = os.path.join(BASE, "corpus", "candidates.tsv")
OUT = os.path.join(BASE, "routeA")
os.makedirs(OUT, exist_ok=True)

# identical to pilot._PAGE_CFG (customapp)
PAGE_CFG = {
    "login":   ("username", "POST", {"password": "x"}),
    "search":  ("q",        "GET",  {}),
    "product": ("id",       "GET",  {}),
    "filter":  ("category", "GET",  {}),
}
PAGES = ["login", "search", "product", "filter"]
CATS = ["non_executable", "app_rejected", "sql_failed", "backend_invalid", "backend_valid"]
FAMS = ["boolean_blind", "error_based", "inline_query", "stacked_queries", "time_blind"]


def set_page(page):
    param, method, extra = PAGE_CFG[page]
    pilot.PAGE, pilot.PARAM, pilot.METHOD, pilot.EXTRA = page, param, method, extra


def route_a(payload):
    """Mirror the pilot's classify() Route-A gates using the pilot's own probe()."""
    pa = pilot.probe(pilot.BACKEND, payload)
    if not pa["reached"]:
        return "non_executable", pa
    if not pa["attempted"]:
        return "app_rejected", pa
    if pa["sql_error"]:
        return "sql_failed", pa
    if not pa["valid"]:
        return "backend_invalid", pa
    return "backend_valid", pa


def load_candidates():
    rows = []
    with open(CORPUS, encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < len(header):
                parts += [""] * (len(header) - len(parts))
            rows.append(dict(zip(header, parts)))
    return rows, header


def main():
    cands, header = load_candidates()
    out_cols = header + ["route_a_category", "backend_status", "backend_valid"]
    results = []
    cat_count = {(p, c): 0 for p in PAGES for c in CATS}
    fam_valid = {f: 0 for f in FAMS}
    page_valid = {p: 0 for p in PAGES}

    done = 0
    for page in PAGES:
        set_page(page)
        for r in cands:
            if r["page"] != page:
                continue
            cat, pa = route_a(r["final_payload"])
            r2 = dict(r)
            r2["route_a_category"] = cat
            r2["backend_status"] = pa["status"]
            r2["backend_valid"] = "1" if cat == "backend_valid" else "0"
            results.append(r2)
            cat_count[(page, cat)] += 1
            if cat == "backend_valid":
                fam_valid[r["family"]] = fam_valid.get(r["family"], 0) + 1
                page_valid[page] += 1
            done += 1
            if done % 200 == 0:
                print("  ...%d/%d tested" % (done, len(cands)), flush=True)

    # ---- write full results ----
    with open(os.path.join(OUT, "routeA_results.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(out_cols) + "\n")
        for r in results:
            f.write("\t".join(str(r.get(c, "")) for c in out_cols) + "\n")

    # ---- write backend-valid survivors (input to step 5) ----
    valids = [r for r in results if r["backend_valid"] == "1"]
    with open(os.path.join(OUT, "backend_valid.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(out_cols) + "\n")
        for r in valids:
            f.write("\t".join(str(r.get(c, "")) for c in out_cols) + "\n")

    # ---- counts ----
    L = []
    L.append("Item 8 (SQLi) -- step 4: Route A (backend :8080, no WAF)")
    L.append("backend-valid = real exploit effect (login: login_ok=1 ; data pages: rows >= %d)" % pilot.TOTAL_PRODUCTS)
    L.append("=" * 70)
    L.append("Candidates tested: %d" % len(results))
    L.append("BACKEND-VALID total: %d" % len(valids))
    L.append("")
    L.append("Per page -- Route A category breakdown:")
    hdr = "  %-8s " % "page" + " ".join("%-15s" % c for c in CATS)
    L.append(hdr)
    for p in PAGES:
        row = "  %-8s " % p + " ".join("%-15d" % cat_count[(p, c)] for c in CATS)
        L.append(row)
    L.append("")
    L.append("BACKEND-VALID per page:")
    for p in PAGES:
        L.append("  %-8s %4d" % (p, page_valid[p]))
    L.append("")
    L.append("BACKEND-VALID per technique family (all pages):")
    for fam in FAMS:
        L.append("  %-16s %4d" % (fam, fam_valid.get(fam, 0)))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[routeA] %d backend-valid -> %s" % (len(valids), os.path.join(OUT, "backend_valid.tsv")))


if __name__ == "__main__":
    main()
