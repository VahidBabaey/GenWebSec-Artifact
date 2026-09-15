#!/usr/bin/env python3
"""
Item 8 (SQLi) CSIC/Torpeda track -- Route A validity on the WAF-free backend (:8080).

Same funnel as the sqlmap track: reuses pilot_A1.probe() + per-page oracle VERBATIM,
switching the page config per page. Backend only (no WAF, no rules). Long run (~63k).

Reads : csic/corpus/candidates.tsv
Writes: csic/routeA/routeA_results.tsv, csic/routeA/backend_valid.tsv, csic/routeA/counts.txt
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
pilot.HTTP_TIMEOUT = 5.0                               # shorter timeout: fail fast, avoid thread pile-up

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results")
CORPUS = os.path.join(BASE, "csic", "corpus", "candidates.tsv")
OUT = os.path.join(BASE, "csic", "routeA")
os.makedirs(OUT, exist_ok=True)

PAGE_CFG = {
    "login":   ("username", "POST", {"password": "x"}),
    "search":  ("q",        "GET",  {}),
    "product": ("id",       "GET",  {}),
    "filter":  ("category", "GET",  {}),
}
PAGES = ["login", "search", "product", "filter"]
CATS = ["non_executable", "app_rejected", "sql_failed", "backend_invalid", "backend_valid"]
TAGS = ["or_tautology", "and_based", "union", "error", "time", "stacked", "other"]


def set_page(page):
    param, method, extra = PAGE_CFG[page]
    pilot.PAGE, pilot.PARAM, pilot.METHOD, pilot.EXTRA = page, param, method, extra


def tech_tag(p):
    low = p.lower()
    if any(t in low for t in ("sleep", "benchmark", "waitfor", "dbms_pipe", "randomblob")):
        return "time"
    if "union" in low:
        return "union"
    if any(t in low for t in ("concat", "char(", "cast(")):
        return "error"
    if ";" in low and any(t in low for t in ("select", "drop", "create", "insert", "update")):
        return "stacked"
    if " or " in low:
        return "or_tautology"
    if " and " in low:
        return "and_based"
    return "other"


def route_a(payload):
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
    cands, header = load(CORPUS)
    # Exclude time-based payloads (SLEEP/WAITFOR/BENCHMARK/DBMS_PIPE/RANDOMBLOB): time-based BLIND
    # injection cannot satisfy this oracle (it neither dumps rows nor bypasses auth), and the
    # SQLite RANDOMBLOB forms allocate gigabytes and exhaust the backend. Documented exclusion.
    kept = [r for r in cands if tech_tag(r["final_payload"]) != "time"]
    excluded_time = len(cands) - len(kept)
    total = len(kept)
    print("[csic-routeA] %d loaded; excluded %d time-based (cannot satisfy oracle / DoS backend); testing %d"
          % (len(cands), excluded_time, total), flush=True)
    out_cols = header + ["tech_tag", "route_a_category", "backend_status", "backend_valid"]

    results = []
    cat_count = {(p, c): 0 for p in PAGES for c in CATS}
    valid_by_tag = {t: 0 for t in TAGS}
    valid_by_page = {p: 0 for p in PAGES}

    done = 0
    for page in PAGES:
        set_page(page)
        for r in kept:
            if r["page"] != page:
                continue
            cat, pa = route_a(r["final_payload"])
            tag = tech_tag(r["final_payload"])
            r2 = dict(r)
            r2["tech_tag"] = tag
            r2["route_a_category"] = cat
            r2["backend_status"] = pa["status"]
            r2["backend_valid"] = "1" if cat == "backend_valid" else "0"
            results.append(r2)
            cat_count[(page, cat)] += 1
            if cat == "backend_valid":
                valid_by_tag[tag] = valid_by_tag.get(tag, 0) + 1
                valid_by_page[page] += 1
            done += 1
            if done % 2000 == 0:
                print("  ...%d/%d  (valid so far: %d)"
                      % (done, total, sum(valid_by_page.values())), flush=True)

    with open(os.path.join(OUT, "routeA_results.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(out_cols) + "\n")
        for r in results:
            f.write("\t".join(str(r.get(c, "")) for c in out_cols) + "\n")

    valids = [r for r in results if r["backend_valid"] == "1"]
    with open(os.path.join(OUT, "backend_valid.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(out_cols) + "\n")
        for r in valids:
            f.write("\t".join(str(r.get(c, "")) for c in out_cols) + "\n")

    L = []
    L.append("Item 8 (SQLi) CSIC/Torpeda -- Route A (backend :8080, no WAF)")
    L.append("=" * 66)
    L.append("Time-based excluded (RANDOMBLOB/SLEEP/WAITFOR/BENCHMARK/DBMS_PIPE): %d" % excluded_time)
    L.append("Candidates tested: %d" % len(results))
    L.append("BACKEND-VALID total: %d" % len(valids))
    L.append("")
    L.append("Per page -- Route A category breakdown:")
    L.append("  %-8s " % "page" + " ".join("%-15s" % c for c in CATS))
    for p in PAGES:
        L.append("  %-8s " % p + " ".join("%-15d" % cat_count[(p, c)] for c in CATS))
    L.append("")
    L.append("BACKEND-VALID per page:")
    for p in PAGES:
        L.append("  %-8s %5d" % (p, valid_by_page[p]))
    L.append("")
    L.append("BACKEND-VALID per coarse technique tag:")
    for t in TAGS:
        L.append("  %-14s %5d" % (t, valid_by_tag.get(t, 0)))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[csic-routeA] %d backend-valid -> %s" % (len(valids), os.path.join(OUT, "backend_valid.tsv")))


if __name__ == "__main__":
    main()
