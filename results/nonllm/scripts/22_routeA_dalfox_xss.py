# REDACTED PUBLIC COPY. Concrete injection-breakout templates / smoke-test
# payloads have been replaced with a [redacted for safety] marker; the
# instantiation logic and comments are intact. See ../README.md.

#!/usr/bin/env python3
"""
Item 8 (XSS) Dalfox track -- Route A: browser-execution validity on the WAF-free backend.

Reuses pilot_A2_customxss_attack_only_v2's Browser (Selenium+chromium), build_url and
http_status VERBATIM. Route A only: a payload is BACKEND-VALID iff the page loads (HTTP 200)
AND a JS dialog fires in the browser. One throwaway `php -S` over customxss/ serves both pages.

Starts with a SMOKE TEST (validate the known seed) so browser breakage is caught immediately.
Relaunches the browser every RELAUNCH_EVERY payloads to dodge the WSL chromium wedge.

Reads : xss_dalfox/corpus/candidates.tsv
Writes: xss_dalfox/routeA/routeA_results.tsv, backend_valid.tsv, counts.txt
"""
import os
import sys
import time
import subprocess

ROOT = "/path/to/GenWebSec"
os.environ.setdefault("CXSS_PAGE", "search")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))

import pilot_A2_customxss_attack_only_v2 as pilot          # noqa: E402
pilot.log_print = lambda *a, **k: None

BASE = os.path.join(ROOT, "results/V2/NonLLM_Results/xss_dalfox")
CORPUS = os.path.join(BASE, "corpus", "candidates.tsv")
OUT = os.path.join(BASE, "routeA")
os.makedirs(OUT, exist_ok=True)

DOCROOT = os.path.join(ROOT, "customxss")
BACKEND_PORT = 8094
BACKEND = "http://127.0.0.1:%d" % BACKEND_PORT
PAGE_CFG = {"search": ("search.php", "q"), "calc": ("calc.php", "expr")}
# chromium needs periodic relaunch to dodge the WSL wedge; firefox is stable and relaunching
# it causes a zombie-renderer teardown hang -> never relaunch firefox.
RELAUNCH_EVERY = 40 if pilot.BROWSER == "chrome" else 0


def start_php():
    if pilot.http_status("%s/search.php?q=2" % BACKEND) == 200:
        return None
    try:
        subprocess.run(["pkill", "-f", "php -S 127.0.0.1:%d" % BACKEND_PORT], capture_output=True, timeout=5)
    except Exception:
        pass
    time.sleep(0.5)
    proc = subprocess.Popen(["php", "-S", "127.0.0.1:%d" % BACKEND_PORT, "-t", DOCROOT],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        if pilot.http_status("%s/search.php?q=2" % BACKEND) == 200:
            return proc
        time.sleep(0.3)
    return proc


def set_page(page):
    page_file, param = PAGE_CFG[page]
    pilot.PAGE, pilot.PAGE_FILE, pilot.PARAM = page, page_file, param
    pilot.BACKEND, pilot.BACKEND_PORT = BACKEND, BACKEND_PORT


def route_a(page, payload, browser):
    set_page(page)
    url, _ = pilot.build_url(BACKEND, payload)
    st = pilot.http_status(url)
    if st != 200:
        return "not_reached", st, False
    executed = browser.validate(url)
    if not executed:
        return "reached_no_exec", st, False
    return "backend_valid", st, True


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
    proc = start_php()
    if pilot.http_status("%s/calc.php?expr=2" % BACKEND) != 200:
        print("[fatal] php -S backend not serving customxss on %s" % BACKEND)
        return
    print("[backend] php -S up on %s" % BACKEND, flush=True)

    browser = pilot.Browser()
    print("[browser] launched", flush=True)

    # ---- SMOKE TEST: the known-good seed must fire a dialog ----
    set_page("calc")
    smoke_url, _ = pilot.build_url(BACKEND, "[smoke-test payload redacted]")
    if not browser.validate(smoke_url):
        print("[SMOKE FAIL] seed [redacted] did not fire on calc -> browser oracle broken; aborting.")
        browser.close()
        return
    print("[SMOKE OK] seed [redacted] fired on calc; proceeding.", flush=True)

    cands, header = load(CORPUS)
    out_cols = header + ["reached", "executed", "route_a_category", "backend_valid"]
    results = []
    done = 0
    for page in ("search", "calc"):
        for r in cands:
            if r["page"] != page:
                continue
            cat, st, valid = route_a(page, r["final_payload"], browser)
            r2 = dict(r)
            r2["reached"] = "1" if st == 200 else "0"
            r2["executed"] = "1" if valid else "0"
            r2["route_a_category"] = cat
            r2["backend_valid"] = "1" if valid else "0"
            results.append(r2)
            done += 1
            if RELAUNCH_EVERY and done % RELAUNCH_EVERY == 0:
                browser.close()
                browser = pilot.Browser()
                print("  ...%d/%d (browser relaunched; valid so far: %d)"
                      % (done, len(cands), sum(1 for x in results if x["backend_valid"] == "1")), flush=True)
            elif done % 20 == 0:
                print("  ...%d/%d (valid so far: %d)"
                      % (done, len(cands), sum(1 for x in results if x["backend_valid"] == "1")), flush=True)
    browser.close()

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
    L.append("Item 8 (XSS) Dalfox -- Route A (php -S backend, no WAF; browser-execution validity)")
    L.append("=" * 72)
    L.append("Candidates tested: %d" % len(results))
    L.append("BACKEND-VALID total (dialog fired): %d" % len(valids))
    L.append("")
    for page in ("search", "calc"):
        v = [r for r in results if r["page"] == page]
        nv = sum(1 for r in v if r["backend_valid"] == "1")
        nr = sum(1 for r in v if r["reached"] == "1")
        L.append("  %-7s  tested=%3d  reached=%3d  backend-valid=%3d" % (page, len(v), nr, nv))
    L.append("")
    L.append("BACKEND-VALID per variant:")
    for var in ("search_escaped", "search_plain", "calc_direct"):
        v = [r for r in results if r.get("variant") == var]
        nv = sum(1 for r in v if r["backend_valid"] == "1")
        L.append("  %-16s %3d / %3d" % (var, nv, len(v)))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[dalfox-routeA] %d backend-valid -> %s" % (len(valids), os.path.join(OUT, "backend_valid.tsv")))


if __name__ == "__main__":
    main()
