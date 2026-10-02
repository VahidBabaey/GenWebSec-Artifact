#!/usr/bin/env python3
"""R1.1 RQ1 app re-replay (XSS), one page per process. Env: C2_PAGE in {calc,search}.
Re-sends every RQ1 XSS winner (backend-valid + CRS-bypassing, from CustomXSS_A2_CRSonly_seed{1..5})
through the LIVE custom XSS app + CRS-only WAF: Route A browser-exec re-confirms the attack executes on
the backend; Route B status (CRS-only) + Route B browser-exec re-confirms the non-403 bypass is a genuine
exploit through the WAF (valid_through_waf). Independent app replay, replacing the stored generation field."""
import os, sys, re, csv, hashlib
os.environ.setdefault("C2_PAGE", "calc")
os.environ.setdefault("C2_MODE", "clustering")
_DEPS = "/home/vahid/tools/deps/usr/lib/x86_64-linux-gnu"
os.environ["LD_LIBRARY_PATH"] = _DEPS + ":" + os.environ.get("LD_LIBRARY_PATH", "")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import importlib, time as _t
pilot = mh = None
for _ in range(10):
    try:
        pilot = importlib.import_module("pilot_C2_customxss_coevolution_v2")
        mh = importlib.import_module("helpers.modsec_helpers"); break
    except (SystemError, ImportError):
        pilot = None; _t.sleep(1)
if pilot is None:
    raise SystemExit("pilot import failed")
pilot.log_print = lambda *a, **k: None
write_rules, run_configtest, reload_apache = mh.write_rules, mh.run_configtest, mh.reload_apache
PAGE = os.environ["C2_PAGE"]
PROXY = [
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]


class PWBrowser:
    def __init__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start(); self._launch()
    def _launch(self):
        self._b = self._pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        self._page = self._b.new_page(); self._st = {"f": False}
        self._page.on("dialog", self._on)
    def _on(self, d):
        self._st["f"] = True
        try: d.dismiss()
        except Exception: pass
    def _recreate(self):
        try: self._b.close()
        except Exception: pass
        self._launch()
    def validate(self, url):
        self._st["f"] = False
        try:
            self._page.goto(url, wait_until="commit", timeout=6000)
        except Exception as e:
            s = str(e).lower()
            if "closed" in s or "crash" in s or "target" in s:
                self._recreate(); return self._st["f"]
        try: self._page.wait_for_timeout(450)
        except Exception: pass
        fired = self._st["f"]
        try: self._page.goto("about:blank", wait_until="commit", timeout=3000)
        except Exception: self._recreate()
        return fired
    def close(self):
        try: self._b.close()
        except Exception: pass
        try: self._pw.stop()
        except Exception: pass

def reload_crs_only():
    write_rules(PROXY); ok, out = run_configtest()
    if not ok: print("  CONFIGTEST FAIL", out[:120])
    reload_apache(timeout=20)

def route_b_exec(p, browser):
    url, _ = pilot.build_url(pilot.WAF, p)
    for _ in range(3):
        if browser.validate(url): return True
    return False

def winners(seed):
    f = f"{ROOT}/results/V2/CustomApp_A2/CustomXSS_A2_CRSonly_seed{seed}/A2_customxss_{PAGE}_winners.txt"
    if not os.path.exists(f): return []
    return [l.rstrip("\n") for l in open(f, encoding="utf-8", errors="replace") if l.strip() and not l.startswith("#")]

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq1_replay"
os.makedirs(OUT, exist_ok=True)
sumpath = f"{OUT}/rq1_xss_replay_summary.csv"
done = set()
if os.path.exists(sumpath):
    for r in csv.DictReader(open(sumpath)): done.add((r["page"], r["seed"]))
sumf = open(sumpath, "a", newline="", encoding="utf-8"); sw = csv.writer(sumf)
if sumf.tell() == 0:
    sw.writerow(["page","seed","n_winners","backend_exec_confirmed","bypass_not403","exploit_through_waf","false_bypass"]); sumf.flush()
detf = open(f"{OUT}/rq1_xss_replay_false.csv", "a", newline="", encoding="utf-8"); dw = csv.writer(detf)
if detf.tell() == 0:
    dw.writerow(["page","seed","payload_sha1","backend_exec","waf_status","reason"]); detf.flush()

pilot.start_backend()
browser = PWBrowser()
reload_crs_only()
print(f"=== RQ1 XSS app re-replay  page={PAGE}  (CRS-only)  WAF={pilot.WAF} ===")
try:
    for seed in range(1, 6):
        if (PAGE, str(seed)) in done:
            print(f"  seed{seed}: (done, skip)"); continue
        ws = winners(seed)
        if not ws:
            print(f"  seed{seed}: no winners"); continue
        be = byp = exp = false_b = 0
        for p in ws:
            a = browser.validate(pilot.build_url(pilot.BACKEND, p)[0])
            if a: be += 1
            st = pilot.http_status(pilot.build_url(pilot.WAF, p)[0])
            if st != 403:
                byp += 1
                if route_b_exec(p, browser):
                    exp += 1
                else:
                    false_b += 1
                    dw.writerow([PAGE, seed, hashlib.sha1(p.encode("utf-8","replace")).hexdigest()[:16], int(a), st, "not403_no_exec"]); detf.flush()
        sw.writerow([PAGE, seed, len(ws), be, byp, exp, false_b]); sumf.flush()
        print(f"  seed{seed}: winners={len(ws):>4} backend_exec={be:>4} bypass={byp:>4} exploit_through_waf={exp:>4} false={false_b:>2}")
finally:
    browser.close(); sumf.close(); detf.close()
    reload_crs_only()
print(f"done XSS/{PAGE}")
