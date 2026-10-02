#!/usr/bin/env python3
"""R1.1 RQ4 two-stage re-verification (residual bypasses, eps0.3) for XSS customxss, one page per process.
Env: C2_PAGE in {calc,search}.

Takes the residual bypasses under CG-Adaptive (C2) / CG-Static (D2) at eps0.3 (blocked==0) from the
existing A2_HeldOut per-attack CSVs, reloads each ruleset, and re-probes those winners through the WAF:
status 403 = blocked, else the exploit is re-confirmed by JS execution in a headless browser (Playwright).
A residual that is not-403 but does NOT execute through the WAF is a FALSE bypass.
Resumable: (page,technique,cg_seed) already summarized are skipped."""
import os, sys, re, csv, glob, hashlib
from collections import defaultdict
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
EPS = "0.3"
XSS_PAGES = ["search", "calc"]
SECRULE = re.compile(r"^\s*SecRule\b"); IDPAT = re.compile(r"id:\d+")


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

PROXY = [
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]
def reload_with(rules):
    write_rules(PROXY + rules); ok, out = run_configtest()
    if not ok: print("  !! CONFIGTEST FAIL", out[:120])
    reload_apache(timeout=30)

def rule_files(tech, seed):
    if tech == "CG-Adaptive":
        base = f"{ROOT}/results/V2/CustomApp_C2/CustomXSS_C2_Token_eps{EPS}_seed{seed}"
        return [f"{base}/C2_customxss_{p}_clustering_rules.txt" for p in XSS_PAGES]
    base = f"{ROOT}/results/V2/CustomApp_D2/CustomXSS_D2_eps{EPS}_seed{seed}"
    return [f"{base}/D2_customxss_{p}_clustering_rules.txt" for p in XSS_PAGES]

def build_ruleset(tech, seed):
    raw = []
    for fp in rule_files(tech, seed):
        if os.path.exists(fp):
            for line in open(fp, encoding="utf-8", errors="replace"):
                if SECRULE.match(line): raw.append(line.strip())
    out, nid = [], 1000001
    for r in raw:
        out.append(IDPAT.sub(f"id:{nid}", r, count=1)); nid += 1
    return out

def route_b_exec(p, browser):
    url, _ = pilot.build_url(pilot.WAF, p)
    for _try in range(3):
        if browser.validate(url): return True
    return False

GLOB = f"{ROOT}/results/V2/A2_HeldOut/A2_customxss_heldout_seed*/Defense_results/rq4_replay_customxss_{PAGE}_seed*_perattack.csv"
files = [f for f in glob.glob(GLOB) if "/eps0." not in f]
byp = defaultdict(list)
for f in files:
    ma = re.search(r"_seed(\d+)_perattack", f); aseed = ma.group(1) if ma else "?"
    with open(f, encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            if row["technique"] in ("CG-Adaptive", "CG-Static") and row["blocked"] == "0":
                byp[(row["technique"], row["cg_seed"])].append((aseed, row["attack_idx"], row["payload"]))
print(f"[customxss/{PAGE}] residual-bypass groups: {len(byp)}  total: {sum(len(v) for v in byp.values())}", flush=True)

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq4"
os.makedirs(OUT, exist_ok=True)
sumpath = f"{OUT}/rq4_xss_summary.csv"
done = set()
if os.path.exists(sumpath):
    for r in csv.DictReader(open(sumpath)):
        done.add((r["target"], r["page"], r["technique"], r["cg_seed"]))
sumf = open(sumpath, "a", newline="", encoding="utf-8"); sw = csv.writer(sumf)
if sumf.tell() == 0:
    sw.writerow(["target","page","technique","cg_seed","reported_bypasses","reprobe_not403","verified_exploit","false_bypass","now_403"]); sumf.flush()
detf = open(f"{OUT}/rq4_xss_false_bypasses.csv", "a", newline="", encoding="utf-8"); dw = csv.writer(detf)
if detf.tell() == 0:
    dw.writerow(["target","page","technique","cg_seed","attack_seed","attack_idx","payload_sha1","waf_status","reason"]); detf.flush()
prf = open(f"{OUT}/rq4_xss_perrequest.csv", "a", newline="", encoding="utf-8"); pw = csv.writer(prf)
if prf.tell() == 0:
    pw.writerow(["target","page","technique","cg_seed","attack_seed","attack_idx","payload_sha1","waf_status","exploit_through_waf"]); prf.flush()

pilot.start_backend()
browser = PWBrowser()
print(f"=== RQ4 XSS re-verify  target=customxss page={PAGE}  WAF={pilot.WAF} ===", flush=True)
try:
    for (tech, cg_seed) in sorted(byp):
        if ("customxss", PAGE, tech, cg_seed) in done:
            print(f"  {tech} seed{cg_seed}: (done, skip)"); continue
        rules = build_ruleset(tech, cg_seed)
        if not rules:
            print(f"  {tech} seed{cg_seed}: NO RULES (path?) — skip"); continue
        reload_with(rules)
        winners = byp[(tech, cg_seed)]
        not403 = exploit = false_b = now403 = 0
        for aseed, idx, p in winners:
            st = pilot.http_status(pilot.build_url(pilot.WAF, p)[0])
            h = hashlib.sha1(p.encode("utf-8","replace")).hexdigest()[:16]
            if st == 403:
                now403 += 1
                pw.writerow(["customxss", PAGE, tech, cg_seed, aseed, idx, h, st, ""])
                continue
            not403 += 1
            ex = 1 if route_b_exec(p, browser) else 0
            pw.writerow(["customxss", PAGE, tech, cg_seed, aseed, idx, h, st, ex])
            if ex:
                exploit += 1
            else:
                false_b += 1
                dw.writerow(["customxss", PAGE, tech, cg_seed, aseed, idx, h, st, "not403_no_exec"]); detf.flush()
        prf.flush()
        sw.writerow(["customxss", PAGE, tech, cg_seed, len(winners), not403, exploit, false_b, now403]); sumf.flush()
        print(f"  {tech} seed{cg_seed}: reported={len(winners):>4} not403={not403:>4} exploit={exploit:>4} false={false_b:>3} now403={now403:>3}", flush=True)
finally:
    browser.close(); sumf.close(); detf.close(); prf.close()
    reload_with([])
print(f"done customxss/{PAGE}", flush=True)
