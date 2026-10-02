#!/usr/bin/env python3
"""R1.1 RQ3 XSS replay (VALID + BYPASSED scope), all seeds for one (strategy, page).
Env: C2_PAGE in {calc,search}, RP_STRAT in {CG,PP}.

For each run we take the held-out (stress) attacks the log marks as backend-VALID (lines
'[stress] N. [valid ] [BYPASS|BLOCKED] <payload>') and re-check ONLY those against the custom XSS app
through the real WAF (non-executable and the CRS-blocked masses are not claimed as successes, so they do
not bear on the bypass criterion):
  * Route A (php -S backend, no WAF): re-confirm the attack still EXECUTES (JS dialog fires in a headless
    browser) -> validates the 'valid' denominator.
  * Route B status under CRS-only  -> CRS-bypass set; under CRS+frozen rules -> still-bypass (residuals).
  * Route B browser on each residual -> re-confirm it actually EXECUTES through the WAF (a real exploit,
    not merely a non-403). A residual that is not-403 but does NOT execute is a FALSE bypass.
Reproduces the logged funnel (valid / CRS-bypass / blocked-by-rules / still-bypass) from the valid set and
reports, per run, whether every counted bypass is a confirmed exploit. Resumable: (strategy,page,seed)
already in the summary are skipped.

Oracle note: the data was generated with Selenium+snap-chromium; snapd is now masked, so this replay drives
Playwright's bundled chromium (libasound.so.2 from the user's pre-staged 22.04 deps). Both are headless
Chromium with identical execution verdicts for these dialog payloads (verified on calc eval-sink + search
string-breakout exploits before running)."""
import os, sys, re, csv, time, hashlib
os.environ.setdefault("C2_PAGE", "calc")
os.environ.setdefault("C2_MODE", "clustering")
_DEPS = "/home/vahid/tools/deps/usr/lib/x86_64-linux-gnu"
os.environ["LD_LIBRARY_PATH"] = _DEPS + ":" + os.environ.get("LD_LIBRARY_PATH", "")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")

import importlib, time as _t
pilot = write_rules = run_configtest = reload_apache = None
for _att in range(10):   # transient WSL C-ext import failures -> retry
    try:
        pilot = importlib.import_module("pilot_C2_customxss_coevolution_v2")
        _mh = importlib.import_module("helpers.modsec_helpers")
        write_rules, run_configtest, reload_apache = _mh.write_rules, _mh.run_configtest, _mh.reload_apache
        break
    except (SystemError, ImportError):
        pilot = None; _t.sleep(1.0)
if pilot is None:
    raise SystemExit("pilot/helpers import failed after retries (transient WSL C-ext issue)")
pilot.log_print = lambda *a, **k: None

PAGE = os.environ["C2_PAGE"]; STRAT = os.environ.get("RP_STRAT", "CG")


class PWBrowser:
    """Playwright headless-chromium execution oracle. validate(url) -> True iff a JS dialog fires.
    Recreates itself if the page/browser crashes so a long run survives."""
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
            self._page.goto(url, wait_until="commit", timeout=6000)   # return once the response commits
        except Exception as e:
            s = str(e).lower()
            if "closed" in s or "crash" in s or "target" in s:
                self._recreate(); return self._st["f"]
        try:
            self._page.wait_for_timeout(450)       # let the injected script run and fire its dialog
        except Exception:
            pass
        fired = self._st["f"]
        try:                                       # reset: stop any alert loop + prevent bleed into next payload
            self._page.goto("about:blank", wait_until="commit", timeout=3000)
        except Exception:
            self._recreate()
        return fired
    def close(self):
        try: self._b.close()
        except Exception: pass
        try: self._pw.stop()
        except Exception: pass


PROXY = [   # carried in sft_rule.conf (vahid-writable, same IncludeOptional as 00-genwebsec-proxy.conf)
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]
def reload_with(rules):
    write_rules(PROXY + rules)
    ok, out = run_configtest()
    if not ok: print("  !! CONFIGTEST FAILED", out[:160])
    reload_apache(timeout=20)

def route_a_exec(p, browser):
    url, _ = pilot.build_url(pilot.BACKEND, p)
    return browser.validate(url)

def route_b_status(p):
    url, _ = pilot.build_url(pilot.WAF, p)
    return pilot.http_status(url)

def route_b_exec(p, browser):
    url, _ = pilot.build_url(pilot.WAF, p)
    for _try in range(3):      # retry so a browser hiccup can't fake a false-bypass
        if browser.validate(url):
            return True
    return False

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq3_xss"
os.makedirs(OUT, exist_ok=True)

def paths(seed):
    if STRAT == "CG":
        d = f"{ROOT}/results/V2/CustomApp_C2/CustomXSS_C2_Token_eps0.3_seed{seed}"
        return f"{d}/C2_customxss_{PAGE}_clustering.txt", f"{d}/C2_customxss_{PAGE}_clustering_rules.txt"
    d = f"{ROOT}/results/V2/CustomApp_C2-PP/CustomXSS_C2_Token_seed{seed}"
    return f"{d}/C2_customxss_{PAGE}_per_payload.txt", f"{d}/C2_customxss_{PAGE}_per_payload_rules.txt"

def extract_valid(path):
    """Held-out (stress) attacks the log marks backend-VALID, with the log's WAF tag (BYPASS/BLOCKED)."""
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^\s*\[stress\]\s*(\d+)\.\s*\[valid\s*\]\s*\[(BYPASS|BLOCKED)\s*\]\s(.*)$", ln.rstrip("\n"))
        if m: out.append((int(m.group(1)), m.group(2).upper(), m.group(3)))
    out.sort(); return out

def log_funnel(path):
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"\[stress\] generated (\d+)\s+valid (\d+)\s+CRS-bypass (\d+)\s+blocked-by-rules (\d+)\s+still-bypass (\d+)\s+rule-block%=([\d.]+)", ln)
        if m: return tuple(int(x) for x in m.groups()[:5]) + (float(m.group(6)),)
    return None

sumpath = f"{OUT}/rq3_xss_summary.csv"
done = set()
if os.path.exists(sumpath):
    for r in csv.DictReader(open(sumpath)):
        done.add((r["strategy"], r["page"], r["seed"]))

sumf = open(sumpath, "a", newline="", encoding="utf-8"); sw = csv.writer(sumf)
if sumf.tell() == 0:
    sw.writerow(["strategy","page","seed","n_valid_checked","n_rules","log_valid","log_crsbyp","log_blocked","log_resid","log_block%",
                 "reA_valid_confirmed","rep_crsbyp","rep_blocked","rep_resid","rep_block%","resid_exploit_confirmed","false_bypass","ver_block%","faithful_funnel"])
    sumf.flush()
paf = open(f"{OUT}/rq3_xss_perattack.csv", "a", newline="", encoding="utf-8"); pw = csv.writer(paf)
if paf.tell() == 0:
    pw.writerow(["strategy","page","seed","idx","payload_sha1","log_tag","routeA_exec","crs_status","rule_status","rule_exec"])
    paf.flush()

bk = pilot.start_backend()      # ensure the page's php -S backend is up (Route A and Route B resolve to it)
browser = PWBrowser()
print(f"=== RQ3 XSS replay (valid+bypassed)  strategy={STRAT}  page={PAGE}  (BACKEND={pilot.BACKEND}  WAF={pilot.WAF}) ===")
print(f"{'seed':>4} {'nV':>4} {'nR':>3} | {'LOG v/cb/blk/res/blk%':>26} | {'REPLAY reA/cb/blk/res/blk%':>28} | {'residX fb verBlk%':>18} | faithful  secs")
t_all = time.time()
try:
    SEEDS = [int(x) for x in os.environ.get("RP_SEEDS", "1,2,3,4,5,6,7,8,9,10").split(",")]
    for seed in SEEDS:
        if (STRAT, PAGE, str(seed)) in done:
            print(f"{seed:>4}  (already done — skip)"); continue
        logp, rulp = paths(seed)
        if not os.path.exists(logp):
            print(f"{seed:>4}  MISSING {logp}"); continue
        lf = log_funnel(logp)
        if lf is None:
            print(f"{seed:>4}  NO stress funnel — skip"); continue
        t0 = time.time()
        valid = extract_valid(logp)     # [(idx, tag, payload)]
        secrules = [l.strip() for l in open(rulp, encoding="utf-8", errors="replace") if l.strip().startswith("SecRule")] if os.path.exists(rulp) else []
        # PASS 1: CRS-only -> Route A execution (validity re-confirm) + Route B status (CRS-bypass)
        reload_with([])
        rowdata = []
        for idx, tag, p in valid:
            a = route_a_exec(p, browser)
            cs = route_b_status(p)
            rowdata.append({"idx": idx, "tag": tag, "p": p, "a": a, "cs": cs})
        # PASS 2: CRS+frozen rules -> Route B status (still-bypass) + Route B execution on residuals
        reload_with(secrules)
        for r in rowdata:
            st = route_b_status(r["p"]); r["rs"] = st
            r["re"] = (route_b_exec(r["p"], browser) if st != 403 else None)
        # per-attack rows
        for r in rowdata:
            pw.writerow([STRAT, PAGE, seed, r["idx"], hashlib.sha1(r["p"].encode("utf-8","replace")).hexdigest()[:16],
                         r["tag"], int(r["a"]), r["cs"], r["rs"], ("" if r["re"] is None else int(r["re"]))])
        paf.flush()
        reA_conf = sum(1 for r in rowdata if r["a"])
        crsbyp = [r for r in rowdata if r["cs"] != 403]
        still = [r for r in rowdata if r["rs"] != 403]
        blocked = len(crsbyp) - len(still)
        block_rep = 100.0*blocked/len(crsbyp) if crsbyp else 0.0
        resid_exploit = sum(1 for r in still if r["re"])
        false_byp = sum(1 for r in still if not r["re"])
        block_ver = 100.0*(len(crsbyp)-resid_exploit)/len(crsbyp) if crsbyp else 0.0
        faithful = (len(crsbyp)==lf[2] and blocked==lf[3] and len(still)==lf[4])
        secs = time.time()-t0
        sw.writerow([STRAT,PAGE,seed,len(valid),len(secrules),lf[1],lf[2],lf[3],lf[4],lf[5],
                     reA_conf,len(crsbyp),blocked,len(still),round(block_rep,1),resid_exploit,false_byp,round(block_ver,1),int(faithful)])
        sumf.flush()
        print(f"{seed:>4} {len(valid):>4} {len(secrules):>3} | {lf[1]:>4}/{lf[2]:>3}/{lf[3]:>3}/{lf[4]:>3}/{lf[5]:>5} | "
              f"{reA_conf:>4}/{len(crsbyp):>3}/{blocked:>3}/{len(still):>3}/{block_rep:>5.1f} | {resid_exploit:>3} {false_byp:>2} {block_ver:>5.1f} | {'OK' if faithful else 'MISMATCH'} {secs:>5.0f}")
finally:
    browser.close()
    sumf.close(); paf.close()
    reload_with([])     # leave CRS-only + proxy loaded
    if bk is not None:
        try: bk.terminate()
        except Exception: pass
print(f"done {STRAT}/{PAGE} in {time.time()-t_all:.0f}s")
