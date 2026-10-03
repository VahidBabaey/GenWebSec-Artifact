#!/usr/bin/env python3
"""Attack agent vs OWASP CRS 4.29.0 (XSS), driven by the NEW *_crs429 PROMPT MODULES.

Reuses WorkFlowV2/pilot_A2_customxss_attack_only_heldout's funnel (classify/generate_payloads), but:
  - rebinds pilot.build_attack_messages to the NEW CRS-4.29 XSS prompt module (seed + methods baked
    into the prompt, NOT injected at runtime);
  - points Route B (WAF) at the CRS 4.29.0 container via a `localhost:<port>` URL (so the browser's
    Host header is NOT a numeric IP -> no CRS 920350 artifact);
  - replaces the broken snap-chromium/selenium oracle with a Playwright oracle (the system chromium is
    a snap shim and snapd is down; playwright's bundled chromium works once libasound.so.2 is exposed
    via LD_LIBRARY_PATH from the no-sudo ~/chromedeps extraction);
  - round 0 uses the prompt's embedded 4.29 seed; later rounds evolve from confirmed winners.

Three-step check per candidate (pilot.classify):
  (1) validation      : backend_valid        (JS dialog FIRES in a real browser, Route A)
  (2) WAF bypass      : waf_bypassed          (non-403 through CRS 4.29.0, Route B)
  (3) false-bypass chk: valid_through_waf True (JS dialog RE-CONFIRMED on the CRS-4.29 response)

Env: TGT (customxss|bwapp), ROUNDS (default 5), A2_MODEL (default openai/gpt-4.1-mini)."""
import os, sys, csv, time, importlib

# ---- expose libasound.so.2 (no-sudo) so playwright chromium can launch ----
_LIBDIR = os.path.expanduser("~/chromedeps/usr/lib/x86_64-linux-gnu")
os.environ["LD_LIBRARY_PATH"] = _LIBDIR + ":" + os.environ.get("LD_LIBRARY_PATH", "")

TGT = os.environ.get("TGT", "customxss")
ROUNDS = int(os.environ.get("ROUNDS", "5"))
os.environ.setdefault("A2_MODEL", "openai/gpt-4.1-mini")
if TGT == "customxss":
    os.environ["A2_TARGET"] = "customxss"; os.environ["CXSS_PAGE"] = "calc"
    os.environ["CXSS_BACKEND_PORT"] = "8096"          # crs-xss:8086 proxies to 127.0.0.1:8096
    PAGE = "calc"; PROMPT_MOD = "prompts.xss_customapp_attack_prompts_crs429"
    WAF_BASE = "http://localhost:8086"
elif TGT == "bwapp":
    os.environ["A2_TARGET"] = "bwapp"; os.environ["A2_PAGE"] = "xss_eval"
    PAGE = "xss_eval"; PROMPT_MOD = "prompts.xss_bwapp_attack_prompts_crs429"
    WAF_BASE = "http://localhost:8090"
else:
    raise SystemExit("TGT must be customxss|bwapp")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")

pilot = None
for _ in range(10):
    try:
        pilot = importlib.import_module("pilot_A2_customxss_attack_only_heldout"); break
    except (SystemError, ImportError):
        time.sleep(1)
if pilot is None:
    raise SystemExit("pilot import failed")
pilot.log_print = lambda *a, **k: None

# ---- rebind attack prompt to the NEW 4.29 module ("change prompts" step) ----
newmod = importlib.import_module(PROMPT_MOD)
pilot.build_attack_messages = newmod.build_attack_messages
pilot.DEFAULT_SEEDS = newmod.DEFAULT_SEEDS
EMBEDDED_SEED = newmod.DEFAULT_SEEDS[PAGE]
print(f"[prompt] attack agent now uses {PROMPT_MOD} (embedded 4.29 seed: {EMBEDDED_SEED!r})", flush=True)

# ---- point Route B (WAF) at CRS 4.29.0 container ----
pilot.WAF = WAF_BASE
pilot.write_rules = lambda *a, **k: None
pilot.run_configtest = lambda *a, **k: (True, "")
pilot.reload_apache = lambda *a, **k: (True, "")

NEEDS_SESSION = bool(getattr(pilot, "NEEDS_SESSION", False))

# ---- Playwright oracle (same interface classify expects: validate/login_bwapp/_recreate/close) ----
from playwright.sync_api import sync_playwright

class PWBrowser:
    def __init__(self, need_session=False):
        self.need_session = need_session
        self._pw = sync_playwright().start()
        self._launch()

    def _launch(self):
        self._b = self._pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        self._ctx = self._b.new_context()
        self._page = self._ctx.new_page()
        self._fired = 0
        self._page.on("dialog", self._on_dialog)

    def _on_dialog(self, d):
        self._fired += 1
        try:
            d.dismiss()
        except Exception:
            pass

    def validate(self, url) -> bool:
        self._fired = 0
        try:
            self._page.goto(url, wait_until="load", timeout=15000)
        except Exception:
            pass                       # a dialog mid-navigation can raise; handler still counted it
        try:
            self._page.wait_for_timeout(350)
        except Exception:
            pass
        return self._fired > 0

    def login_bwapp(self) -> bool:
        try:
            self._page.goto(f"{pilot.BACKEND}/login.php", timeout=15000)
            self._page.fill("input[name=login]", pilot.BWAPP_USER)
            self._page.fill("input[name=password]", pilot.BWAPP_PASS)
            try:
                self._page.select_option("select[name=security_level]", pilot.BWAPP_SECURITY)
            except Exception:
                pass
            try:
                self._page.click("button[name=form]", timeout=4000)
            except Exception:
                self._page.click("input[name=form]", timeout=4000)
            self._page.wait_for_timeout(500)
            src = self._page.content().lower()
            return ("logout" in src) or ("portal" in self._page.url)
        except Exception as e:
            print("  [browser] login error:", str(e)[:120], flush=True)
            return False

    def _recreate(self):
        for fn in (lambda: self._ctx.close(), lambda: self._b.close()):
            try:
                fn()
            except Exception:
                pass
        self._launch()
        if self.need_session:
            self.login_bwapp()

    def close(self):
        for fn in (lambda: self._b.close(), lambda: self._pw.stop()):
            try:
                fn()
            except Exception:
                pass

# ---- bring up backend + session ----
backend_proc = None
if getattr(pilot, "NEEDS_PHP_BACKEND", False):
    backend_proc = pilot.start_backend()
    url = f"{pilot.BACKEND}/{pilot.PAGE_FILE}?{pilot.PARAM}=2"
    if pilot.http_status(url) != 200:
        raise SystemExit(f"[fatal] customxss php backend not up at {pilot.BACKEND}")
    print(f"[backend] php -S up at {pilot.BACKEND}", flush=True)
if NEEDS_SESSION:
    pilot.establish_session()

browser = PWBrowser(need_session=NEEDS_SESSION)
if NEEDS_SESSION:
    if not browser.login_bwapp() or not pilot.session_ok():
        browser.close(); raise SystemExit("[fatal] bWAPP session not established")
    print("[session] bWAPP authenticated (urllib + browser)", flush=True)
print("[browser] playwright chromium ready", flush=True)

# ---- sanity: canonical XSS BLOCKED by CRS 4.29; embedded seed valid+bypass+through ----
canon = "<script>alert(1)</script>"
cu, _ = pilot.build_url(pilot.WAF, canon)
print(f"[sanity] canonical {canon!r}: waf_status={pilot.http_status(cu)} (expect 403)", flush=True)
sr = pilot.classify(EMBEDDED_SEED, 0, browser)
print(f"[sanity] embedded seed: reached={sr['reached']} executed(backend_valid)={sr['backend_valid']} "
      f"waf_status={sr['waf_status']} waf_bypassed={sr['waf_bypassed']} valid_through_waf={sr.get('valid_through_waf')} "
      f"(expect valid+bypass+through)", flush=True)

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/crs429_attack_newprompts"
os.makedirs(OUT, exist_ok=True)
tag = f"{TGT}_{PAGE}"
rows, confirmed_all, cur_seeds = [], set(), None
examples = []
try:
    for rnd in range(ROUNDS):
        browser._recreate()
        if NEEDS_SESSION:
            pilot.establish_session()        # keep urllib session fresh too
        payloads = pilot.generate_payloads(rnd, cur_seeds)
        nval = nwaf = nfalse = nconf = 0; winners, fresh = [], []
        for p in payloads:
            rec = pilot.classify(p, rnd, browser)
            if not rec["backend_valid"]:
                continue
            nval += 1                                  # step 1: validation
            if not rec["waf_bypassed"]:
                continue
            nwaf += 1                                   # step 2: WAF bypass (non-403)
            if rec.get("valid_through_waf") is True:     # step 3: false-bypass re-check
                nconf += 1; winners.append(p)
                if p not in confirmed_all:
                    fresh.append(p); confirmed_all.add(p)
                    if len(examples) < 8:
                        examples.append(p)
            else:
                nfalse += 1
        rows.append((rnd, len(payloads), nval, nwaf, nfalse, nconf, len(fresh), len(confirmed_all)))
        print(f"round {rnd}: generated={len(payloads)} validated={nval} waf_bypass_non403={nwaf} "
              f"false_bypass={nfalse} CONFIRMED(3-step)={nconf} new_distinct={len(fresh)} "
              f"cumulative_distinct={len(confirmed_all)}", flush=True)
        cur_seeds = winners if winners else cur_seeds
finally:
    browser.close()
    if backend_proc is not None:
        try:
            backend_proc.terminate()
        except Exception:
            pass

with open(f"{OUT}/{tag}_rounds.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["round", "generated", "validated_step1", "waf_bypass_non403_step2",
                "false_bypass", "confirmed_3step", "new_distinct", "cumulative_distinct_confirmed"])
    for r in rows:
        w.writerow(r)
with open(f"{OUT}/{tag}_confirmed_bypasses_PRIVATE.txt", "w", encoding="utf-8") as f:
    f.write(f"# {TGT}/{PAGE} - distinct attacks CONFIRMED (3-step) to bypass OWASP CRS 4.29.0,\n")
    f.write(f"# generated live by the attack agent using prompt module {PROMPT_MOD}\n")
    f.write(f"# total distinct confirmed: {len(confirmed_all)}\n\n")
    for p in sorted(confirmed_all):
        f.write(p + "\n")
print(f"\n[{tag}] TOTAL distinct 3-step-confirmed NEW CRS-4.29 bypasses: {len(confirmed_all)}", flush=True)
print(f"[{tag}] examples: " + " | ".join(repr(e) for e in examples[:5]), flush=True)
print(f"[{tag}] wrote {OUT}/{tag}_rounds.csv", flush=True)
