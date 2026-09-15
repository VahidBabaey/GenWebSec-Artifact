#!/usr/bin/env python3
"""
generate_backend_benign.py
==========================
Generate VALID BENIGN FP corpora for specific Juice Shop / bWAPP backend pages.

For a given (type, site, page) it produces `count` benign samples. EVERY saved sample satisfies
BOTH non-negotiable principles:

  (1) VALID  -- the request works legitimately on the backend. The SAME request is first sent
      DIRECTLY to the backend (Route A, no WAF) and kept only if the app processes it as a NORMAL,
      non-malicious request:
        * login  : a normal login response (the app's standard "invalid credentials" or accepted
                   response), NOT a server / SQL error and NOT an injection success;
        * search : a normal search response (valid JSON / the results page), NO SQL error, NOT an
                   exploit table-dump;
        * calc   : the value is sound arithmetic that evaluates to a finite number (and, with
                   --browser, is confirmed to fire NO JavaScript dialog in a real browser).
  (2) NOT BLOCKED BY THE BASELINE CRS -- the SAME request is then sent through the WAF proxy
      (Route B) and kept only if it is NOT blocked (HTTP status != 403; 403-only, exactly as the
      pipeline decides "blocked").

Only samples passing (1) AND (2) are written. Request/session/oracle logic mirrors, exactly, the
pipeline scripts pilot_A1_juice_attack_only.py, pilot_A1_bwapp_attack_only.py and
pilot_A2_bwapp_attack_only.py, and the existing generator customapp/generate_benign.py.

RUN THIS WITH THE BASELINE CRS LOADED (no learned / custom rules). The corpus is then "legitimate
traffic the baseline allows"; a later FP step loads the learned/transferred rules and counts how
many of these the added rules wrongly block -- that count is the new per-backend FP column.

bWAPP pages require an authenticated session (bee/bug, security level low) -- established here in a
shared cookie jar, exactly as the pipeline does. Juice login/search need no session.

USAGE
  python generate_backend_benign.py --type sqli --site juice --page login     # default 1000
  python generate_backend_benign.py --type sqli --site juice --page search     # 1000
  python generate_backend_benign.py --type sqli --site bwapp --page login       # 1000
  python generate_backend_benign.py --type sqli --site bwapp --page search       # 1000
  python generate_backend_benign.py --type xss  --site bwapp --page calc         # 2000  (+ --browser)
  python generate_backend_benign.py --all                                          # all five
Optional: --count N  (override the default), --out DIR (default: <project>/Data), --browser (calc only).

OUTPUT  Data/benign_<type>_<site>_<page>.jsonl -- one replayable JSON request-record per line:
        {"type","site","page","method","url","body","content_type","value"}
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ----------------------------------------------------------------------------- config
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "Data"
HTTP_TIMEOUT = 12.0
ATTEMPT_CAP = 10             # max total attempts = ATTEMPT_CAP * count before giving up

JUICE_BACKEND = "http://localhost:3000"     # Route A: Juice direct, NO WAF
JUICE_WAF = "http://localhost/juice"        # Route B: WAF + Juice
BWAPP_BACKEND = "http://localhost:8082"     # Route A: bWAPP direct, NO WAF
BWAPP_WAF = "http://localhost/bwapp"        # Route B: WAF + bWAPP

BWAPP_USER, BWAPP_PASS, BWAPP_SECURITY = "bee", "bug", "0"   # low security session

# shared cookie jar: cookies for host "localhost" are carried to :8082 AND to the :80 proxy
COOKIE_JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(COOKIE_JAR))


# ----------------------------------------------------------------------------- HTTP
def http(url, method="GET", body=None, content_type="application/x-www-form-urlencoded"):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", content_type)
    try:
        with OPENER.open(req, timeout=HTTP_TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)[:160]


def http_retry(url, method="GET", body=None, content_type="application/x-www-form-urlencoded"):
    """Send once; retry ONCE on a transient failure (-1 / 503) so an outage isn't mistaken for a result."""
    st, bd = http(url, method, body, content_type)
    if st in (-1, 503):
        time.sleep(1.5)
        st, bd = http(url, method, body, content_type)
    return st, bd


# ----------------------------------------------------------------------------- bWAPP session
def bwapp_establish_session():
    http(f"{BWAPP_BACKEND}/login.php", "GET")
    body = urllib.parse.urlencode({"login": BWAPP_USER, "password": BWAPP_PASS,
                                   "security_level": BWAPP_SECURITY, "form": "submit"}).encode()
    http(f"{BWAPP_BACKEND}/login.php", "POST", body)


def bwapp_session_ok(page_file, marker):
    st, body = http(f"{BWAPP_BACKEND}/{page_file}")
    return st == 200 and marker in body.lower()


def bwapp_sql_error(body: str) -> bool:
    low = body.lower()
    return any(m in low for m in (
        "you have an error in your sql syntax", "error in your sql syntax",
        "warning: mysqli", "mysql_fetch", "mysql_num_rows", "you have an error"))


# ----------------------------------------------------------------------------- benign value generators
# Only benign characters (letters, digits, space, . _ - @, and arithmetic for calc). No SQLi/XSS metachars.
random.seed(20260703)

FIRST = ["john", "mary", "alice", "bob", "carol", "david", "emma", "frank", "grace", "henry",
         "ivy", "jack", "kate", "leo", "mia", "noah", "olivia", "peter", "quinn", "rose",
         "sam", "tina", "umar", "vera", "will", "xena", "yusuf", "zoe", "liam", "nora",
         "ethan", "ava", "lucas", "sophia", "mason", "isla", "logan", "ruby", "oscar", "lily"]
LAST = ["smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
        "martinez", "lopez", "wilson", "anderson", "taylor", "thomas", "moore", "jackson",
        "white", "harris", "clark", "lewis", "walker", "hall", "young", "king", "wright",
        "scott", "green", "baker", "adams", "nelson", "hill", "carter", "mitchell", "perez",
        "roberts", "turner", "phillips", "campbell", "parker", "evans"]
DOM = ["example.com", "mail.com", "shop.lab", "test.org", "corp.net", "webmail.com", "inbox.net"]
PROD = ["juice", "apple", "orange", "carrot", "smoothie", "tea", "coffee", "water", "bottle",
        "mug", "shirt", "tshirt", "cotton", "sticker", "notebook", "tote", "bag", "pack",
        "organic", "fresh", "green", "ceramic", "insulated", "lemon", "mango", "berry",
        "cocoa", "mint", "ginger", "honey", "almond", "oat", "soy", "glass", "steel", "banana"]
ADJ = ["large", "small", "blue", "red", "green", "premium", "classic", "eco", "new", "mini",
       "deluxe", "soft", "warm", "cool", "light", "dark", "round", "slim", "bold", "pure"]
# bWAPP movie-table words (the sqli_1 "title" search matches these) plus generic tokens
MOVIE = ["iron", "man", "dark", "knight", "rises", "star", "trek", "into", "darkness", "hobbit",
         "world", "war", "steel", "spider", "amazing", "fast", "furious", "cabin", "woods",
         "joe", "retaliation"]   # specific movie-title words (avoid over-broad tokens that dump many rows)
PW_CH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def rand_pw():
    return "".join(random.choice(PW_CH) for _ in range(random.randint(8, 14)))


def _local_part():
    f, l = random.choice(FIRST), random.choice(LAST)
    return random.choice([f, f + l, f + "." + l, f + "_" + l,
                          f + str(random.randint(1, 9999)), l + f[0] + str(random.randint(1, 99))])


def gen_juice_login():
    return {"user": f"{_local_part()}@{random.choice(DOM)}", "pass": rand_pw()}


def gen_bwapp_login():
    return {"user": _local_part(), "pass": rand_pw()}


def gen_juice_search():
    return random.choice([random.choice(PROD),
                          random.choice(ADJ) + " " + random.choice(PROD),
                          random.choice(PROD) + " " + random.choice(PROD),
                          random.choice(ADJ)])


def gen_bwapp_search():
    # bWAPP's movie table is tiny, so 1000 DISTINCT benign searches must include many that return
    # no match -- a normal, benign "no results" search (still 200, no SQL error, < 8 rows). Draw from
    # a broad benign vocabulary: movie words return a small result set, the rest return an empty one.
    pool = MOVIE + PROD + ADJ + FIRST
    term = " ".join(random.choice(pool) for _ in range(random.randint(1, 2)))
    if random.random() < 0.35:
        term = f"{term} {random.randint(1, 999)}"
    return term


def gen_calc():
    ops = ["+", "-", "*", "/"]
    parts = [str(random.randint(1, 999))]
    for _ in range(random.randint(1, 2)):          # 2-3 operands total
        parts.append(random.choice(ops))
        parts.append(str(random.randint(1, 99)))
    return "".join(parts)


def calc_is_sound(expr: str) -> bool:
    """The generated value must be a well-formed arithmetic expression evaluating to a finite number."""
    if not re.fullmatch(r"[0-9+\-*/(). ]+", expr):
        return False
    try:
        v = eval(expr, {"__builtins__": {}}, {})   # only our own arithmetic strings, char-whitelisted above
        return isinstance(v, (int, float)) and abs(v) < 1e12
    except Exception:
        return False


# ----------------------------------------------------------------------------- app-level validity oracles
def juice_login_valid(s, b):
    # normal login processing (not a 500 / SQL error). A random benign email normally 401s;
    # if it happened to match a real account we still accept it (a valid, benign login).
    if s == 500 or "SQLITE_ERROR" in b:
        return False
    if s == 401 and "invalid email or password" in b.lower():
        return True
    if s == 200 and '"token"' in b:
        return True
    return False


def juice_search_valid(s, b):
    if s != 200 or "SQLITE_ERROR" in b:
        return False
    try:
        j = json.loads(b)
    except Exception:
        return False
    data = j.get("data") if isinstance(j, dict) else None
    if not isinstance(data, list):
        return False
    # a benign search never leaks a deleted product (that would be an exploit, not benign)
    if any(isinstance(d, dict) and d.get("deletedAt") is not None for d in data):
        return False
    return True


def bwapp_login_valid(s, b):
    if s != 200 or bwapp_sql_error(b):
        return False
    return "sql injection" in b.lower()          # normal sqli_3 page rendered (session ok, no error)


def bwapp_search_valid(s, b):
    if s != 200 or bwapp_sql_error(b):
        return False
    if "sql injection" not in b.lower():
        return False
    return b.count("</tr>") < 8                    # a normal result set, not a full-table dump


def bwapp_calc_valid(s, b):
    if s != 200:
        return False
    return "cross-site scripting" in b.lower()     # normal xss_eval page rendered (session ok)


# ----------------------------------------------------------------------------- per-target registry
def _juice_login_send(base, v):
    return http_retry(f"{base}/rest/user/login", "POST",
                      json.dumps({"email": v["user"], "password": v["pass"]}).encode(),
                      "application/json")


def _juice_search_send(base, v):
    return http_retry(f"{base}/rest/products/search?q=" + urllib.parse.quote(v, safe=""))


def _bwapp_login_send(base, v):
    body = urllib.parse.urlencode({"login": v["user"], "password": v["pass"], "form": "submit"}).encode()
    return http_retry(f"{base}/sqli_3.php", "POST", body)


def _bwapp_search_send(base, v):
    return http_retry(f"{base}/sqli_1.php?" + urllib.parse.urlencode({"title": v, "action": "search"}))


def _bwapp_calc_send(base, v):
    return http_retry(f"{base}/xss_eval.php?" + urllib.parse.urlencode({"date": v}))


def _juice_login_record(v):
    return {"method": "POST", "url": f"{JUICE_WAF}/rest/user/login",
            "body": json.dumps({"email": v["user"], "password": v["pass"]}),
            "content_type": "application/json", "value": v}


def _juice_search_record(v):
    return {"method": "GET", "url": f"{JUICE_WAF}/rest/products/search?q=" + urllib.parse.quote(v, safe=""),
            "body": None, "content_type": None, "value": v}


def _bwapp_login_record(v):
    return {"method": "POST", "url": f"{BWAPP_WAF}/sqli_3.php",
            "body": urllib.parse.urlencode({"login": v["user"], "password": v["pass"], "form": "submit"}),
            "content_type": "application/x-www-form-urlencoded", "value": v}


def _bwapp_search_record(v):
    return {"method": "GET", "url": f"{BWAPP_WAF}/sqli_1.php?" + urllib.parse.urlencode({"title": v, "action": "search"}),
            "body": None, "content_type": None, "value": v}


def _bwapp_calc_record(v):
    return {"method": "GET", "url": f"{BWAPP_WAF}/xss_eval.php?" + urllib.parse.urlencode({"date": v}),
            "body": None, "content_type": None, "value": v}


def txt_url_of(rec):
    """One-line URL for the .txt corpus. GET pages -> the literal URL sent. POST pages (the two
    logins) -> the same WAF endpoint with the submitted params appended as a query string, so the
    line is distinct and reconstructable (same convention as data/benignurls.txt)."""
    if rec["method"] == "GET":
        return rec["url"]
    if rec.get("content_type") == "application/json":
        params = json.loads(rec["body"])
    else:
        params = dict(urllib.parse.parse_qsl(rec["body"]))
    return rec["url"] + "?" + urllib.parse.urlencode(params)


TARGETS = {
    ("sqli", "juice", "login"):  dict(count=1000, bases=(JUICE_BACKEND, JUICE_WAF), session=None,
                                      gen=gen_juice_login,  valid=juice_login_valid,
                                      send=_juice_login_send,  record=_juice_login_record),
    ("sqli", "juice", "search"): dict(count=1000, bases=(JUICE_BACKEND, JUICE_WAF), session=None,
                                      gen=gen_juice_search, valid=juice_search_valid,
                                      send=_juice_search_send, record=_juice_search_record),
    ("sqli", "bwapp", "login"):  dict(count=1000, bases=(BWAPP_BACKEND, BWAPP_WAF),
                                      session=("sqli_3.php", "sql injection"),
                                      gen=gen_bwapp_login,  valid=bwapp_login_valid,
                                      send=_bwapp_login_send,  record=_bwapp_login_record),
    ("sqli", "bwapp", "search"): dict(count=1000, bases=(BWAPP_BACKEND, BWAPP_WAF),
                                      session=("sqli_1.php", "sql injection"),
                                      gen=gen_bwapp_search, valid=bwapp_search_valid,
                                      send=_bwapp_search_send, record=_bwapp_search_record),
    ("xss", "bwapp", "calc"):    dict(count=2000, bases=(BWAPP_BACKEND, BWAPP_WAF),
                                      session=("xss_eval.php", "cross-site scripting"),
                                      gen=gen_calc,         valid=bwapp_calc_valid,
                                      send=_bwapp_calc_send,   record=_bwapp_calc_record,
                                      is_calc=True),
}


# ----------------------------------------------------------------------------- optional Selenium (calc only)
class Browser:
    """Confirms a benign calc value fires NO dialog (validate()==False). Mirrors pilot_A2's Browser."""
    CHROMIUM = "/usr/bin/chromium-browser"
    CHROMEDRIVER = "/usr/bin/chromedriver"

    def __init__(self):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        opts = Options()
        for a in ["--headless=new", "--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]:
            opts.add_argument(a)
        opts.binary_location = self.CHROMIUM
        self._d = webdriver.Chrome(service=Service(self.CHROMEDRIVER), options=opts)
        self._d.set_page_load_timeout(15)

    def login_bwapp(self):
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import Select
        self._d.get(f"{BWAPP_BACKEND}/login.php")
        self._d.find_element(By.NAME, "login").send_keys(BWAPP_USER)
        self._d.find_element(By.NAME, "password").send_keys(BWAPP_PASS)
        try:
            Select(self._d.find_element(By.NAME, "security_level")).select_by_value(BWAPP_SECURITY)
        except Exception:
            pass
        self._d.find_element(By.NAME, "form").click()
        time.sleep(0.5)

    def _drain(self):
        from selenium.common.exceptions import NoAlertPresentException
        n = 0
        for _ in range(10):
            try:
                self._d.switch_to.alert.dismiss(); n += 1
            except NoAlertPresentException:
                break
            except Exception:
                break
        return n

    def dialog_fires(self, url):
        from selenium.common.exceptions import UnexpectedAlertPresentException
        self._drain()
        fired = False
        try:
            self._d.get(url)
        except UnexpectedAlertPresentException:
            fired = True
        time.sleep(0.3)
        if self._drain() > 0:
            fired = True
        try:
            self._d.get("about:blank")
        except UnexpectedAlertPresentException:
            self._drain()
        return fired

    def close(self):
        try:
            self._d.quit()
        except Exception:
            pass


# ----------------------------------------------------------------------------- generate one target
def generate(kind, site, page, count, out_dir, use_browser):
    key = (kind, site, page)
    cfg = TARGETS[key]
    backend_base, waf_base = cfg["bases"]
    gen, valid, send, record = cfg["gen"], cfg["valid"], cfg["send"], cfg["record"]
    is_calc = cfg.get("is_calc", False)

    print(f"\n=== {kind}/{site}/{page}  target={count} benign ===")
    print(f"    Route A (backend, no WAF): {backend_base}")
    print(f"    Route B (WAF proxy)     : {waf_base}")

    # backend reachability + (bWAPP) authenticated session
    if cfg["session"] is not None:
        bwapp_establish_session()
        pf, marker = cfg["session"]
        if not bwapp_session_ok(pf, marker):
            print(f"!! bWAPP session/{pf} not reachable (need bee/bug low + running backend). ABORT.")
            return None
    else:
        st, _ = http_retry(f"{backend_base}/rest/products/search?q=ping")
        if st != 200:
            print(f"!! Juice backend not reachable at {backend_base} (status {st}). ABORT.")
            return None

    browser = None
    if is_calc and use_browser:
        try:
            browser = Browser(); browser.login_bwapp()
            print("    [browser] Selenium bWAPP session established (no-dialog confirmation ON)")
        except Exception as e:
            print(f"!! --browser requested but Selenium/Chromium failed to start: {e}. ABORT.")
            return None

    seen = set()
    kept = []          # list of record dicts
    n_blocked = n_invalid_a = n_invalid_b = n_error = n_dialog = 0
    attempts = 0
    max_attempts = count * ATTEMPT_CAP

    while len(kept) < count and attempts < max_attempts:
        attempts += 1
        v = gen()
        dkey = json.dumps(v, sort_keys=True) if isinstance(v, dict) else v
        if dkey in seen:
            continue
        seen.add(dkey)

        if is_calc and not calc_is_sound(v):
            continue

        # ---- Route A: direct backend, must be app-valid ----
        sA, bA = send(backend_base, v)
        if sA == -1:
            n_error += 1; continue
        if not valid(sA, bA):
            n_invalid_a += 1; continue

        # ---- Route B: WAF proxy, must NOT be blocked by baseline CRS (403-only) ----
        sB, bB = send(waf_base, v)
        if sB == 403:
            n_blocked += 1; continue
        if sB == -1:
            n_error += 1; continue
        if not valid(sB, bB):          # the proxied (allowed) response must also be a normal one
            n_invalid_b += 1; continue

        # ---- optional: confirm a benign calc fires no JS dialog in a real browser ----
        if browser is not None:
            direct_url = f"{backend_base}/xss_eval.php?" + urllib.parse.urlencode({"date": v})
            if browser.dialog_fires(direct_url):
                n_dialog += 1; continue

        rec = record(v)
        rec.update({"type": kind, "site": site, "page": page})
        kept.append(rec)
        if len(kept) % 200 == 0:
            print(f"    kept {len(kept)}/{count}  (attempts {attempts})")

    if browser is not None:
        browser.close()

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"benign_{kind}_{site}_{page}"
    txt_file = out_dir / f"{stem}.txt"        # one valid URL per line (the corpus you asked for)
    jsonl_file = out_dir / f"{stem}.jsonl"    # full replayable record (keeps POST bodies exact)
    with open(txt_file, "w", encoding="utf-8") as f:
        for rec in kept:
            f.write(txt_url_of(rec) + "\n")
    with open(jsonl_file, "w", encoding="utf-8") as f:
        for rec in kept:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"    SAVED {len(kept)} benign -> {txt_file}  (+ {jsonl_file.name})")
    print(f"    dropped: baseline-CRS-blocked={n_blocked}  invalid@backend={n_invalid_a}  "
          f"invalid@waf={n_invalid_b}  transient-errors={n_error}"
          + (f"  dialog-fired={n_dialog}" if browser is not None else "")
          + f"  (attempts={attempts})")
    if len(kept) < count:
        print(f"    !! WARNING: only {len(kept)}/{count} collected before the attempt cap "
              f"({max_attempts}). Inspect the drop counts above.")
    return txt_file


# ----------------------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Generate valid benign FP corpora for Juice/bWAPP pages.")
    ap.add_argument("--type", choices=["sqli", "xss"])
    ap.add_argument("--site", choices=["juice", "bwapp"])
    ap.add_argument("--page", choices=["login", "search", "calc"])
    ap.add_argument("--count", type=int, default=None, help="override the per-page default count")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="output directory (default: <project>/Data)")
    ap.add_argument("--browser", action="store_true",
                    help="calc only: also confirm each sample fires NO JS dialog via headless Chromium")
    ap.add_argument("--all", action="store_true", help="run all five targets with their default counts")
    args = ap.parse_args()

    out_dir = Path(args.out)

    if args.all:
        for (kind, site, page), cfg in TARGETS.items():
            generate(kind, site, page, cfg["count"], out_dir,
                     use_browser=(args.browser and cfg.get("is_calc", False)))
        return

    if not (args.type and args.site and args.page):
        ap.error("specify --type, --site and --page (or use --all)")
    key = (args.type, args.site, args.page)
    if key not in TARGETS:
        ap.error(f"unknown target {key}. Valid: {sorted(TARGETS.keys())}")
    count = args.count if args.count is not None else TARGETS[key]["count"]
    generate(args.type, args.site, args.page, count, out_dir, use_browser=args.browser)


if __name__ == "__main__":
    main()
