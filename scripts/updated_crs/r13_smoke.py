#!/usr/bin/env python3
"""R1.3 SMOKE TEST (gate before the full run):
  (1) canonical attacks  -> expect 403 (ModSecurity active + blocking on CRS 4.29.0)
  (2) benign requests    -> expect non-403 (ideally 200, reaching the backend through the proxy)
  (3) a few REAL RQ1 CRS-3.3.2-bypassing attacks -> record status through CRS 4.29.0
  (4) audit-log check     -> confirm the container emits a JSON audit record for a 403
Status-only, no exploit oracle (per the task: just check attacks against the updated CRS)."""
import subprocess, urllib.request, urllib.parse, urllib.error, glob, json, time

SQLI = "http://127.0.0.1:8081"   # crs-sqli -> customapp :8080
XSS  = "http://127.0.0.1:8086"   # crs-xss  -> customxss :8096
ROOT = "/home/vahid/Projects/GenWebSec"

def send(base, path, param, payload, method="GET", extra=None):
    params = dict(extra or {}); params[param] = payload
    data = urllib.parse.urlencode(params)
    try:
        if method == "GET":
            req = urllib.request.Request(f"{base}/{path}?{data}")
        else:
            req = urllib.request.Request(f"{base}/{path}", data=data.encode(), method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{str(e)[:40]}"

SQLI_CFG = {"login": ("login", "username", "POST", {"password": "x"}),
            "search": ("search", "q", "GET", {}),
            "product": ("product", "id", "GET", {}),
            "filter": ("filter", "category", "GET", {})}
XSS_CFG = {"search": ("search.php", "q", "GET", {}), "calc": ("calc.php", "expr", "GET", {})}

def sqli(page, p):
    path, param, method, extra = SQLI_CFG[page]; return send(SQLI, path, param, p, method, extra)
def xss(page, p):
    path, param, method, extra = XSS_CFG[page]; return send(XSS, path, param, p, method, extra)

def sample(pattern, n=2):
    out = []
    for f in sorted(glob.glob(pattern)):
        for line in open(f, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                out.append(line)
                if len(out) >= n:
                    return out
    return out

print("========== (1) CANONICAL ATTACKS  -> expect 403 ==========")
for pg, p in [("product", "1' OR '1'='1"), ("search", "x' UNION SELECT username,password FROM users-- -"),
              ("login", "' OR '1'='1' -- "), ("filter", "x' OR 1=1-- -")]:
    print(f"  SQLi/{pg:<7} -> {str(sqli(pg,p)):>5}   {p}")
for pg, p in [("search", "<script>alert(1)</script>"), ("search", '"><img src=x onerror=alert(1)>'),
              ("calc", "<script>alert(document.cookie)</script>")]:
    print(f"  XSS /{pg:<7} -> {str(xss(pg,p)):>5}   {p}")

print("\n========== (2) BENIGN  -> expect non-403 (200) ==========")
for pg, p in [("product", "2"), ("search", "shoes"), ("filter", "electronics"), ("login", "alice")]:
    print(f"  SQLi/{pg:<7} -> {str(sqli(pg,p)):>5}   {p!r}")
for pg, p in [("search", "hello world"), ("calc", "2+2"), ("calc", "3*4")]:
    print(f"  XSS /{pg:<7} -> {str(xss(pg,p)):>5}   {p!r}")

print("\n========== (3) REAL RQ1 CRS-3.3.2 BYPASSES through CRS 4.29.0 (status only) ==========")
for page in ["product", "search", "login", "filter"]:
    for p in sample(f"{ROOT}/results/V2/CustomApp_A1/*A1_CRSonly_seed1/A1_customapp_{page}_winners.txt", 2):
        print(f"  SQLi/{page:<7} -> {str(sqli(page,p)):>5}   {p[:90]}")
for page in ["search", "calc"]:
    for p in sample(f"{ROOT}/results/V2/CustomApp_A2/*A2_CRSonly_seed1/A2_customxss_{page}_winners.txt", 2):
        print(f"  XSS /{page:<7} -> {str(xss(page,p)):>5}   {p[:90]}")

print("\n========== (4) AUDIT LOG CHECK (JSON audit for a 403) ==========")
sqli("product", "1' OR '1'='1")           # guaranteed-relevant request
time.sleep(1.0)
r = subprocess.run(["docker", "logs", "--tail", "60", "crs-sqli"], capture_output=True, text=True, timeout=30)
jl = [l for l in (r.stdout + "\n" + r.stderr).splitlines() if l.strip().startswith("{")]
print(f"  JSON audit lines found in last 60 log lines: {len(jl)}")
if jl:
    try:
        j = json.loads(jl[-1])
        tx = j.get("transaction", {})
        resp = tx.get("response", {}) if isinstance(tx.get("response"), dict) else {}
        msgs = (tx.get("messages") or j.get("audit_data", {}).get("messages") or [])
        print("  top-level keys:", list(j.keys()))
        print("  http_code:", resp.get("http_code") or resp.get("status"))
        rule_ids = []
        for m in msgs:
            det = m.get("details", {}) if isinstance(m, dict) else {}
            rid = det.get("ruleId") or det.get("id")
            if rid: rule_ids.append(rid)
        print("  matched rule ids (sample):", rule_ids[:12])
        print("  message count:", len(msgs))
    except Exception as e:
        print("  parse note:", e)
        print("  raw tail:", jl[-1][:500])
print("== smoke done ==")
