#!/usr/bin/env python3
"""R1.3 smoke v2: SAME tests but with Host: localhost (faithful to the CRS-3.3.2 baseline, which used
http://localhost/...). This removes the 920350 numeric-IP +3 anomaly artifact that would overcount blocks."""
import subprocess, urllib.request, urllib.parse, urllib.error, glob, json, re, time

SQLI = "http://127.0.0.1:8081"
XSS  = "http://127.0.0.1:8086"
ROOT = "/home/vahid/Projects/GenWebSec"
HOST = "localhost"

def send(base, path, param, payload, method="GET", extra=None):
    params = dict(extra or {}); params[param] = payload
    data = urllib.parse.urlencode(params)
    hdr = {"Host": HOST}
    try:
        if method == "GET":
            req = urllib.request.Request(f"{base}/{path}?{data}", headers=hdr)
        else:
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
            req = urllib.request.Request(f"{base}/{path}", data=data.encode(), method="POST", headers=hdr)
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{str(e)[:40]}"

SQLI_CFG = {"login": ("login", "username", "POST", {"password": "x"}), "search": ("search", "q", "GET", {}),
            "product": ("product", "id", "GET", {}), "filter": ("filter", "category", "GET", {})}
XSS_CFG = {"search": ("search.php", "q", "GET", {}), "calc": ("calc.php", "expr", "GET", {})}
def sqli(pg, p): a = SQLI_CFG[pg]; return send(SQLI, a[0], a[1], p, a[2], a[3])
def xss(pg, p):  a = XSS_CFG[pg];  return send(XSS,  a[0], a[1], p, a[2], a[3])

def sample(pattern, n=3):
    out = []
    for f in sorted(glob.glob(pattern)):
        for line in open(f, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                out.append(line)
                if len(out) >= n: return out
    return out

print("========== (1) CANONICAL ATTACKS (Host: localhost) -> expect 403 ==========")
for pg, p in [("product", "1' OR '1'='1"), ("search", "x' UNION SELECT username,password FROM users-- -"),
              ("login", "' OR '1'='1' -- "), ("filter", "x' OR 1=1-- -")]:
    print(f"  SQLi/{pg:<7} -> {str(sqli(pg,p)):>5}   {p}")
for pg, p in [("search", "<script>alert(1)</script>"), ("calc", "<script>alert(document.cookie)</script>")]:
    print(f"  XSS /{pg:<7} -> {str(xss(pg,p)):>5}   {p}")

print("\n========== (2) BENIGN (Host: localhost) -> expect 200 ==========")
for pg, p in [("product", "2"), ("search", "shoes"), ("filter", "electronics"), ("login", "alice")]:
    print(f"  SQLi/{pg:<7} -> {str(sqli(pg,p)):>5}   {p!r}")
for pg, p in [("search", "hello world"), ("calc", "2+2")]:
    print(f"  XSS /{pg:<7} -> {str(xss(pg,p)):>5}   {p!r}")

print("\n========== (3) REAL RQ1 BYPASSES through CRS 4.29.0 (Host: localhost, status only) ==========")
for page in ["product", "search", "login", "filter"]:
    for p in sample(f"{ROOT}/results/V2/CustomApp_A1/*A1_CRSonly_seed1/A1_customapp_{page}_winners.txt", 3):
        print(f"  SQLi/{page:<7} -> {str(sqli(page,p)):>5}   {p[:88]}")
for page in ["search", "calc"]:
    for p in sample(f"{ROOT}/results/V2/CustomApp_A2/*A2_CRSonly_seed1/A2_customxss_{page}_winners.txt", 3):
        print(f"  XSS /{page:<7} -> {str(xss(page,p)):>5}   {p[:88]}")

print("\n========== (4) CLEAN AUDIT for a canonical 403 (confirm 920350 gone; show inspected fields) ==========")
sqli("product", "1' OR '1'='1")
time.sleep(1.0)
r = subprocess.run(["docker", "logs", "--tail", "40", "crs-sqli"], capture_output=True, text=True, timeout=30)
jl = [l for l in (r.stdout + "\n" + r.stderr).splitlines() if l.strip().startswith("{")]
j = json.loads(jl[-1]) if jl else {}
print("  request_line:", j.get("request", {}).get("request_line"))
print("  Host header sent:", j.get("request", {}).get("headers", {}).get("Host"))
print("  response.status:", j.get("response", {}).get("status"))
print("  producer:", j.get("audit_data", {}).get("producer"))
print("  matched rules (id | field | msg):")
for m in j.get("audit_data", {}).get("messages", []):
    rid = (re.search(r'\[id "(\d+)"\]', m) or [None, "?"])[1]
    fld = (re.search(r'at ([A-Z_]+(?::[^.\s]+)?)\.', m) or [None, "-"])[1]
    msg = (re.search(r'\[msg "([^"]+)"\]', m) or [None, "-"])[1]
    print(f"    {rid:>7} | {fld:<22} | {msg}")
print("== smoke2 done ==")
