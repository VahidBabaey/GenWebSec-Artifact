#!/usr/bin/env python3
"""Verify CRS 4.29.0 actually INSPECTS each bwapp/juice request shape (canonical attack must 403),
   so a 0% block rate reflects real evasion, not an un-inspected field. Then look at real juice-search."""
import urllib.request, urllib.parse, urllib.error, json, subprocess, re, glob, time

CRS = "http://127.0.0.1:8081"; HOST = "localhost"
ROOT = "/home/vahid/Projects/GenWebSec"

def build(target, page, payload):
    if target == "bwapp":
        if page == "login":
            return "POST", f"{CRS}/bwapp/sqli_3.php", urllib.parse.urlencode({"login": payload, "password": "wrongpw", "form": "submit"}).encode(), "application/x-www-form-urlencoded"
        return "GET", f"{CRS}/bwapp/sqli_1.php?" + urllib.parse.urlencode({"title": payload, "action": "search"}), None, None
    if page == "login":
        return "POST", f"{CRS}/juice/rest/user/login", json.dumps({"email": payload, "password": "x"}).encode(), "application/json"
    return "GET", f"{CRS}/juice/rest/products/search?q=" + urllib.parse.quote(payload, safe=""), None, None

def send(target, page, payload):
    method, url, body, ct = build(target, page, payload)
    hdr = {"Host": HOST}
    if ct: hdr["Content-Type"] = ct
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, method=method, headers=hdr), timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return f"ERR:{str(e)[:30]}"

print("== canonical SQLi via each shape (expect 403 if CRS inspects that field) ==")
for target, page in [("bwapp", "login"), ("bwapp", "search"), ("juice", "login"), ("juice", "search")]:
    for canon in ["' OR '1'='1", "' UNION SELECT NULL,NULL,NULL-- -", "1' AND SLEEP(5)-- -"]:
        print(f"  {target}/{page:<7} {str(send(target,page,canon)):>5}  <= {canon}")
    print()

print("== 6 REAL juice-search payloads: status + the payload ==")
reals = []
for f in sorted(glob.glob(f"{ROOT}/results/V2/A1_HeldOut/A1_juice_heldout_seed*/A1_juice_search_winners.txt")):
    for line in open(f, encoding="utf-8", errors="replace"):
        s = line.rstrip("\n")
        if s and not s.startswith("#"):
            reals.append(s)
    if len(reals) >= 6:
        break
for p in reals[:6]:
    print(f"  {str(send('juice','search',p)):>5}  <= {p}")

print("\n== audit for a canonical juice-search 403 (confirms ARGS:q inspected) ==")
send("juice", "search", "' UNION SELECT NULL,NULL,NULL-- -")
time.sleep(1)
r = subprocess.run(["docker", "logs", "--tail", "25", "crs-sqli"], capture_output=True, text=True, timeout=30)
jl = [l for l in (r.stdout + "\n" + r.stderr).splitlines() if l.strip().startswith("{") and '"audit_data"' in l]
if jl:
    j = json.loads(jl[-1])
    print("  request_line:", j.get("request", {}).get("request_line"))
    print("  status:", j.get("response", {}).get("status"))
    for m in j.get("audit_data", {}).get("messages", []):
        rid = (re.search(r'\[id "(\d+)"\]', m) or [None, "?"])[1]
        fld = (re.search(r'(?:at|within) ([A-Z_]+(?::[^.\s]+)?)', m) or [None, "-"])[1]
        msg = (re.search(r'\[msg "([^"]+)"\]', m) or [None, "-"])[1]
        print(f"    {rid} | {fld} | {msg}")
else:
    print("  (no audit json found)")
