#!/usr/bin/env python3
"""Set up the XSS replay environment: start the two php -S backends (8094 search-side, 8095 calc-side,
both serving the whole customxss docroot), install the /customxss WAF proxy route into the vahid-owned
sft_rule.conf (loaded by IncludeOptional /etc/modsecurity/custom/*.conf, same as 00-genwebsec-proxy.conf),
reload Apache, and verify every route plus that CRS still blocks a raw XSS probe through the WAF."""
import sys, subprocess, time, urllib.request, urllib.error, urllib.parse
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache
DOCROOT = ROOT + "/customxss"

# per-page proxy routes: /customxss/<page>.php -> that page's own backend port (Route A hits the SAME
# port directly; the only difference on Route B is the WAF in front). Mirrors the documented setup
# (experimental-setup.tex: :8094/8095 -> /customxss/) and the Route-A ports in the C2 logs.
PROXY = [
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]

def up(port):
    try:
        return urllib.request.urlopen(f"http://127.0.0.1:{port}/index.php", timeout=3).status == 200
    except Exception:
        return False

for port in (8094, 8095):
    if not up(port):
        subprocess.Popen(["php", "-S", f"127.0.0.1:{port}", "-t", DOCROOT],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
for _ in range(20):
    if up(8094) and up(8095):
        break
    time.sleep(0.5)
print("backend 8094 up:", up(8094), "  backend 8095 up:", up(8095))

write_rules(PROXY)   # sft_rule.conf = proxy route only (no WAF rules yet)
ok, out = run_configtest()
print("configtest ok:", ok)
if not ok:
    print(out[:800]); sys.exit(1)
print("reload:", reload_apache(timeout=20)[0])

def code(url):
    try:
        return urllib.request.urlopen(url, timeout=6).status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return repr(e)

xss = urllib.parse.urlencode({"q": "<script>alert(1)</script>"})
calcx = urllib.parse.urlencode({"expr": "alert(1)"})
print("backend direct 8094 search benign :", code("http://127.0.0.1:8094/search.php?q=hello"))
print("backend direct 8095 calc   benign :", code("http://127.0.0.1:8095/calc.php?expr=2"))
print("WAF /customxss/search.php  benign :", code("http://localhost/customxss/search.php?q=hello"))
print("WAF /customxss/calc.php    benign :", code("http://localhost/customxss/calc.php?expr=2"))
print("WAF /customxss/search.php  XSS    :", code(f"http://localhost/customxss/search.php?{xss}"))
print("WAF /customxss/calc.php    XSS    :", code(f"http://localhost/customxss/calc.php?{calcx}"))
