#!/usr/bin/env python3
"""Characterize the PP/calc seed1 off-by-one: re-measure the CRS-only bypass count (status!=403) of the
log-valid held-out attacks several times. Stable 63 => a borderline-CRS payload that genuinely bypasses
CRS (the run-time log's 62 was the borderline call); varying => transient. Either way it is status-only
and creates no verified bypass (still-bypass stayed 0)."""
import os, sys, re, time
os.environ["C2_PAGE"] = "calc"; os.environ["C2_MODE"] = "per_payload"
_DEPS = "/home/vahid/tools/deps/usr/lib/x86_64-linux-gnu"
os.environ["LD_LIBRARY_PATH"] = _DEPS + ":" + os.environ.get("LD_LIBRARY_PATH", "")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import importlib
pilot = importlib.import_module("pilot_C2_customxss_coevolution_v2")
mh = importlib.import_module("helpers.modsec_helpers")
pilot.log_print = lambda *a, **k: None
PROXY = [
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]
def reload_crs():
    mh.write_rules(PROXY); mh.run_configtest(); mh.reload_apache(timeout=20)

LOG = f"{ROOT}/results/V2/CustomApp_C2-PP/CustomXSS_C2_Token_seed1/C2_customxss_calc_per_payload.txt"
valid = []
for ln in open(LOG, encoding="utf-8", errors="replace"):
    m = re.match(r"^\s*\[stress\]\s*(\d+)\.\s*\[valid\s*\]\s*\[(BYPASS|BLOCKED)\s*\]\s(.*)$", ln.rstrip("\n"))
    if m: valid.append((int(m.group(1)), m.group(2), m.group(3)))
print("log-valid attacks:", len(valid), " (log reported CRS-bypass=62)")
pilot.start_backend()
prev = None
for trial in range(3):
    reload_crs()
    byp = set()
    for idx, tag, p in valid:
        if pilot.http_status(pilot.build_url(pilot.WAF, p)[0]) != 403:
            byp.add(idx)
    print(f"trial {trial}: CRS-bypass count = {len(byp)}")
    if prev is not None:
        d = byp ^ prev
        if d: print("   indices differing from previous trial:", sorted(d))
    prev = byp
reload_crs()
print("done")
