#!/usr/bin/env python3
"""R1.1 RQ3 replay (SQLi), ONE run, validation test.
Extract the 300 saved held-out (stress) attacks from the C1 log, load the run's frozen rules,
and re-run the two-stage check (Route A backend exploit + Route B WAF status + exploit-through-WAF
oracle) under CRS-only and under CRS+rules. Compare the recomputed funnel with the logged one."""
import os, sys, re, time
os.environ["A1_PAGE"] = os.environ.get("RP_PAGE", "search")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import pilot_A1_customapp_attack_only_v2 as pilot
pilot.log_print = lambda *a, **k: None
if hasattr(pilot, "ensure_backend_up"): pilot.ensure_backend_up = lambda *a, **k: True
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache

PAGE = os.environ["A1_PAGE"]; SEED = int(os.environ.get("RP_SEED", "1"))
RUN = f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps0.3_seed{SEED}"
LOG = f"{RUN}/C1_customapp_{PAGE}_clustering.txt"
RULES = f"{RUN}/C1_customapp_{PAGE}_clustering_rules.txt"

_TAGS = re.compile(r"^(?:\[\s*(?:valid|invalid|sql_failed|backend_valid|backend_invalid|non_executable|app_rejected|reached_no_exec|BYPASS|BLOCKED)\s*\]\s*)+", re.I)
def extract_stress(path):
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^\s*\[stress\]\s*(\d+)\.\s(.*)$", ln.rstrip("\n"))
        if m:
            p = _TAGS.sub("", m.group(2))  # strip leading classification tag(s): [valid ] [BYPASS ], [sql_failed   ], ...
            out.append((int(m.group(1)), p))
    out.sort()
    return [p for _, p in out]

def log_funnel(path):
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"\[stress\] generated (\d+)\s+valid (\d+)\s+CRS-bypass (\d+)\s+blocked-by-rules (\d+)\s+still-bypass (\d+)\s+rule-block%=([\d.]+)", ln)
        if m: return tuple(int(x) for x in m.groups()[:5]) + (float(m.group(6)),)
    return None

def reload_with(rules):
    write_rules(rules); ok, out = run_configtest()
    if not ok: print("  !! CONFIGTEST FAILED:", out[:160])
    reload_apache(timeout=15)

attacks = extract_stress(LOG)
secrules = [l.strip() for l in open(RULES, encoding="utf-8", errors="replace") if l.strip().startswith("SecRule")]
lf = log_funnel(LOG)
print(f"page={PAGE} seed={SEED}  extracted stress attacks={len(attacks)}  frozen rules={len(secrules)}")
print(f"LOGGED funnel: generated={lf[0]} valid={lf[1]} CRS-bypass={lf[2]} blocked-by-rules={lf[3]} still-bypass={lf[4]} block%={lf[5]}")

import collections
t0 = time.time()
# PASS 1: CRS only -> backend_valid, crs status, exploit-through-CRS
reload_with([])
recs = []
cats = collections.Counter(); bstat = collections.Counter()
for p in attacks:
    r = pilot.classify(p, 0)
    cats[r["category"]] += 1; bstat[r["backend_status"]] += 1
    recs.append({"p": p, "bv": r["backend_valid"], "crs_byp": r["waf_bypassed"], "crs_vtw": r["valid_through_waf"] is True})
valid = [r for r in recs if r["bv"]]
crs_byp = [r for r in valid if r["crs_byp"]]
crs_byp_exploit = [r for r in crs_byp if r["crs_vtw"]]
print(f"PASS1 (CRS): valid={len(valid)}  CRS-bypass={len(crs_byp)}  CRS-bypass&exploit={len(crs_byp_exploit)}  [{time.time()-t0:.0f}s]")
print("  category counts:", dict(cats))
print("  backend_status counts (Route A):", dict(bstat))

# PASS 2: CRS + frozen rules -> re-classify the CRS-bypassing valid attacks (Route A + Route B with rules)
reload_with(secrules)
flap = 0
for r in crs_byp:
    rr = pilot.classify(r["p"], 0)
    if not rr["backend_valid"]:   # Route A flapped on the re-run; retry once
        rr = pilot.classify(r["p"], 0); flap += 1
    r["rule_blocked"] = (rr["waf_status"] == 403)
    r["rule_vtw"] = (not r["rule_blocked"]) and (rr["valid_through_waf"] is True)
reload_with([])  # restore CRS-only
if flap: print(f"  (pass2 Route A re-validation retried on {flap} attack(s))")

# reported (403-only) funnel, as the paper computed it
den_rep = len(crs_byp)
resid_rep = sum(1 for r in crs_byp if not r["rule_blocked"])
block_rep = 100.0 * (den_rep - resid_rep) / den_rep if den_rep else 0.0
# verified (two-stage): denominator and residual require the exploit to actually fire through the WAF
den_ver = len(crs_byp_exploit)
resid_ver = sum(1 for r in crs_byp_exploit if (not r["rule_blocked"]) and r["rule_vtw"])
block_ver = 100.0 * (den_ver - resid_ver) / den_ver if den_ver else 0.0

print(f"PASS2 (CRS+rules):")
print(f"  REPORTED (403-only):  denom(CRS-bypass)={den_rep}  residual={resid_rep}  block%={block_rep:.1f}   [log said CRS-bypass={lf[2]} blocked={lf[3]} residual={lf[4]} block%={lf[5]}]")
print(f"  VERIFIED (two-stage): denom(CRS-bypass&exploit)={den_ver}  residual(pass&exploit)={resid_ver}  block%={block_ver:.1f}")
# any residual that passes the rules but does NOT exploit -> a 'false bypass' the two-stage criterion removes
false_byp = sum(1 for r in crs_byp if (not r["rule_blocked"]) and not r["rule_vtw"])
print(f"  residuals that pass CRS+rules but do NOT exploit through the WAF (false bypasses): {false_byp}")
print(f"done in {time.time()-t0:.0f}s")
