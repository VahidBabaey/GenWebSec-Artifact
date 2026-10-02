#!/usr/bin/env python3
"""R1.1 RQ1 app re-replay (SQLi), one page per process. Env: A1_PAGE in {login,search,product,filter}.
Re-sends every RQ1 winner (backend-valid + CRS-bypassing attack, from CustomApp_A1_CRSonly_seed{1..5})
through the LIVE custom app + CRS-only WAF with the two-stage oracle, independently re-confirming that
each non-403 bypass is a genuine exploit through the WAF (valid_through_waf). This replaces trusting the
stored generation-time field with a fresh app replay, matching the RQ3/RQ4 bar."""
import os, sys, re, csv, hashlib
os.environ.setdefault("A1_PAGE", "login")
os.environ.setdefault("A1_TARGET", "customapp")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import importlib, time as _t
pilot = mh = None
for _ in range(10):
    try:
        pilot = importlib.import_module("pilot_A1_customapp_attack_only_v2")
        mh = importlib.import_module("helpers.modsec_helpers"); break
    except (SystemError, ImportError):
        pilot = None; _t.sleep(1)
if pilot is None:
    raise SystemExit("pilot import failed")
pilot.log_print = lambda *a, **k: None
if hasattr(pilot, "ensure_backend_up"): pilot.ensure_backend_up = lambda *a, **k: True
write_rules, run_configtest, reload_apache = mh.write_rules, mh.run_configtest, mh.reload_apache
PAGE = os.environ["A1_PAGE"]

def reload_crs_only():
    write_rules([]); ok, out = run_configtest()
    if not ok: print("  CONFIGTEST FAIL", out[:120])
    reload_apache(timeout=20)

def winners(seed):
    f = f"{ROOT}/results/V2/CustomApp_A1/CustomApp_A1_CRSonly_seed{seed}/A1_customapp_{PAGE}_winners.txt"
    if not os.path.exists(f): return []
    return [l.rstrip("\n") for l in open(f, encoding="utf-8", errors="replace") if l.strip() and not l.startswith("#")]

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq1_replay"
os.makedirs(OUT, exist_ok=True)
sumpath = f"{OUT}/rq1_sqli_replay_summary.csv"
done = set()
if os.path.exists(sumpath):
    for r in csv.DictReader(open(sumpath)): done.add((r["page"], r["seed"]))
sumf = open(sumpath, "a", newline="", encoding="utf-8"); sw = csv.writer(sumf)
if sumf.tell() == 0:
    sw.writerow(["page","seed","n_winners","backend_valid_confirmed","bypass_not403","exploit_through_waf","false_bypass"]); sumf.flush()
detf = open(f"{OUT}/rq1_sqli_replay_false.csv", "a", newline="", encoding="utf-8"); dw = csv.writer(detf)
if detf.tell() == 0:
    dw.writerow(["page","seed","payload_sha1","backend_valid","waf_status","reason"]); detf.flush()

reload_crs_only()
print(f"=== RQ1 SQLi app re-replay  page={PAGE}  (CRS-only)  WAF={pilot.WAF} ===")
for seed in range(1, 6):
    if (PAGE, str(seed)) in done:
        print(f"  seed{seed}: (done, skip)"); continue
    ws = winners(seed)
    if not ws:
        print(f"  seed{seed}: no winners file"); continue
    bv = byp = exp = false_b = 0
    for p in ws:
        r = pilot.classify(p, 0)
        if r["backend_valid"]: bv += 1
        if r["backend_valid"] and r["waf_bypassed"]:
            byp += 1
            if r["valid_through_waf"] is True:
                exp += 1
            else:
                false_b += 1
                dw.writerow([PAGE, seed, hashlib.sha1(p.encode("utf-8","replace")).hexdigest()[:16],
                             int(r["backend_valid"]), r["waf_status"], "not403_no_exploit"]); detf.flush()
    sw.writerow([PAGE, seed, len(ws), bv, byp, exp, false_b]); sumf.flush()
    print(f"  seed{seed}: winners={len(ws):>4} backend_valid={bv:>4} bypass={byp:>4} exploit_through_waf={exp:>4} false={false_b:>2}")
sumf.close(); detf.close()
print(f"done SQLi/{PAGE}")
