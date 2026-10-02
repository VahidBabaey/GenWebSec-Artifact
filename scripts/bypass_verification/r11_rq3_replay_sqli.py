#!/usr/bin/env python3
"""R1.1 RQ3 SQLi replay, all seeds for one (strategy, page). Env: A1_PAGE, RP_STRAT in {CG,PP}.
Extracts each run's saved held-out (stress) attacks, loads its frozen rules, and re-runs the
two-stage check against the custom SQLi app through the WAF (Route A exploit + Route B status +
exploit-through-WAF oracle), under CRS-only then CRS+rules. Writes per-attack + per-run artifacts
and prints a faithfulness table vs the logged funnel."""
import os, sys, re, csv, time, hashlib, collections
os.environ.setdefault("A1_PAGE", "search")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import importlib, time as _t
pilot = write_rules = run_configtest = reload_apache = None
for _att in range(10):   # transient WSL C-ext import failures (SystemError/ImportError) -> retry
    try:
        pilot = importlib.import_module("pilot_A1_customapp_attack_only_v2")
        _mh = importlib.import_module("helpers.modsec_helpers")
        write_rules, run_configtest, reload_apache = _mh.write_rules, _mh.run_configtest, _mh.reload_apache
        break
    except (SystemError, ImportError):
        pilot = None; _t.sleep(1.0)
if pilot is None:
    raise SystemExit("pilot/helpers import failed after retries (transient WSL C-ext issue)")
pilot.log_print = lambda *a, **k: None
if hasattr(pilot, "ensure_backend_up"): pilot.ensure_backend_up = lambda *a, **k: True

PAGE = os.environ["A1_PAGE"]; STRAT = os.environ.get("RP_STRAT", "CG")
OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq3"
os.makedirs(OUT, exist_ok=True)
_TAGS = re.compile(r"^(?:\[\s*(?:valid|invalid|sql_failed|backend_valid|backend_invalid|non_executable|app_rejected|reached_no_exec|BYPASS|BLOCKED)\s*\]\s*)+", re.I)

def paths(seed):
    if STRAT == "CG":
        d = f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps0.3_seed{seed}"
        return f"{d}/C1_customapp_{PAGE}_clustering.txt", f"{d}/C1_customapp_{PAGE}_clustering_rules.txt"
    d = f"{ROOT}/results/V2/CustomApp_C1-PP/CustomApp_C1_Token_seed{seed}"
    return f"{d}/C1_customapp_{PAGE}_per_payload.txt", f"{d}/C1_customapp_{PAGE}_per_payload_rules.txt"

def extract_stress(path):
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"^\s*\[stress\]\s*(\d+)\.\s(.*)$", ln.rstrip("\n"))
        if m: out.append((int(m.group(1)), _TAGS.sub("", m.group(2))))
    out.sort(); return [p for _, p in out]

def log_funnel(path):
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"\[stress\] generated (\d+)\s+valid (\d+)\s+CRS-bypass (\d+)\s+blocked-by-rules (\d+)\s+still-bypass (\d+)\s+rule-block%=([\d.]+)", ln)
        if m: return tuple(int(x) for x in m.groups()[:5]) + (float(m.group(6)),)
    return None

def reload_with(rules):
    write_rules(rules); ok, out = run_configtest()
    if not ok: print("  !! CONFIGTEST FAILED", out[:120])
    reload_apache(timeout=15)

def classify_valid(p):   # classify with 1 retry if Route A flaps
    r = pilot.classify(p, 0)
    if not r["backend_valid"] and r["backend_status"] in (-1, None, 500, 502, 503):
        r = pilot.classify(p, 0)
    return r

sumf = open(f"{OUT}/rq3_sqli_summary.csv", "a", newline="", encoding="utf-8")
sw = csv.writer(sumf)
if sumf.tell() == 0:
    sw.writerow(["strategy","page","seed","n_stress","n_rules","log_valid","log_crsbyp","log_blocked","log_resid","log_block%",
                 "rep_valid","rep_crsbyp","rep_blocked","rep_resid","rep_block%","ver_crsbyp_exploit","ver_resid_exploit","ver_block%","false_bypass","faithful"])
paf = open(f"{OUT}/rq3_sqli_perattack.csv", "a", newline="", encoding="utf-8")
pw = csv.writer(paf)
if paf.tell() == 0:
    pw.writerow(["strategy","page","seed","idx","payload_sha1","backend_valid","crs_status","crs_vtw","rule_status","rule_vtw"])

print(f"=== RQ3 SQLi replay  strategy={STRAT}  page={PAGE} ===")
print(f"{'seed':>4} {'nstr':>4} {'nR':>3} | {'LOG v/cb/blk/res/blk%':>26} | {'REPLAY v/cb/blk/res/blk%':>28} | {'VER cbX/resX/blk%':>20} | fb faithful")
t0 = time.time()
for seed in range(1, 11):
    logp, rulp = paths(seed)
    if not os.path.exists(logp): print(f"{seed:>4}  MISSING {logp}"); continue
    attacks = extract_stress(logp)
    secrules = [l.strip() for l in open(rulp, encoding="utf-8", errors="replace") if l.strip().startswith("SecRule")] if os.path.exists(rulp) else []
    lf = log_funnel(logp)
    # PASS 1 CRS
    reload_with([])
    recs = []
    for i, p in enumerate(attacks, 1):
        r = classify_valid(p)
        recs.append({"i": i, "p": p, "bv": r["backend_valid"], "cb": r["waf_bypassed"], "cvtw": r["valid_through_waf"] is True,
                     "cs": r["waf_status"]})
    valid = [r for r in recs if r["bv"]]
    crs_byp = [r for r in valid if r["cb"]]
    crs_byp_x = [r for r in crs_byp if r["cvtw"]]
    # PASS 2 CRS+rules
    reload_with(secrules)
    for r in crs_byp:
        rr = classify_valid(r["p"])
        r["rb"] = (rr["waf_status"] == 403); r["rs"] = rr["waf_status"]
        r["rvtw"] = (not r["rb"]) and (rr["valid_through_waf"] is True)
    # write per-attack rows (all stress attacks; rule_* only for crs_byp)
    byid = {r["i"]: r for r in crs_byp}
    for r in recs:
        rr = byid.get(r["i"])
        pw.writerow([STRAT, PAGE, seed, r["i"], hashlib.sha1(r["p"].encode("utf-8","replace")).hexdigest()[:16],
                     int(r["bv"]), r["cs"] if r["cs"] is not None else "", int(r["cvtw"]) if r["bv"] and r["cb"] else "",
                     (rr["rs"] if rr and rr["rs"] is not None else ""), (int(rr["rvtw"]) if rr else "")])
    den_rep = len(crs_byp); resid_rep = sum(1 for r in crs_byp if not r["rb"]); block_rep = 100.0*(den_rep-resid_rep)/den_rep if den_rep else 0.0
    den_ver = len(crs_byp_x); resid_ver = sum(1 for r in crs_byp_x if (not r["rb"]) and r["rvtw"]); block_ver = 100.0*(den_ver-resid_ver)/den_ver if den_ver else 0.0
    false_byp = sum(1 for r in crs_byp if (not r["rb"]) and not r["rvtw"])
    blocked_rep = den_rep - resid_rep
    faithful = (len(valid)==lf[1] and den_rep==lf[2] and blocked_rep==lf[3] and resid_rep==lf[4])
    sw.writerow([STRAT,PAGE,seed,len(attacks),len(secrules),lf[1],lf[2],lf[3],lf[4],lf[5],
                 len(valid),den_rep,blocked_rep,resid_rep,round(block_rep,1),den_ver,resid_ver,round(block_ver,1),false_byp,int(faithful)])
    print(f"{seed:>4} {len(attacks):>4} {len(secrules):>3} | {lf[1]:>4}/{lf[2]:>3}/{lf[3]:>3}/{lf[4]:>3}/{lf[5]:>5} | "
          f"{len(valid):>4}/{den_rep:>3}/{blocked_rep:>3}/{resid_rep:>3}/{block_rep:>5.1f} | {den_ver:>4}/{resid_ver:>3}/{block_ver:>5.1f} | {false_byp:>2} {'OK' if faithful else 'MISMATCH'}")
sumf.close(); paf.close()
reload_with([])  # leave CRS-only loaded
print(f"done {STRAT}/{PAGE} in {time.time()-t0:.0f}s")
