#!/usr/bin/env python3
"""R1.1 RQ4 two-stage re-verification (residual bypasses, eps0.3), one (target, page) per process.
Env: A1_TARGET in {customapp,bwapp,juice}, A1_PAGE.

The original RQ4 replay recorded, per (ruleset, held-out winner), blocked (HTTP 403) vs bypassed. Here
we take the RESIDUAL bypasses under the two defenses (technique in {CG-Adaptive, CG-Static}, blocked==0)
from those per-attack CSVs, reload each ruleset, and re-probe exactly those winners through the WAF with
the exploit oracle (pilot.probe -> status + valid). A residual that is not-403 but whose exploit does
NOT fire through the WAF is a FALSE bypass. Reports, per ruleset, reported vs verified residual bypasses.
Resumable: (target,page,technique,cg_seed) already summarized are skipped.
"""
import os, sys, re, csv, glob, hashlib
from collections import defaultdict
os.environ.setdefault("A1_TARGET", "customapp")
os.environ.setdefault("A1_PAGE", "login")
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import importlib, time as _t
pilot = mh = None
for _ in range(10):
    try:
        pilot = importlib.import_module("pilot_A1_sqli_attack_only_v2")
        mh = importlib.import_module("helpers.modsec_helpers"); break
    except (SystemError, ImportError):
        pilot = None; _t.sleep(1)
if pilot is None:
    raise SystemExit("pilot import failed after retries")
pilot.log_print = lambda *a, **k: None
write_rules, run_configtest, reload_apache = mh.write_rules, mh.run_configtest, mh.reload_apache

TARGET = os.environ["A1_TARGET"]; PAGE = os.environ["A1_PAGE"]
EPS = "0.3"
RULE_PAGES = ["login", "search", "product", "filter"]   # ruleset = union of custom-app pages, re-IDed
SECRULE = re.compile(r"^\s*SecRule\b"); IDPAT = re.compile(r"id:\d+")

def rule_files(tech, seed):
    if tech == "CG-Adaptive":
        base = f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps{EPS}_seed{seed}"
        return [f"{base}/C1_customapp_{p}_clustering_rules.txt" for p in RULE_PAGES]
    base = f"{ROOT}/results/V2/CustomApp_D1/CustomApp_D1_eps{EPS}_seed{seed}"
    return [f"{base}/D1_customapp_{p}_clustering_rules.txt" for p in RULE_PAGES]

def build_ruleset(tech, seed):
    raw = []
    for fp in rule_files(tech, seed):
        if os.path.exists(fp):
            for line in open(fp, encoding="utf-8", errors="replace"):
                if SECRULE.match(line):
                    raw.append(line.strip())
    out, nid = [], 1000001
    for r in raw:
        out.append(IDPAT.sub(f"id:{nid}", r, count=1)); nid += 1
    return out

def reload_with(rules):
    write_rules(rules); ok, out = run_configtest()
    if not ok: print("  !! CONFIGTEST FAIL", out[:120])
    reload_apache(timeout=30)

# collect residual bypasses for this (target,page) from the eps0.3 per-attack CSVs
GLOB = f"{ROOT}/results/V2/A1_HeldOut/A1_{TARGET}_heldout_seed*/Defense_results/rq4_replay_{TARGET}_{PAGE}_seed*_perattack.csv"
files = [f for f in glob.glob(GLOB) if "/eps0." not in f]
byp = defaultdict(list)   # (technique, cg_seed) -> [(attack_seed, attack_idx, payload)]
for f in files:
    ma = re.search(r"_seed(\d+)_perattack", f); aseed = ma.group(1) if ma else "?"
    with open(f, encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            if row["technique"] in ("CG-Adaptive", "CG-Static") and row["blocked"] == "0":
                byp[(row["technique"], row["cg_seed"])].append((aseed, row["attack_idx"], row["payload"]))
print(f"[{TARGET}/{PAGE}] residual-bypass groups: {len(byp)}  total residual bypasses: {sum(len(v) for v in byp.values())}", flush=True)

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq4"
os.makedirs(OUT, exist_ok=True)
sumpath = f"{OUT}/rq4_sqli_summary.csv"
done = set()
if os.path.exists(sumpath):
    for r in csv.DictReader(open(sumpath)):
        done.add((r["target"], r["page"], r["technique"], r["cg_seed"]))
sumf = open(sumpath, "a", newline="", encoding="utf-8"); sw = csv.writer(sumf)
if sumf.tell() == 0:
    sw.writerow(["target","page","technique","cg_seed","reported_bypasses","reprobe_not403","verified_exploit","false_bypass","now_403"])
    sumf.flush()
detf = open(f"{OUT}/rq4_sqli_false_bypasses.csv", "a", newline="", encoding="utf-8"); dw = csv.writer(detf)
if detf.tell() == 0:
    dw.writerow(["target","page","technique","cg_seed","attack_seed","attack_idx","payload_sha1","waf_status","reason"]); detf.flush()
prf = open(f"{OUT}/rq4_sqli_perrequest.csv", "a", newline="", encoding="utf-8"); pw = csv.writer(prf)
if prf.tell() == 0:
    pw.writerow(["target","page","technique","cg_seed","attack_seed","attack_idx","payload_sha1","waf_status","exploit_through_waf"]); prf.flush()

if TARGET == "bwapp":
    try: pilot.establish_session()
    except Exception as e: print("  bwapp session warn:", e)
    # bwApp's docker-start recovery fails on this host (iptable_raw); the backend is assumed up (started
    # after `modprobe iptable_raw`). customapp (no docker) and juice (docker-start works) keep the real
    # recovery path, so a juice crash is recovered mid-run instead of corrupting probe results.
    pilot.ensure_backend_up = (lambda *a, **k: True)

print(f"=== RQ4 re-verify  target={TARGET} page={PAGE}  WAF={pilot.WAF} ===", flush=True)
for (tech, cg_seed) in sorted(byp):
    if (TARGET, PAGE, tech, cg_seed) in done:
        print(f"  {tech} seed{cg_seed}: (done, skip)"); continue
    rules = build_ruleset(tech, cg_seed)
    if not rules:
        print(f"  {tech} seed{cg_seed}: NO RULES built (path?) — skip"); continue
    reload_with(rules)
    if TARGET == "bwapp" and not pilot.session_ok():   # refresh the bee/bug session once per group (stable within a group)
        try: pilot.establish_session()
        except Exception: pass
    winners = byp[(tech, cg_seed)]
    not403 = exploit = false_b = now403 = 0
    for aseed, idx, p in winners:
        pb = pilot.probe(pilot.WAF, p)
        st = pb["status"]
        h = hashlib.sha1(p.encode("utf-8","replace")).hexdigest()[:16]
        if st == 403:
            now403 += 1
            pw.writerow([TARGET, PAGE, tech, cg_seed, aseed, idx, h, st, ""])
            continue
        not403 += 1
        ex = 1 if pb["valid"] else 0
        pw.writerow([TARGET, PAGE, tech, cg_seed, aseed, idx, h, st, ex])
        if pb["valid"]:
            exploit += 1
        else:
            false_b += 1
            dw.writerow([TARGET, PAGE, tech, cg_seed, aseed, idx, h, st, "not403_no_exploit"]); detf.flush()
    prf.flush()
    sw.writerow([TARGET, PAGE, tech, cg_seed, len(winners), not403, exploit, false_b, now403]); sumf.flush()
    print(f"  {tech} seed{cg_seed}: reported={len(winners):>4} not403={not403:>4} exploit={exploit:>4} false={false_b:>3} now403={now403:>3}", flush=True)

sumf.close(); detf.close(); prf.close()
reload_with([])
print(f"done {TARGET}/{PAGE}", flush=True)
