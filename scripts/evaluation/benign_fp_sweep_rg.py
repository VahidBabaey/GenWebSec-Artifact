#!/usr/bin/env python3
"""
Benign false-positive sweep for the CG rule sets (RQ4 companion).

For ONE unit = (FAM in {sqli,xss}, TECH in {CG-Adaptive,CG-Static,CRS-only}, EPS, SEED):
  * build the per-seed UNION rule set for that family (union of pages, re-IDed above CRS's
    900000-999999 band) -- identical construction to WorkFlowV2/rq4_replay_heldout.py
  * deploy it (write_rules -> configtest -> reload_apache), then replay EACH benign corpus
    SEPARATELY through the WAF and count blocks (HTTP 403 = false positive), then restore CRS.

Benign corpora (each measured separately):
  sqli rules -> benign_sqli_bwapp_login, benign_sqli_bwapp_search,
                benign_sqli_juice_login, benign_sqli_juice_search   (1000 each)   + CSIC all.csv (8363)
  xss  rules -> benign_xss_bwapp_calc (2000)                                       + CSIC all.csv (8363)

Faithful transport (same as measure_backend_benign_fp_table17.py): GET as-is; POST with the recorded
body + content-type so ModSecurity parses ARGS exactly as in production. blocked = HTTP 403;
transport errors excluded from the numerator; denominator = corpus size; FP% = 100*blocked/total.

Env: FAM, TECH, EPS, SEED.  Outputs under results/V2/A1-A2_BenignTest/{A1|A2}/...
"""
import os, sys, re, csv, json
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import requests

ROOT = "/path/to/GenWebSec"
sys.path.insert(0, ROOT)
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache  # noqa: E402

FAM  = os.environ.get("FAM", "sqli").lower()          # sqli | xss
TECH = os.environ.get("TECH", "CG-Adaptive")          # CG-Adaptive | CG-Static | CRS-only
EPS  = os.environ.get("EPS", "0.3")
SEED = os.environ.get("SEED", "1")

WAFBASE = "http://localhost"
FP_TIMEOUT = 5.0
FP_WORKERS = 8
CONFIGTEST_TIMEOUT = 120.0
MAX_DETAIL = 200                                       # cap FP-sample listing per corpus in the DETAIL file

SECRULE = re.compile(r"^\s*SecRule\b")
IDPAT   = re.compile(r"id:\d+")
DATA    = os.path.join(ROOT, "Data")

SQLI_PAGES = ["login", "search", "product", "filter"]
XSS_PAGES  = ["search", "calc"]

# corpus-key -> list of jsonl files (csic handled specially)
CORPORA = OrderedDict([
    ("sqli", OrderedDict([
        ("bwapp_login",  [f"{DATA}/benign_sqli_bwapp_login.jsonl"]),
        ("bwapp_search", [f"{DATA}/benign_sqli_bwapp_search.jsonl"]),
        ("juice_login",  [f"{DATA}/benign_sqli_juice_login.jsonl"]),
        ("juice_search", [f"{DATA}/benign_sqli_juice_search.jsonl"]),
        ("csic",         ["__csic__"]),
    ])),
    ("xss", OrderedDict([
        ("bwapp_calc",   [f"{DATA}/benign_xss_bwapp_calc.jsonl"]),
        ("csic",         ["__csic__"]),
    ])),
])


def rule_files(fam, tech, seed):
    if fam == "sqli":
        if tech == "CG-Adaptive":
            base = f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps{EPS}_seed{seed}"
            return [(p, f"{base}/C1_customapp_{p}_clustering_rules.txt") for p in SQLI_PAGES]
        if tech == "RG":
            base = f"{ROOT}/results/V2/Random-Groups/CustomApp_D1_eps{EPS}_seed{seed}"
            return [(p, f"{base}/D1_customapp_{p}_random_group_rules.txt") for p in SQLI_PAGES]
        base = f"{ROOT}/results/V2/CustomApp_D1/CustomApp_D1_eps{EPS}_seed{seed}"
        return [(p, f"{base}/D1_customapp_{p}_clustering_rules.txt") for p in SQLI_PAGES]
    else:
        if tech == "CG-Adaptive":
            base = f"{ROOT}/results/V2/CustomApp_C2/CustomXSS_C2_Token_eps{EPS}_seed{seed}"
            return [(p, f"{base}/C2_customxss_{p}_clustering_rules.txt") for p in XSS_PAGES]
        if tech == "RG":
            base = f"{ROOT}/results/V2/Random-Groups/CustomXSS_D2_eps{EPS}_seed{seed}"
            return [(p, f"{base}/D2_customxss_{p}_random_group_rules.txt") for p in XSS_PAGES]
        base = f"{ROOT}/results/V2/CustomApp_D2/CustomXSS_D2_eps{EPS}_seed{seed}"
        return [(p, f"{base}/D2_customxss_{p}_clustering_rules.txt") for p in XSS_PAGES]


def build_ruleset(fam, tech, seed):
    if tech == "CRS-only":
        return [], []
    raw, missing = [], []
    for page, fp in rule_files(fam, tech, seed):
        if not os.path.exists(fp):
            missing.append(os.path.basename(fp)); continue
        with open(fp, encoding="utf-8") as f:
            for line in f:
                if SECRULE.match(line):
                    raw.append((page, line.strip()))
    out, nid = [], 1000001
    for page, r in raw:
        out.append((page, IDPAT.sub(f"id:{nid}", r, count=1))); nid += 1
    return out, missing


def load_corpus(paths):
    recs = []
    for p in paths:
        if p == "__csic__":
            recs.extend(load_csic())
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
    return recs


def load_csic():
    """Adapt Data/all.csv rows to the same transport record shape used for the jsonl corpora."""
    recs = []
    with open(f"{DATA}/all.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            method = str(row["method"]).upper()
            path = str(row["path"])
            q = row.get("query")
            q = None if (q is None or q == "" or str(q).lower() == "nan") else str(q)
            if method == "GET":
                url = WAFBASE + "/" + path.lstrip("/") + (f"?{q}" if q else "")
                recs.append({"method": "GET", "url": url, "body": None, "content_type": None})
            else:
                url = WAFBASE + "/" + path.lstrip("/")
                recs.append({"method": "POST", "url": url, "body": (q or ""),
                             "content_type": "application/x-www-form-urlencoded"})
    return recs


def replay_status(rec, session):
    try:
        if rec["method"] == "GET":
            r = session.get(rec["url"], timeout=FP_TIMEOUT, allow_redirects=False)
        else:
            body = rec.get("body")
            data = body.encode("utf-8") if isinstance(body, str) else body
            headers = {"Content-Type": rec["content_type"]} if rec.get("content_type") else {}
            r = session.post(rec["url"], data=data, headers=headers, timeout=FP_TIMEOUT, allow_redirects=False)
        return r.status_code
    except Exception:
        return None


def _collect_stats(recs, session):
    """Threaded status collection with self-heal for the sporadic CPython METH_METHOD glitch;
    falls back to sequential if the executor keeps glitching. Backends need NOT be up: an
    unblocked request just yields 5xx (backend down) which is a valid status, never a 403."""
    for _ in range(4):
        try:
            with ThreadPoolExecutor(max_workers=FP_WORKERS) as ex:
                return list(ex.map(lambda rc: replay_status(rc, session), recs))
        except SystemError:
            continue
    return [replay_status(rc, session) for rc in recs]   # sequential fallback


def measure_fp(recs, session):
    blocked = err = 0
    fp_samples = []
    stats = _collect_stats(recs, session)
    for rec, st in zip(recs, stats):
        if st == 403:
            blocked += 1
            if len(fp_samples) < MAX_DETAIL:
                fp_samples.append((rec.get("method"), rec.get("url"), rec.get("body")))
        elif st is None:
            err += 1
    total = len(recs)
    rate = 100.0 * blocked / total if total else 0.0
    return blocked, err, total, rate, fp_samples


def set_waf(rules):
    write_rules(rules)
    ok, out = run_configtest(timeout=CONFIGTEST_TIMEOUT)
    if ok:
        reload_apache(timeout=30.0)
    return ok, out


def main():
    fam_dir = "A1" if FAM == "sqli" else "A2"
    outroot = os.path.join(ROOT, "results", "V2", "A1-A2_BenignTest", fam_dir)
    if TECH == "CRS-only":
        outdir = outroot
        stem = f"crs_baseline_{FAM}"
    else:
        outdir = os.path.join(outroot, f"eps{EPS}")
        stem = f"benign_fp_{TECH}_eps{EPS}_seed{SEED}"
    os.makedirs(outdir, exist_ok=True)

    rules, missing = build_ruleset(FAM, TECH, SEED)
    if missing:
        print(f"[warn] {FAM} {TECH} eps{EPS} seed{SEED} missing: {missing}", flush=True)

    corpora_spec = CORPORA[FAM]
    corpora = {ck: load_corpus(paths) for ck, paths in corpora_spec.items()}

    session = requests.Session()
    session.mount("http://", requests.adapters.HTTPAdapter(
        pool_connections=FP_WORKERS, pool_maxsize=FP_WORKERS, max_retries=0))

    print(f"[fp] {FAM} {TECH} eps{EPS} seed{SEED}  rules={len(rules)}  "
          f"corpora={{{', '.join(f'{k}:{len(v)}' for k,v in corpora.items())}}}", flush=True)

    ok, cfgout = set_waf([r for _, r in rules])
    status = "ok" if ok else "configtest_fail"
    results = OrderedDict()
    if ok:
        for ck, recs in corpora.items():
            b = measure_fp(recs, session)
            results[ck] = b
            print(f"    {ck:13}: FP {b[0]:>4}/{b[2]:<5} = {b[3]:6.3f}%  (errors={b[1]})", flush=True)
    else:
        print(f"[fp] CONFIGTEST FAILED ({len(rules)} rules): {cfgout[:200]}", flush=True)

    set_waf([])   # restore CRS-only baseline

    # ---- per-unit CSV ----
    with open(os.path.join(outdir, f"{stem}.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["family", "technique", "eps", "seed", "n_rules", "corpus",
                    "blocked", "errors", "total", "fp_pct", "status"])
        for ck in corpora_spec:
            if ok:
                b = results[ck]
                w.writerow([FAM, TECH, EPS, SEED, len(rules), ck, b[0], b[1], b[2], f"{b[3]:.4f}", "ok"])
            else:
                w.writerow([FAM, TECH, EPS, SEED, len(rules), ck, "", "", len(corpora[ck]), "", "configtest_fail"])

    # ---- rule dump ----
    with open(os.path.join(outdir, f"{stem}_rules.conf"), "w", encoding="utf-8") as f:
        f.write(f"# {FAM} {TECH} eps{EPS} seed{SEED}  union of {len(rules)} rules across pages, re-IDed\n")
        for page, r in rules:
            f.write(f"# from page: {page}\n{r}\n")

    # ---- DETAIL: which benign samples were wrongly blocked ----
    with open(os.path.join(outdir, f"{stem}_DETAIL.txt"), "w", encoding="utf-8") as f:
        f.write("=" * 84 + "\n")
        f.write(f"BENIGN FP DETAIL  |  {FAM} / {TECH} / eps{EPS} / seed{SEED}\n")
        f.write("=" * 84 + "\n")
        f.write(f"Rule set: union of {len(rules)} rules (re-IDed on CRS).  blocked = HTTP 403 = FALSE POSITIVE\n")
        f.write("Faithful transport: GET as-is; POST with recorded body+content-type.\n\n")
        if not ok:
            f.write(f"CONFIGTEST FAILED ({len(rules)} rules): {cfgout[:400]}\n")
        else:
            for ck in corpora_spec:
                b = results[ck]
                f.write("#" * 84 + "\n")
                f.write(f"{ck}  |  FP {b[0]}/{b[2]} = {b[3]:.3f}%  (transport errors={b[1]})\n")
                f.write("#" * 84 + "\n")
                if b[0] == 0:
                    f.write("  no false positives.\n\n")
                    continue
                shown = b[4]
                f.write(f"  wrongly-blocked benign samples ({b[0]} total"
                        + (f", first {len(shown)} shown" if b[0] > len(shown) else "") + "):\n")
                for m, u, body in shown:
                    f.write(f"    {m} {u}" + (f"   body={body}" if body else "") + "\n")
                f.write("\n")

    print(f"[fp] wrote {os.path.join(outdir, stem)}.csv (+ _DETAIL.txt, _rules.conf)", flush=True)


if __name__ == "__main__":
    main()
