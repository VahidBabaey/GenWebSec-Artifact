#!/usr/bin/env python3
"""R1.1 item 5: WAF audit-log capture. Enables ModSecurity audit logging (SecAuditEngine On) via the
vahid-writable sft_rule.conf, with CRS + a CG-Adaptive customapp rule set loaded, then replays a small
REPRESENTATIVE set of requests through the WAF:
  benign              -> HTTP 200 passed (no rule match)
  classic SQLi/XSS    -> HTTP 403 blocked by CRS
  held-out winner     -> HTTP 403 blocked by OUR custom rule (id 1000xxx)
  eval-sink alert(1)  -> HTTP 200 passed-but-exploit (bypasses CRS)
It then parses the Serial audit log and writes a REDACTED per-request summary (status, matched rule ids +
messages, CRS vs custom, deny action) with raw payloads removed, demonstrating the log distinguishes
blocking from other responses. Restores SecAuditEngine Off afterward. Audit log -> /var/cache/modsecurity
(www-data writes, vahid reads via the www-data group); unique filename per run (the file can't be truncated)."""
import os, sys, re, csv, urllib.request, urllib.parse, urllib.error
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import importlib, time
mh = importlib.import_module("helpers.modsec_helpers")
write_rules, run_configtest, reload_apache = mh.write_rules, mh.run_configtest, mh.reload_apache

# Serial audit log is opened by the Apache MASTER (root), which bypasses the 0750 on /home/vahid; by
# pre-creating the file as vahid we keep it vahid-owned (root O_APPENDs, ownership unchanged) so we can
# read it back. (/tmp fails under systemd PrivateTmp; /var/cache/modsecurity ends up root:root 0640.)
os.makedirs("/home/vahid/rq4_audit", exist_ok=True)
AUDIT = "/home/vahid/rq4_audit/audit.log"
open(AUDIT, "w").close(); os.chmod(AUDIT, 0o666)
OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.1/waf_logs"
os.makedirs(OUT, exist_ok=True)
PROXY = [
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]
AUDIT_DIRECTIVES = [
    "SecAuditEngine On",
    "SecAuditLogType Serial",
    f"SecAuditLog {AUDIT}",
    "SecAuditLogParts ABHZ",
]

def reload_with(extra):
    write_rules(AUDIT_DIRECTIVES + PROXY + extra)
    ok, out = run_configtest()
    if not ok:
        print("CONFIGTEST FAIL:", out[:300]); sys.exit(1)
    reload_apache(timeout=30)

def req(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1

def cg_rules():
    base = f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps0.3_seed10"
    out, nid = [], 1000001
    for p in ("login", "search", "product", "filter"):
        fp = f"{base}/C1_customapp_{p}_clustering_rules.txt"
        if os.path.exists(fp):
            for ln in open(fp, encoding="utf-8", errors="replace"):
                if ln.strip().startswith("SecRule"):
                    out.append(re.sub(r"id:\d+", f"id:{nid}", ln.strip(), count=1)); nid += 1
    return out

def winners(n=6):
    f = f"{ROOT}/results/V2/A1_HeldOut/A1_customapp_heldout_seed1/A1_customapp_search_winners.txt"
    out = []
    for ln in open(f, encoding="utf-8", errors="replace"):
        s = ln.rstrip("\n")
        if s and not s.startswith("#"):
            out.append(s)
        if len(out) >= n: break
    return out

E = urllib.parse.urlencode
REQS = [
    ("benign_sqli_product",  "/customapp/product?id=1"),
    ("benign_xss_calc",      "/customxss/calc.php?expr=2"),
    ("attack_sqli_crs",      "/customapp/search?" + E({"q": "' OR '1'='1"})),
    ("attack_xss_crs",       "/customxss/search.php?" + E({"q": "<script>alert(1)</script>"})),
    ("attack_xss_eval_bypass","/customxss/calc.php?" + E({"expr": "alert(1)"})),
] + [(f"heldout_winner_{i}", "/customapp/search?" + E({"q": p})) for i, p in enumerate(winners(6), 1)]

_BND = re.compile(r"^--([0-9a-fA-F]+)-([A-Z])--\s*$")
def parse_audit(path):
    txns, cur, part = [], None, None
    if not os.path.exists(path): return txns
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = _BND.match(ln)
        if m:
            letter = m.group(2)
            if letter == "A":
                if cur is not None: txns.append(cur)
                cur = {}
            if cur is None: cur = {}
            part = letter; cur[part] = ""
            continue
        if part is not None and cur is not None:
            cur[part] += ln
    if cur: txns.append(cur)
    return txns

def summarize(txn):
    H = txn.get("H", ""); B = txn.get("B", "")
    ids = re.findall(r'\[id "(\d+)"\]', H)
    msgs = re.findall(r'\[msg "([^"]*)"\]', H)
    denied = ("Access denied" in H)
    reqline = (B.splitlines() or [""])[0]
    reqline = re.sub(r"\?\S*", "?<redacted>", reqline)
    crs = sorted({i for i in ids if i.startswith("9")})
    custom = sorted({i for i in ids if i.startswith("1000")})
    return {"request_line_redacted": reqline.strip()[:90],
            "all_rule_ids": ",".join(sorted(set(ids))), "crs_rules": ",".join(crs),
            "custom_rules": ",".join(custom), "n_msgs": len(msgs),
            "access_denied": int(denied), "sample_msgs": " | ".join(sorted(set(msgs))[:3])}

print("=== item 5: WAF audit-log capture ===")
cg = cg_rules()
print(f"loaded {len(cg)} CG-Adaptive customapp rules (eps0.3 seed10) + audit on")
try:
    reload_with(cg)
    statuses = []
    for lbl, path in REQS:
        st = req("http://localhost" + path)
        statuses.append((lbl, st))
        print(f"  {lbl:<24} -> HTTP {st}")
    time.sleep(1.2)
    txns = parse_audit(AUDIT)
    print(f"audit transactions logged: {len(txns)} (requests sent: {len(REQS)})  audit perms: {oct(os.stat(AUDIT).st_mode)[-3:]}")
finally:
    write_rules(PROXY); run_configtest(); reload_apache(timeout=30)
    print("[restore] SecAuditEngine Off (sft_rule.conf -> proxy only)")

# match each audit transaction to its request by exact URL target (robust to the reload readiness probe)
def txn_target(t):
    first = (t.get("B", "").splitlines() or [""])[0]
    m = re.match(r'^(?:GET|POST)\s+(\S+)\s+HTTP', first)
    return m.group(1) if m else None
sent = {path: (lbl, st) for (lbl, path), (lbl2, st) in zip(REQS, statuses)}
matched = []   # (label, status, txn) in REQS order
by_target = {}
for t in txns:
    tg = txn_target(t)
    if tg in sent and tg not in by_target:
        by_target[tg] = t
for lbl, path in REQS:
    t = by_target.get(path)
    matched.append((lbl, sent[path][1], t))

with open(f"{OUT}/audit_summary.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["label","http_status","access_denied","crs_rules","custom_rules","n_msgs","request_line_redacted","sample_msgs"])
    for lbl, st, t in matched:
        s = summarize(t) if t else {"access_denied":"", "crs_rules":"", "custom_rules":"", "n_msgs":"", "request_line_redacted":"(no audit txn)", "sample_msgs":""}
        w.writerow([lbl, st, s["access_denied"], s["crs_rules"], s["custom_rules"], s["n_msgs"], s["request_line_redacted"], s["sample_msgs"]])

with open(f"{OUT}/audit_H_parts_redacted.txt", "w", encoding="utf-8") as f:
    for lbl, st, t in matched:
        f.write(f"===== {lbl}  HTTP {st} =====\n")
        if t:
            H = t.get("H", "")
            H = re.sub(r'\[data "[^"]*"\]', '[data "<redacted>"]', H)   # strip matched payload data
            H = re.sub(r'\[uri "[^"]*"\]', '[uri "<redacted>"]', H)
            f.write(H.strip() + "\n\n")

print(f"wrote {OUT}/audit_summary.csv and audit_H_parts_redacted.txt")
