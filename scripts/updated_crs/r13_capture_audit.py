#!/usr/bin/env python3
"""R1.3 audit artifact: capture representative CRS 4.29.0 audit records (blocked + passed, both families),
   showing matched rules, anomaly score, and which request fields were inspected. Payloads redacted."""
import subprocess, json, os, time, re, glob, socket, csv
import urllib.request, urllib.parse, urllib.error

ROOT = "/home/vahid/Projects/GenWebSec"
R13 = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3"
OUT = f"{R13}/audit"; os.makedirs(OUT, exist_ok=True)
IMG = "owasp/modsecurity-crs:apache"; HOST = "localhost"

def run(cmd, t=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=t); return r.returncode, r.stdout, r.stderr

def listening(p):
    s = socket.socket(); s.settimeout(0.3)
    try: s.connect(("127.0.0.1", p)); s.close(); return True
    except Exception: return False

# 1) audit containers with full audit (AUDIT_ENGINE=On -> logs passed requests too)
AUD = [("crs-audit-sqli", 8087, "http://127.0.0.1:8080", 8446),
       ("crs-audit-xss", 8089, "http://127.0.0.1:8096", 8447)]
for name, port, backend, ssl in AUD:
    run(["docker", "rm", "-f", name])
    run(["docker", "run", "-d", "--name", name, "--network", "host",
         "-e", f"PORT={port}", "-e", f"SSL_PORT={ssl}", "-e", f"BACKEND={backend}",
         "-e", "BLOCKING_PARANOIA=1", "-e", "ANOMALY_INBOUND=5", "-e", "ANOMALY_OUTBOUND=4",
         "-e", "MODSEC_RULE_ENGINE=on", "-e", "MODSEC_AUDIT_ENGINE=On",
         "-e", "MODSEC_AUDIT_LOG=/dev/stdout", "-e", "MODSEC_AUDIT_LOG_FORMAT=JSON",
         "-e", "SERVER_NAME=localhost", IMG])
for _, port, _, _ in AUD:
    for _ in range(60):
        if listening(port): break
        time.sleep(0.25)

SQLI = "http://127.0.0.1:8087"; XSS = "http://127.0.0.1:8089"

def first_bypass(fam, page):
    try:
        for line in open(f"{R13}/attack_replay/still_bypassing_raw_PRIVATE.txt", encoding="utf-8", errors="replace"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 5 and parts[0] == fam and parts[1] == page:
                return "\t".join(parts[4:])
    except Exception:
        pass
    return None

def first_winner(pattern):
    for ff in sorted(glob.glob(pattern)):
        for line in open(ff, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                return line
    return None

sqli_byp = first_bypass("sqli", "login")   # real payload read at runtime from the unpublished winners; none hardcoded
xss_byp = first_bypass("xss", "calc")
sqli_blk = first_winner(f"{ROOT}/results/V2/CustomApp_A1/*A1_CRSonly_seed1/A1_customapp_search_winners.txt")
xss_blk = first_winner(f"{ROOT}/results/V2/CustomApp_A2/*A2_CRSonly_seed1/A2_customxss_search_winners.txt")

CUR = [
    ("sqli", "canonical-attack", SQLI, "product", "id", "GET", {}, "1' OR '1'='1"),
    ("sqli", "real-attack-blocked", SQLI, "search", "q", "GET", {}, sqli_blk),
    ("sqli", "real-attack-still-bypassing", SQLI, "login", "username", "POST", {"password": "x"}, sqli_byp),
    ("sqli", "benign", SQLI, "product", "id", "GET", {}, "2"),
    ("xss", "canonical-attack", XSS, "search.php", "q", "GET", {}, "<script>alert(1)</script>"),
    ("xss", "real-attack-blocked", XSS, "search.php", "q", "GET", {}, xss_blk),
    ("xss", "real-attack-still-bypassing", XSS, "calc.php", "expr", "GET", {}, xss_byp),
    ("xss", "benign", XSS, "search.php", "q", "GET", {}, "hello world"),
]

def send(base, route, param, payload, method, extra):
    params = dict(extra); params[param] = payload
    data = urllib.parse.urlencode(params)
    hdr = {"Host": HOST}
    try:
        if method == "GET":
            req = urllib.request.Request(f"{base}/{route}?{data}", headers=hdr)
        else:
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
            req = urllib.request.Request(f"{base}/{route}", data=data.encode(), method="POST", headers=hdr)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1

def last_audit(container):
    _, out, err = run(["docker", "logs", "--tail", "12", container])
    for l in reversed((out + "\n" + err).splitlines()):
        if l.strip().startswith("{") and '"audit_data"' in l:
            try: return json.loads(l)
            except Exception: pass
    return None

FIELD_RE = re.compile(r'(?:at|within) ((?:ARGS|ARGS_NAMES|REQUEST_HEADERS|REQUEST_COOKIES|REQUEST_BODY|REQUEST_URI|REQUEST_FILENAME|TX|MATCHED_VAR)[:A-Za-z0-9_\.\-]*)')
def parse_msgs(j):
    msgs = j.get("audit_data", {}).get("messages", []) or []
    rules = []; fields = set(); score = None
    for m in msgs:
        rid = (re.search(r'\[id "(\d+)"\]', m) or [None, None])[1]
        msg = (re.search(r'\[msg "([^"]+)"\]', m) or [None, None])[1]
        for f in FIELD_RE.findall(m):
            fields.add(f)
        if rid:
            rules.append((rid, msg))
        sc = re.search(r'Total Score: (\d+)', m) or re.search(r'blocking=(\d+)', m)
        if sc:
            score = sc.group(1)
    return rules, sorted(fields), score

cont = {"sqli": "crs-audit-sqli", "xss": "crs-audit-xss"}
rows = []; samples = []
for fam, label, base, route, param, method, extra, payload in CUR:
    if payload is None:
        continue
    st = send(base, route, param, payload, method, extra)
    time.sleep(0.7)
    j = last_audit(cont[fam])
    if not j:
        rows.append([fam, label, route, st, "NO-AUDIT", "", ""]); continue
    rules, fields, score = parse_msgs(j)
    rows.append([fam, label, route, st, ";".join(r[0] for r in rules), score or "", ",".join(fields)])
    # redacted sample
    jj = json.loads(json.dumps(j))
    rl = jj.get("request", {}).get("request_line", "")
    if "?" in rl:
        jj["request"]["request_line"] = re.sub(r'(\?)\S*', r'\1[REDACTED_QUERY]', rl)
    if "body" in jj.get("request", {}):
        jj["request"]["body"] = "[REDACTED]"
    jj["audit_data"]["messages"] = [re.sub(r'\[data "[^"]*"\]', '[data "[REDACTED]"]', m)
                                    for m in jj.get("audit_data", {}).get("messages", [])]
    jj.get("audit_data", {}).pop("error_messages", None)        # duplicate of messages; carries raw Matched Data
    if isinstance(jj.get("response"), dict) and "body" in jj["response"]:
        jj["response"]["body"] = "[REDACTED: response body]"     # passed requests reflect the payload
    jj = {"_label": label, "_family": fam, "_status": st, **jj}
    samples.append(jj)

with open(f"{OUT}/audit_summary.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["family", "label", "endpoint", "status", "matched_rule_ids", "inbound_anomaly_score", "inspected_fields"])
    for r in rows:
        w.writerow(r); print(" ", r)
with open(f"{OUT}/audit_sample_redacted.jsonl", "w", encoding="utf-8") as fh:
    for s in samples:
        fh.write(json.dumps(s) + "\n")

for name, *_ in AUD:
    run(["docker", "rm", "-f", name])
print("\nwrote", f"{OUT}/audit_summary.csv", "and audit_sample_redacted.jsonl")
