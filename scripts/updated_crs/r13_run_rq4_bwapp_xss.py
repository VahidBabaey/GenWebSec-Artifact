#!/usr/bin/env python3
"""R1.3 (extension): replay the RQ4 held-out bwApp XSS attacks (xss_eval, valid + CRS-3.3.2-bypassing)
   through CRS 4.29.0. XSS can be blocked inbound OR outbound, so this routes through a dedicated crs-bwapp
   container to the REAL bwApp backend with a bee/bug session (full inbound+outbound pipeline, as the study).
   Status-only: 403 = blocked by updated CRS, non-403 = still bypasses."""
import urllib.request, urllib.parse, urllib.error, http.cookiejar, subprocess, socket, time, os, csv, re, glob, hashlib, collections
from concurrent.futures import ThreadPoolExecutor, as_completed

CRS = "http://127.0.0.1:8090"          # crs-bwapp -> real bwApp :8082
HOST = "localhost"
ROOT = "/home/vahid/Projects/GenWebSec"
OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/rq4_bwapp_juice"
os.makedirs(OUT, exist_ok=True)
IMG = "owasp/modsecurity-crs:apache"

def run(cmd, t=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=t); return r.returncode, r.stdout, r.stderr

def listening(p):
    s = socket.socket(); s.settimeout(0.3)
    try: s.connect(("127.0.0.1", p)); s.close(); return True
    except Exception: return False

# 1) deploy crs-bwapp (host net -> real bwApp :8082)
run(["docker", "rm", "-f", "crs-bwapp"])
run(["docker", "run", "-d", "--name", "crs-bwapp", "--network", "host",
     "-e", "PORT=8090", "-e", "SSL_PORT=8448", "-e", "BACKEND=http://127.0.0.1:8082",
     "-e", "BLOCKING_PARANOIA=1", "-e", "ANOMALY_INBOUND=5", "-e", "ANOMALY_OUTBOUND=4",
     "-e", "MODSEC_RULE_ENGINE=on", "-e", "MODSEC_AUDIT_ENGINE=RelevantOnly",
     "-e", "MODSEC_AUDIT_LOG=/dev/stdout", "-e", "MODSEC_AUDIT_LOG_FORMAT=JSON", "-e", "SERVER_NAME=localhost", IMG])
for _ in range(60):
    if listening(8090): break
    time.sleep(0.25)
print("crs-bwapp :8090 listening:", listening(8090))

# 2) login through the CRS container to get a bee/bug (security low) session
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
login_body = urllib.parse.urlencode({"login": "bee", "password": "bug", "security_level": "0", "form": "submit"}).encode()
try:
    req = urllib.request.Request(f"{CRS}/login.php", data=login_body, method="POST",
                                 headers={"Host": HOST, "Content-Type": "application/x-www-form-urlencoded"})
    opener.open(req, timeout=15).read()
except Exception as e:
    print("login warn:", e)
cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in jar)
print("session cookies:", cookie_hdr[:80])

def get(url, cookie=True):
    hdr = {"Host": HOST}
    if cookie and cookie_hdr:
        hdr["Cookie"] = cookie_hdr
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=12) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)[:40]

# 3) session_ok + confirm CRS inspects ARGS:date (canonical -> 403)
st, body = get(f"{CRS}/xss_eval.php?date=2")
print(f"session_ok: status={st} looks_like_page={'date' in body.lower() or 'xss' in body.lower()}")
for canon in ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>']:
    cst, _ = get(f"{CRS}/xss_eval.php?date=" + urllib.parse.quote(canon, safe=""))
    print(f"canonical XSS -> {cst}  <= {canon}")

# 4) load held-out bwApp xss_eval winners (seeds 1-5), dedupe
seen = set(); lines = 0
for f in sorted(glob.glob(f"{ROOT}/results/V2/A2_HeldOut/A2_bwapp_heldout_seed*/A2_bwapp_xss_eval_winners.txt")):
    for line in open(f, encoding="utf-8", errors="replace"):
        s = line.rstrip("\n")
        if s and not s.startswith("#"):
            lines += 1; seen.add(s)
payloads = sorted(seen)
print(f"bwapp xss_eval held-out: lines={lines}  distinct={len(payloads)}")

def probe(payload):
    url = f"{CRS}/xss_eval.php?date=" + urllib.parse.quote(payload, safe="")
    st, _ = get(url)
    return (payload, st)

results = []; done = 0
with ThreadPoolExecutor(max_workers=8) as ex:
    futs = [ex.submit(probe, p) for p in payloads]
    for fu in as_completed(futs):
        results.append(fu.result()); done += 1
        if done % 300 == 0:
            print(f"  ...{done}/{len(payloads)}")

# per-request CSV (hashed) + still-bypassing
per = f"{OUT}/rq4_bwapp_xss_through_crs429_perrequest.csv"
with open(per, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["target", "page", "payload_sha1", "status", "blocked_by_crs429"])
    for payload, st in sorted(results, key=lambda r: r[1]):
        w.writerow(["bwapp", "xss_eval", hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:16], st, int(st == 403)])
with open(f"{OUT}/rq4_bwapp_xss_still_bypassing_PRIVATE.txt", "w", encoding="utf-8") as fh:
    for payload, st in results:
        if st != 403:
            fh.write(f"{st}\t{payload}\n")

n = len(results); blk = sum(1 for _, st in results if st == 403); byp = n - blk
dist = dict(collections.Counter(st for _, st in results))
summ = f"{OUT}/rq4_bwapp_xss_through_crs429_summary.csv"
with open(summ, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["scope", "n_distinct", "blocked_crs429", "still_bypassing", "block_rate_pct", "persistence_pct", "status_dist"])
    w.writerow(["bwapp:xss_eval", n, blk, byp, f"{100.0*blk/n if n else 0:.2f}", f"{100.0*byp/n if n else 0:.2f}", dist])
print(f"\nbwapp:xss_eval  n={n}  blocked={blk}  still_bypass={byp}  block%={100.0*blk/n if n else 0:.2f}  dist={dist}")
print("per-request ->", per); print("summary ->", summ); print("== bwapp XSS replay done ==")
