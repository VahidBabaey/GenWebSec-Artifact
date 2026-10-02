#!/usr/bin/env python3
"""R1.3: deploy two CRS 4.29.0 containers (host net) as reverse proxies to the real backends.
   crs-sqli :8081 -> customapp :8080 ;  crs-xss :8086 -> php customxss docroot :8096
   Config pinned to the baseline: PL1, inbound anomaly 5, outbound 4, rule engine on."""
import subprocess, socket, time, urllib.request, urllib.error

DOCROOT = "/home/vahid/Projects/GenWebSec/customxss"
IMG = "owasp/modsecurity-crs:apache"

def run(cmd, t=180):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
    return r.returncode, r.stdout, r.stderr

def listening(p):
    s = socket.socket(); s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", p)); s.close(); return True
    except Exception:
        return False

def http(url, t=6):
    try:
        with urllib.request.urlopen(url, timeout=t) as r:
            return r.status, r.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)[:90]

# 1) dedicated XSS backend on 8096 (serves whole customxss docroot: search.php + calc.php)
if not listening(8096):
    subprocess.Popen(["php", "-S", "127.0.0.1:8096", "-t", DOCROOT],
                     stdout=open("/tmp/r13_xss8096.log", "ab"), stderr=subprocess.STDOUT,
                     start_new_session=True)
    for _ in range(40):
        if listening(8096): break
        time.sleep(0.25)
print("xss backend :8096 =", "UP" if listening(8096) else "DOWN")

# 2) tear down any prior R1.3 containers (idempotent)
for name in ["crs-sqli", "crs-xss"]:
    run(["docker", "rm", "-f", name])

common = ["-e", "BLOCKING_PARANOIA=1", "-e", "ANOMALY_INBOUND=5", "-e", "ANOMALY_OUTBOUND=4",
          "-e", "MODSEC_RULE_ENGINE=on", "-e", "MODSEC_AUDIT_ENGINE=RelevantOnly",
          "-e", "MODSEC_AUDIT_LOG=/dev/stdout", "-e", "MODSEC_AUDIT_LOG_FORMAT=JSON",
          "-e", "SERVER_NAME=localhost"]

rc, out, err = run(["docker", "run", "-d", "--name", "crs-sqli", "--network", "host",
                    "-e", "PORT=8081", "-e", "SSL_PORT=8444", "-e", "BACKEND=http://127.0.0.1:8080"]
                   + common + [IMG])
print("crs-sqli run rc", rc, (out.strip()[:20] if rc == 0 else err[:300]))

rc, out, err = run(["docker", "run", "-d", "--name", "crs-xss", "--network", "host",
                    "-e", "PORT=8086", "-e", "SSL_PORT=8445", "-e", "BACKEND=http://127.0.0.1:8096"]
                   + common + [IMG])
print("crs-xss  run rc", rc, (out.strip()[:20] if rc == 0 else err[:300]))

# 3) wait for both to listen
for p in (8081, 8086):
    ok = False
    for _ in range(60):
        if listening(p): ok = True; break
        time.sleep(0.25)
    print(f"port {p}:", "LISTENING" if ok else "NOT LISTENING")

print("\n== docker ps ==")
print(run(["docker", "ps", "--format", "{{.Names}}  {{.Status}}  net={{.Networks}}"])[1])

for name in ["crs-sqli", "crs-xss"]:
    print(f"\n== logs {name} (tail 12) ==")
    rc, out, err = run(["docker", "logs", "--tail", "12", name])
    print((out or "")[-1200:])
    print((err or "")[-400:])

# 4) prove the proxy->backend path works with a BENIGN request through each container
print("\n== reachability through the CRS containers (benign) ==")
st, b = http("http://127.0.0.1:8081/product?id=2")
print(f"  crs-sqli /product?id=2 -> {st}  oracle_marker={'<!--ORACLE' in b}")
st, b = http("http://127.0.0.1:8086/search.php?q=hello")
print(f"  crs-xss  /search.php?q=hello -> {st}  len={len(b)}")
st, b = http("http://127.0.0.1:8086/calc.php?expr=2%2B2")
print(f"  crs-xss  /calc.php?expr=2+2 -> {st}  len={len(b)}")
print("== done ==")
