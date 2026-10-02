#!/usr/bin/env python3
"""R1.3 artifact: capture updated-CRS container + configuration metadata (advisor requirement)."""
import subprocess, json, os

ROOT = "/home/vahid/Projects/GenWebSec"
OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/metadata"
os.makedirs(OUT, exist_ok=True)
IMG = "owasp/modsecurity-crs:apache"

def run(cmd, t=60):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
    return r.stdout, r.stderr

lines = []
def L(s): lines.append(s); print(s)

L("# R1.3 updated-CRS container & configuration metadata")
L("")
L("## Image")
out, _ = run(["docker", "inspect", "--format", "{{.Id}}", IMG]); L(f"image_ref      : {IMG}")
L(f"image_id       : {out.strip()}")
out, _ = run(["docker", "inspect", "--format", "{{index .RepoDigests 0}}", IMG]); L(f"repo_digest    : {out.strip()}")

L("")
L("## Versions (read from inside the image / a live audit record)")
out, _ = run(["docker", "run", "--rm", "--entrypoint", "head", IMG, "-n", "2", "/etc/modsecurity.d/owasp-crs/crs-setup.conf"])
crsver = [l for l in out.splitlines() if "ver." in l.lower()]
L(f"crs_version    : {crsver[0].strip() if crsver else out.strip()}")
out, _ = run(["docker", "exec", "crs-sqli", "httpd", "-v"]); L(f"httpd_version  : {out.strip().splitlines()[0] if out.strip() else '?'}")
# ModSecurity engine version from a fresh audit 'producer' field
import urllib.request, urllib.error, time
try:
    req = urllib.request.Request("http://127.0.0.1:8081/product?id=1%27+OR+%271%27%3D%271", headers={"Host": "localhost"})
    try:
        urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError:
        pass
    time.sleep(1)
    lg, _ = run(["docker", "logs", "--tail", "40", "crs-sqli"])
    prod = None
    for l in lg.splitlines():
        if l.strip().startswith("{") and "producer" in l:
            prod = json.loads(l).get("audit_data", {}).get("producer")
    L(f"engine_producer: {prod}")
except Exception as e:
    L(f"engine_producer: (note {e})")

L("")
L("## Applied configuration (from docker inspect of the running containers)")
for name in ["crs-sqli", "crs-xss"]:
    out, _ = run(["docker", "inspect", name])
    info = json.loads(out)[0]
    env = info["Config"]["Env"]
    knobs = [e for e in env if any(k in e for k in ["BLOCKING_PARANOIA", "DETECTION_PARANOIA", "ANOMALY_INBOUND",
             "ANOMALY_OUTBOUND", "MODSEC_RULE_ENGINE", "MODSEC_AUDIT_ENGINE", "MODSEC_REQ_BODY_ACCESS",
             "MODSEC_RESP_BODY_ACCESS", "BACKEND=", "PORT=", "SSL_PORT="])]
    net = info.get("HostConfig", {}).get("NetworkMode")
    L(f"### {name}  (network={net})")
    for e in sorted(knobs):
        L(f"   {e}")

L("")
L("## Reverse-proxy wiring")
L("   crs-sqli :8081  --proxy-->  http://127.0.0.1:8080   (customapp SQLi backend, clean routes /login /search /product /filter)")
L("   crs-xss  :8086  --proxy-->  http://127.0.0.1:8096   (php -S serving the customxss docroot: search.php, calc.php)")
L("   All replay requests sent with HTTP header 'Host: localhost' to match the CRS-3.3.2 baseline")
L("   (avoids CRS rule 920350 'Host header is a numeric IP address', a +3 anomaly artifact of connecting via 127.0.0.1).")

L("")
L("## Exact docker run commands (reproducible)")
L("   docker run -d --name crs-sqli --network host \\")
L("     -e PORT=8081 -e SSL_PORT=8444 -e BACKEND=http://127.0.0.1:8080 \\")
L("     -e BLOCKING_PARANOIA=1 -e ANOMALY_INBOUND=5 -e ANOMALY_OUTBOUND=4 \\")
L("     -e MODSEC_RULE_ENGINE=on -e MODSEC_AUDIT_ENGINE=RelevantOnly \\")
L("     -e MODSEC_AUDIT_LOG=/dev/stdout -e MODSEC_AUDIT_LOG_FORMAT=JSON -e SERVER_NAME=localhost \\")
L("     owasp/modsecurity-crs:apache")
L("   docker run -d --name crs-xss  --network host \\")
L("     -e PORT=8086 -e SSL_PORT=8445 -e BACKEND=http://127.0.0.1:8096 \\")
L("     -e BLOCKING_PARANOIA=1 -e ANOMALY_INBOUND=5 -e ANOMALY_OUTBOUND=4 \\")
L("     -e MODSEC_RULE_ENGINE=on -e MODSEC_AUDIT_ENGINE=RelevantOnly \\")
L("     -e MODSEC_AUDIT_LOG=/dev/stdout -e MODSEC_AUDIT_LOG_FORMAT=JSON -e SERVER_NAME=localhost \\")
L("     owasp/modsecurity-crs:apache")
L("")
L("## Baseline (unchanged host, for reference)")
L("   Apache 2.4.52 + ModSecurity 2.9.5 + OWASP CRS 3.3.2, PL1, inbound anomaly 5 / outbound 4, blocking rule 949110.")
L("   The host was NOT modified; the updated CRS runs in a container beside it.")

with open(f"{OUT}/crs429_container_metadata.md", "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
print("\nwrote", f"{OUT}/crs429_container_metadata.md")
