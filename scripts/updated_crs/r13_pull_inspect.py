#!/usr/bin/env python3
"""R1.3: pull the OWASP CRS Apache image and read its REAL version + env-config knobs."""
import subprocess, json

def run(cmd, timeout=900):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr

IMG = "owasp/modsecurity-crs:apache"

print("==== docker pull", IMG, "====")
rc, out, err = run(["docker", "pull", IMG])
print("PULL rc =", rc)
print((out or "")[-700:])
if rc != 0:
    print("PULL ERR:", (err or "")[-700:])
    raise SystemExit("pull failed")

print("\n==== image metadata ====")
rc, out, err = run(["docker", "inspect", IMG])
info = json.loads(out)[0] if rc == 0 and out.strip() else {}
cfg = info.get("Config", {})
print("Id          :", info.get("Id"))
print("RepoDigests :", info.get("RepoDigests"))
print("ExposedPorts:", list((cfg.get("ExposedPorts") or {}).keys()))
print("Entrypoint  :", cfg.get("Entrypoint"))
print("Cmd         :", cfg.get("Cmd"))
print("---- ENV (defaults; shows the knob names) ----")
for e in (cfg.get("Env") or []):
    print("   ", e)
print("---- LABELS ----")
for k, v in (cfg.get("Labels") or {}).items():
    print(f"    {k} = {v}")

print("\n==== CRS version (from inside the image) ====")
rc, out, err = run(["docker", "run", "--rm", "--entrypoint", "head", IMG,
                    "-n", "20", "/etc/modsecurity.d/owasp-crs/crs-setup.conf"])
print(out or err)

print("==== ls /etc/modsecurity.d/ ====")
rc, out, err = run(["docker", "run", "--rm", "--entrypoint", "ls", IMG, "-la", "/etc/modsecurity.d/"])
print(out or err)

print("==== ls /etc/modsecurity.d/owasp-crs/ ====")
rc, out, err = run(["docker", "run", "--rm", "--entrypoint", "ls", IMG, "-la", "/etc/modsecurity.d/owasp-crs/"])
print(out or err)

print("==== versions: apache + modsecurity module ====")
rc, out, err = run(["docker", "run", "--rm", "--entrypoint", "bash", IMG, "-lc",
                    "httpd -v 2>/dev/null | head -1; echo '--'; ls /usr/lib/apache2/modules/ 2>/dev/null | grep -i security; ls /etc/apache2/mods-* -d 2>/dev/null"])
print(out or err)
print("==== done ====")
