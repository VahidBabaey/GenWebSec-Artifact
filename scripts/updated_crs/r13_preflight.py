#!/usr/bin/env python3
"""R1.3 preflight: verify the real environment before pulling/deploying CRS 4.25.1."""
import subprocess, socket, urllib.request, urllib.error, os

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=40).stdout.strip()
    except Exception as e:
        return f"ERR {e}"

def http(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return -1, str(e)[:90]

def port_listening(p):
    s = socket.socket(); s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", p)); s.close(); return True
    except Exception:
        return False

print("== docker version =="); print(" ", run(["docker", "--version"]))
print("== docker server/storage =="); print(" ", run(["docker", "info", "--format", "{{.ServerVersion}} driver={{.Driver}}"]))
print("== networks =="); print(run(["docker", "network", "ls"]))
print("== running containers =="); print(run(["docker", "ps", "--format", "{{.Names}}  {{.Ports}}"]))

print("== backend 8080 (customapp SQLi) ==")
for ep in ["http://127.0.0.1:8080/product?id=2", "http://127.0.0.1:8080/search?q=test", "http://127.0.0.1:8080/filter?category=x"]:
    st, body = http(ep)
    print(f"   {ep} -> {st}  oracle_marker={'<!--ORACLE' in body}")

print("== customxss docroot ==")
d = "/home/vahid/Projects/GenWebSec/customxss"
print(f"   {d} exists={os.path.isdir(d)}")
if os.path.isdir(d):
    print("   files:", sorted(os.listdir(d))[:30])

print("== php present ==")
print("  ", run(["bash", "-lc", "which php; php -v | head -1"]))

print("== ports listening on 127.0.0.1 ==")
for p in [80, 3000, 8080, 8081, 8082, 8086, 8094, 8095, 8096]:
    print(f"   {p}: {'UP' if port_listening(p) else '-'}")

print("== internet to docker hub ==")
st, _ = http("https://registry-1.docker.io/v2/", 8)
print(f"   registry-1.docker.io/v2/ -> {st} (401 or 200 both mean reachable)")

print("== existing crs image tags locally ==")
print(run(["bash", "-lc", "docker images | grep -i modsec || echo '(none)'"]))
print("== done ==")
