#!/usr/bin/env python3
"""Peek at the real CRS 4.29.0 JSON audit structure so the full-run capture extracts the right fields."""
import subprocess, json

r = subprocess.run(["docker", "logs", "--tail", "80", "crs-sqli"], capture_output=True, text=True, timeout=30)
jl = [l for l in (r.stdout + "\n" + r.stderr).splitlines() if l.strip().startswith("{")]
print("json audit lines:", len(jl))
if not jl:
    raise SystemExit(0)
j = json.loads(jl[-1])
print("\n== TOP-LEVEL KEYS ==", list(j.keys()))
for sect in ("transaction", "request", "response", "audit_data"):
    v = j.get(sect, {})
    if isinstance(v, dict):
        print(f"\n== {sect}.keys ==", list(v.keys()))

tx = j.get("transaction", {})
print("\ntransaction.time:", tx.get("time"))
req = j.get("request", {})
print("request.method:", req.get("method"), " uri:", (req.get("uri") or "")[:80])
print("request.headers keys (fields seen):", list((req.get("headers") or {}).keys()))
resp = j.get("response", {})
print("response.http_code / status:", resp.get("http_code"), resp.get("status"))
ad = j.get("audit_data", {})
msgs = ad.get("messages") or tx.get("messages") or []
print("\n== audit_data keys ==", list(ad.keys()))
print("messages count:", len(msgs))
print("first message raw:")
print("  ", (json.dumps(msgs[0]) if msgs else "none")[:600])
# anomaly score fields if present
for k in ("producer", "engine_mode", "stopwatch", "score"):
    if k in ad:
        print(f"audit_data.{k}:", ad[k])
print("\n== FULL last audit entry (pretty, truncated 2500 chars) ==")
print(json.dumps(j, indent=1)[:2500])
