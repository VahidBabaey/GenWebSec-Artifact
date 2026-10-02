#!/usr/bin/env python3
import os, sys
os.environ["A1_TARGET"] = "bwapp"; os.environ["A1_PAGE"] = "login"
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/WorkFlowV2")
import pilot_A1_sqli_attack_only_v2 as pilot
pilot.log_print = lambda *a, **k: None
print("BACKEND", pilot.BACKEND, "WAF", pilot.WAF, "PAGE_PATH", pilot.PAGE_PATH)
pilot.establish_session()
print("session_ok (backend):", pilot.session_ok())
ws = [l.strip() for l in open(f"{ROOT}/results/V2/A1_HeldOut/A1_bwapp_heldout_seed1/A1_bwapp_login_winners.txt", encoding="utf-8", errors="replace") if l.strip() and not l.startswith("#")][:5]
print(f"testing {len(ws)} winners")
for i, w in enumerate(ws, 1):
    ra = pilot.probe(pilot.BACKEND, w)
    rb = pilot.probe(pilot.WAF, w)
    print(f"  {i}: RouteA valid={ra['valid']} status={ra['status']}  |  RouteB(WAF) valid={rb['valid']} status={rb['status']}")
# also inspect a Route B response body for markers
st, body = pilot.send(pilot.WAF, ws[0])
low = body.lower()
print("RouteB status", st, "len", len(body),
      "| has 'how are you today':", "how are you today" in low,
      "| has 'your secret':", "your secret" in low,
      "| has 'login':", "login" in low, "| redirected_to_login:", "invalid credentials" in low or "login.php" in low)
print("body head:", body[:200].replace(chr(10), " "))
