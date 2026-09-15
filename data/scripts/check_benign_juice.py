"""
Cross-check the LOGIN and SEARCH benign samples against OWASP Juice Shop (no WAF), per the
advisor's criteria. Juice has no product/filter SQLi, so only login + search are checked.

  login : 401 "Invalid email or password"  -> benign      (normal failed login)
          200 + token                       -> INVESTIGATE (unexpected success)
          500 / unreachable                 -> EXCLUDE     (SQL error / crash)
  search: 200, no deleted product           -> benign      (normal search)
          200, a deleted product leaked     -> INVESTIGATE (could indicate attack effect)
          500 SQLITE_ERROR / unreachable    -> EXCLUDE

Login samples are username=...&password=...; the username value is sent into Juice's `email`
field (Juice authenticates by email), so they normally fail with 401 — still clean benign.
"""
import json, re, time, subprocess, urllib.request, urllib.parse, urllib.error
from pathlib import Path

BACKEND = "http://localhost:3000"
DATA = Path(__file__).parent.parent / "data"
CONTAINER = "juice-shop"


def http(url, method="GET", body=None, ctype="application/json"):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)[:80]


def backend_up():
    try:
        return urllib.request.urlopen(f"{BACKEND}/rest/products/search?q=ping", timeout=6).status == 200
    except Exception:
        return False


def ensure_up(max_wait=120):
    if backend_up():
        return True
    print("  [backend] Juice down — recovering...")
    try:
        subprocess.run(["docker", "start", CONTAINER], capture_output=True, timeout=25)
    except Exception:
        pass
    w = 0
    while w < max_wait:
        if backend_up():
            print(f"  [backend] recovered after ~{w}s"); return True
        time.sleep(4); w += 4
    return False


def juice_login(email, password):
    body = json.dumps({"email": email, "password": password}).encode()
    st, t = http(f"{BACKEND}/rest/user/login", "POST", body)
    if st == -1 and ensure_up():
        st, t = http(f"{BACKEND}/rest/user/login", "POST", body)
    if st == -1:
        return "exclude", "unreachable/crash"
    if st >= 500:
        return "exclude", f"http={st} (sql error/abnormal)"
    if st == 200 and '"token"' in t:
        m = re.search(r'"umail"\s*:\s*"([^"]*)"', t)
        return "investigate", f"unexpected_login as {m.group(1) if m else '?'}"
    if st == 401:
        return "benign", "401 invalid email/password"
    return "exclude", f"http={st} unexpected"


def juice_search(q):
    url = f"{BACKEND}/rest/products/search?q=" + urllib.parse.quote(q, safe="")
    st, t = http(url)
    if st == -1 and ensure_up():
        st, t = http(url)
    if st == -1:
        return "exclude", "unreachable/crash"
    if st >= 500 or "SQLITE_ERROR" in t:
        return "exclude", "sql_error/http500"
    try:
        data = json.loads(t).get("data", [])
        ndel = sum(1 for d in data if isinstance(d, dict) and d.get("deletedAt") is not None)
    except Exception:
        return "exclude", "non-json"
    if ndel > 0:
        return "investigate", f"leaked {ndel} deleted product(s)"
    return "benign", f"rows={len(data)}"


def run(page, fn):
    f = DATA / f"benign_{page}.txt"
    samples = [l.rstrip("\n\r") for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
    counts = {"benign": 0, "exclude": 0, "investigate": 0}
    excluded = []
    for qs in samples:
        d = urllib.parse.parse_qs(qs, keep_blank_values=True)
        if page == "login":
            verdict, reason = fn(d.get("username", [""])[0], d.get("password", [""])[0])
        else:
            verdict, reason = fn(d.get("q", [""])[0])
        counts[verdict] += 1
        if verdict != "benign":
            excluded.append(f"[juice/{page}] [{verdict}] [{reason}] {qs}")
    return len(samples), counts, excluded


def main():
    if not ensure_up():
        print("Juice is DOWN and could not be recovered — aborting."); return
    print(f"{'page':<8} | {'total':>5} | {'benign':>6} | {'exclude':>7} | {'investigate':>11}")
    print("-" * 52)
    all_excluded = []
    for page, fn in [("login", juice_login), ("search", juice_search)]:
        total, counts, excluded = run(page, fn)
        all_excluded += excluded
        print(f"{page:<8} | {total:>5} | {counts['benign']:>6} | {counts['exclude']:>7} | {counts['investigate']:>11}")
    print("-" * 52)
    if all_excluded:
        (DATA / "benign_juice_excluded.txt").write_text("\n".join(all_excluded) + "\n", encoding="utf-8")
        print(f"\n{len(all_excluded)} non-benign on Juice -> data/benign_juice_excluded.txt")
    else:
        print("\nALL login+search benign samples are clean benign on Juice too. Nothing excluded.")


if __name__ == "__main__":
    main()
