"""
Re-validate the benign corpus against the BACKEND (no WAF), per the advisor's criteria:

  login_ok=0 / no match / wrong password   -> benign  (keep)
  data page: HTTP 200, no SQL error        -> benign  (keep)
  SQL error (oracle.error set)             -> EXCLUDE  (backend handled it abnormally)
  HTTP 500 / no oracle (crash)             -> EXCLUDE  (not clean benign)
  login_ok=1 (unexpected success)          -> INVESTIGATE (weak test data / attack effect)
  data page full-table dump (rows >= 10)   -> INVESTIGATE (could indicate attack effect)

Reads data/benign_<page>.txt (each line is a URL-encoded querystring), sends each to its page on
the backend, classifies, and writes:
  data/benign_<page>_clean.txt   (benign only)
  data/benign_excluded.txt       (everything not benign, with the reason)
"""
import json, re, urllib.request, urllib.parse, urllib.error
from pathlib import Path

BACKEND = "http://localhost:8080"
DATA = Path(__file__).parent.parent / "data"
TOTAL_PRODUCTS = 10
PAGES = {"login": ("POST", "/login"), "search": ("GET", "/search"),
         "product": ("GET", "/product"), "filter": ("GET", "/filter")}


def http(url, method="GET", body=None):
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return -1, str(e)[:80]


def oracle(body):
    m = re.search(r"<!--ORACLE (.*?) -->", body, re.S)
    try:
        return json.loads(m.group(1)) if m else None
    except Exception:
        return None


def classify(page, qs):
    method, path = PAGES[page]
    if method == "POST":
        st, body = http(BACKEND + path, "POST", qs.encode())
    else:
        st, body = http(f"{BACKEND}{path}?{qs}")
    if st == -1 or st >= 500:
        return "exclude", f"crash/http={st}"
    orc = oracle(body)
    if orc is None:
        return "exclude", f"no-oracle(http={st})"
    if orc.get("error"):
        return "exclude", f"sql_error: {str(orc['error'])[:50]}"
    if page == "login":
        if orc.get("login_ok") == 1:
            return "investigate", f"unexpected_success as {orc.get('user')}"
        return "benign", f"login_ok=0 rows={orc.get('rows')}"
    if orc.get("rows", 0) >= TOTAL_PRODUCTS:
        return "investigate", f"full_dump rows={orc.get('rows')}"
    return "benign", f"rows={orc.get('rows')}"


def main():
    excluded_lines = []
    grand = {"benign": 0, "exclude": 0, "investigate": 0}
    print(f"{'page':<8} | {'total':>5} | {'benign':>6} | {'exclude':>7} | {'investigate':>11}")
    print("-" * 52)
    for page in PAGES:
        f = DATA / f"benign_{page}.txt"
        if not f.exists():
            print(f"{page:<8} | (no file)"); continue
        samples = [l.rstrip("\n\r") for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
        clean, counts = [], {"benign": 0, "exclude": 0, "investigate": 0}
        for qs in samples:
            verdict, reason = classify(page, qs)
            counts[verdict] += 1
            if verdict == "benign":
                clean.append(qs)
            else:
                excluded_lines.append(f"[{page}] [{verdict}] [{reason}] {qs}")
        (DATA / f"benign_{page}_clean.txt").write_text("\n".join(clean) + "\n", encoding="utf-8")
        for k in grand:
            grand[k] += counts[k]
        print(f"{page:<8} | {len(samples):>5} | {counts['benign']:>6} | {counts['exclude']:>7} | {counts['investigate']:>11}")
    print("-" * 52)
    tot = sum(grand.values())
    print(f"{'TOTAL':<8} | {tot:>5} | {grand['benign']:>6} | {grand['exclude']:>7} | {grand['investigate']:>11}")
    if excluded_lines:
        (DATA / "benign_excluded.txt").write_text("\n".join(excluded_lines) + "\n", encoding="utf-8")
        print(f"\n{len(excluded_lines)} non-benign sample(s) written to data/benign_excluded.txt")
    else:
        print("\nALL samples are clean benign at the backend. Nothing excluded.")


if __name__ == "__main__":
    main()
