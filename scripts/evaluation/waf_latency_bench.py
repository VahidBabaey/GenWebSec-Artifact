#!/usr/bin/env python3
"""
Item 5: deployed WAF request latency benchmark (hey).
Compares CRS-only vs each final CG rule set (eps0.3, seed1) on the custom app, plus a direct-backend
baseline, at concurrency 1/10/50, plain and token-laden benign workloads, >=10k requests x 5 repeats.
Overhead % = (L_R - L_CRS)/L_CRS * 100 on the median. Results -> results/V2/WAF_Latency/.
Run as root (needs apache reload). Backend (:8080) must be up.
"""
import os, sys, re, csv, subprocess, time, statistics
ROOT = "/path/to/GenWebSec"
sys.path.insert(0, ROOT)
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache

OUT = os.path.join(ROOT, "results", "V2", "WAF_Latency")
RAW = os.path.join(OUT, "raw")
os.makedirs(RAW, exist_ok=True)

HEY = "/usr/local/bin/hey"
UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36"
CT  = "application/x-www-form-urlencoded"
N        = int(os.environ.get("LAT_N", "10000"))
REPEATS  = int(os.environ.get("LAT_REPEATS", "5"))
CONC     = [int(x) for x in os.environ.get("LAT_CONC", "1,10,50").split(",")]

DIRECT = "http://127.0.0.1:8080"
WAF    = "http://localhost/customapp"
PLAIN  = "/product?id=1"
TOKEN  = "/product?id=1&note=a%3Cb%20and%20c%3Ed"   # a<b and c>d  (SQL/JS-like tokens, benign)

SECRULE = re.compile(r"^\s*SecRule\b"); IDPAT = re.compile(r"id:\d+")
def union(files):
    raw = []
    for fp in files:
        if os.path.exists(fp):
            for ln in open(fp, encoding="utf-8"):
                if SECRULE.match(ln): raw.append(ln.strip())
    out, nid = [], 1000001
    for r in raw:
        out.append(IDPAT.sub(f"id:{nid}", r, count=1)); nid += 1
    return out

# explicit rule-file lists (eps0.3, seed1)
C1 = [f"{ROOT}/results/V2/CustomApp_C1/CustomApp_C1_Token_eps0.3_seed1/C1_customapp_{p}_clustering_rules.txt"
      for p in ("login","search","product","filter")]
D1 = [f"{ROOT}/results/V2/CustomApp_D1/CustomApp_D1_eps0.3_seed1/D1_customapp_{p}_clustering_rules.txt"
      for p in ("login","search","product","filter")]
C2 = [f"{ROOT}/results/V2/CustomApp_C2/CustomXSS_C2_Token_eps0.3_seed1/C2_customxss_{p}_clustering_rules.txt"
      for p in ("search","calc")]
D2 = [f"{ROOT}/results/V2/CustomApp_D2/CustomXSS_D2_eps0.3_seed1/D2_customxss_{p}_clustering_rules.txt"
      for p in ("search","calc")]

# (label, base_url, rules_or_None)  None => direct backend, no WAF change
CONFIGS = [
    ("direct",            DIRECT, None),
    ("crs_only",          WAF,    []),
    ("cg_adaptive_sqli",  WAF,    union(C1)),
    ("cg_static_sqli",    WAF,    union(D1)),
    ("cg_adaptive_xss",   WAF,    union(C2)),
    ("cg_static_xss",     WAF,    union(D2)),
]

def apache_cpu_sec():
    """Cumulative CPU seconds consumed by Apache (the WAF). Prefers systemd cgroup accounting
    for the whole apache2.service (robust to worker churn); falls back to summing /proc."""
    try:
        for ln in open("/sys/fs/cgroup/system.slice/apache2.service/cpu.stat"):
            if ln.startswith("usage_usec"):
                return int(ln.split()[1]) / 1e6
    except Exception:
        pass
    try:
        return int(open("/sys/fs/cgroup/cpu,cpuacct/system.slice/apache2.service/cpuacct.usage").read()) / 1e9
    except Exception:
        pass
    clk = os.sysconf("SC_CLK_TCK"); tot = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if open(f"/proc/{pid}/comm").read().strip() not in ("apache2", "httpd"):
                continue
            d = open(f"/proc/{pid}/stat").read(); a = d[d.rfind(")") + 2:].split()
            tot += int(a[11]) + int(a[12])
        except Exception:
            continue
    return tot / clk

def deploy(rules):
    write_rules(rules)
    ok, out = run_configtest(timeout=120.0)
    if ok: reload_apache(timeout=30.0)
    return ok

NUMRE = {
    "reqps": re.compile(r"Requests/sec:\s*([\d.]+)"),
    "avg":   re.compile(r"Average:\s*([\d.]+) secs"),
    "p50":   re.compile(r"50% in ([\d.]+) secs"),
    "p95":   re.compile(r"95% in ([\d.]+) secs"),
    "p99":   re.compile(r"99% in ([\d.]+) secs"),
}
def parse(o):
    g = lambda k: (float(NUMRE[k].search(o).group(1)) if NUMRE[k].search(o) else None)
    ok = 0; err = 0
    for m in re.finditer(r"\[(\d+)\]\s+(\d+) responses", o):
        code, cnt = int(m.group(1)), int(m.group(2))
        if code == 200:
            ok += cnt
        else:
            err += cnt
    return dict(reqps=g("reqps"), avg_ms=(g("avg") or 0)*1000, p50_ms=(g("p50") or 0)*1000,
                p95_ms=(g("p95") or 0)*1000, p99_ms=(g("p99") or 0)*1000, ok=ok, err=err)

def run_hey(url, c):
    cmd = [HEY, "-n", str(N), "-c", str(c), "-T", CT, "-H", f"User-Agent: {UA}", url]
    c0 = apache_cpu_sec(); w0 = time.time()
    o = subprocess.run(cmd, capture_output=True, text=True, timeout=900).stdout
    w1 = time.time(); c1 = apache_cpu_sec()
    wall = max(w1 - w0, 1e-6)
    cpu = 100.0 * (c1 - c0) / wall   # Apache CPU as % of one core (>100 means multiple worker cores)
    r = parse(o); r["cpu_pct"] = round(cpu, 1)
    return r, o

def health(base):
    for path, name in ((PLAIN, "plain"), (TOKEN, "token")):
        code = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                               "-H", f"Content-Type: {CT}", "-H", f"User-Agent: {UA}",
                               "--max-time", "5", base + path], capture_output=True, text=True).stdout
        print(f"      health {name}: {code}", flush=True)

def warm(url):
    subprocess.run([HEY, "-n", "3000", "-c", "20", "-T", CT, "-H", f"User-Agent: {UA}", url],
                   capture_output=True, timeout=120)

def main():
    rows = []
    print(f"[latency] N={N} repeats={REPEATS} conc={CONC}  configs={[c[0] for c in CONFIGS]}", flush=True)
    for label, base, rules in CONFIGS:
        print(f"\n=== config: {label} ===", flush=True)
        if rules is not None:
            ok = deploy(rules)
            print(f"    deployed {len(rules)} rules  configtest_ok={ok}", flush=True)
            if not ok:
                continue
        else:
            print("    (direct backend, no WAF)", flush=True)
        health(base)
        for wl, path in (("plain", PLAIN), ("token", TOKEN)):
            url = base + path
            warm(url)
            for c in CONC:
                for rep in range(1, REPEATS + 1):
                    r, o = run_hey(url, c)
                    open(os.path.join(RAW, f"{label}_{wl}_c{c}_r{rep}.txt"), "w").write(o)
                    rows.append([label, wl, c, rep, N, r["p50_ms"], r["p95_ms"], r["p99_ms"],
                                 r["avg_ms"], r["reqps"], r["ok"], r["err"], r["cpu_pct"], url])
                    print(f"    {label:17} {wl:5} c={c:<2} r{rep}: "
                          f"p50={r['p50_ms']:.2f}ms p95={r['p95_ms']:.2f} p99={r['p99_ms']:.2f} "
                          f"{r['reqps']:.0f}req/s ok={r['ok']} err={r['err']} cpu={r['cpu_pct']}%", flush=True)
    # restore CRS-only
    deploy([])
    print("\n[latency] WAF restored to CRS-only", flush=True)
    with open(os.path.join(OUT, "latency_raw.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config","workload","concurrency","repeat","n","p50_ms","p95_ms","p99_ms",
                    "avg_ms","req_per_sec","ok","err","cpu_pct","url"])
        w.writerows(rows)
    print(f"[latency] wrote {OUT}/latency_raw.csv ({len(rows)} rows)", flush=True)

if __name__ == "__main__":
    main()
