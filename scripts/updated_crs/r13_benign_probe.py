#!/usr/bin/env python3
import urllib.request, urllib.error, urllib.parse, collections

def http(url, t=5):
    try:
        with urllib.request.urlopen(url, timeout=t) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return -1

print("== backend 8080 (customapp) route support: clean vs .php ==")
for p in ["/login?username=bob&password=x", "/login.php?username=bob&password=x",
          "/search?q=x", "/search.php?q=x", "/product?id=2", "/product.php?id=2",
          "/filter?category=x", "/filter.php?category=x"]:
    print(f"   {p:<42} -> {http('http://127.0.0.1:8080'+p)}")

print("== backend 8096 (customxss) ==")
for p in ["/search.php?q=x", "/calc.php?expr=2", "/index.php"]:
    print(f"   {p:<42} -> {http('http://127.0.0.1:8096'+p)}")

print("== benign corpus page/path distribution ==")
for fam, fn in [("sqli", "/home/vahid/Projects/GenWebSec/data/benignurls.txt"),
                ("xss", "/home/vahid/Projects/GenWebSec/data/benignurls_xss.txt")]:
    c = collections.Counter(); n = 0; sample = None
    for line in open(fn, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        n += 1
        pr = urllib.parse.urlparse(line)
        c[pr.path] += 1
        if sample is None:
            sample = (pr.path, pr.query[:60])
    print(f"   {fam}: total={n}  paths={dict(c)}  sample={sample}")
