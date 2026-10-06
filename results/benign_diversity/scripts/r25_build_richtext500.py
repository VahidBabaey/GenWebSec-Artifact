#!/usr/bin/env python3
"""Rebuild the rich-text benign corpus to a clean 500 that are BOTH backend-valid (200) AND pass the
   CRS baseline (non-403, CRS-only), matching how the paper's benign corpora are built. Also counts the
   legitimate candidates CRS rejected (CRS's own over-block, reported separately). Wider vocab than the
   first builder so 500 distinct strings are reachable. WAF must be CRS-only + PL1 while this runs."""
import urllib.parse, json, random, requests, os, re
CX = "http://127.0.0.1:8094"          # custom XSS search backend (direct)
WAF = "http://localhost/customxss"    # via WAF (CRS-only baseline)
OUT = "/home/vahid/Projects/GenWebSec/results/V2/RevisionNewResults/R2.5/corpora"
ERRLOG = "/var/log/apache2/error.log"
random.seed(20261006)
S = requests.Session()
S.mount("http://", requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=8, max_retries=0))

def logsize():
    try: return os.path.getsize(ERRLOG)
    except Exception: return 0

def trigger_rule(off):
    """Read the error-log delta since `off` and return the (id, msg) of the triggering CRS rule
    (the first match that is not the anomaly-score blocking rule)."""
    try:
        txt = open(ERRLOG, encoding="utf-8", errors="replace").read()[off:]
    except Exception:
        return "", ""
    ids = re.findall(r'\[id "(\d+)"\][^\n]*?\[msg "([^"]*)"\]', txt)
    for i, m in ids:
        if i not in ("949110", "980130"):
            return i, m
    return (ids[0] if ids else ("", ""))

openers = ["Great product!", "Love it.", "Highly recommend.", "Not bad at all.", "Exactly as described.",
           "Really happy with this.", "Solid purchase.", "Works as expected.", "Pleasantly surprised.",
           "Five stars.", "Would buy again.", "Decent value.", "Impressed so far.", "Does the job."]
items = ["the blue mug", "these running shoes", "this phone case", "the desk lamp", "my new headphones",
         "the travel backpack", "this water bottle", "the kitchen knife set", "that board game",
         "the office chair", "these socks", "the wireless mouse", "this notebook", "the yoga mat"]
bodies = ["{n}/5 stars overall", "great value for the price", "fast shipping & well packed",
          "size M/L fits perfectly", "100% genuine, no complaints", "2 for the price of 1, nice",
          "about ${a}-{b}, fair", "quality is top-notch", "arrived in 2 days :)", "colour is lovely",
          "sturdy and light", "easy to set up", "battery lasts 24/7", "would gift it (e.g. birthday)",
          "{adj} and reliable", "works at 50% brightness fine", "a + b = happy customer",
          "no issues after {n} weeks", "looks {adj} on the shelf", "handy for day-to-day use",
          "pros | cons both minor", "rating {n}/5 | great deal", "see photo <link in bio>",
          "love it <3", "runs small: S < M < L", "quality > price honestly", "specs: a|b|c all fine"]
closers = ["Thanks!", "Recommend to friends & family.", "Highly recommend!", "Will order again.",
           "A keeper.", "Worth every cent.", "Cheers.", "Happy shopper.", "No regrets.", "Top marks.",
           "{name} approved.", "Great seller too.", "Shipping was quick.", "Love the design."]
adjs = ["amazing", "excellent", "sturdy", "elegant", "lovely", "practical", "reliable", "stylish",
        "compact", "durable", "handy", "cheerful", "neat", "premium"]
names = ["Anne-Marie", "O'Brien", "J. Smith", "Maria", "the kids", "my mum", "Lee", "D'Angelo"]

def make():
    parts = [random.choice(openers), random.choice(items).capitalize() + ":",
             random.choice(bodies), random.choice(closers)]
    s = " ".join(parts)
    return s.format(n=random.randint(1, 5), a=random.randint(5, 40), b=random.randint(41, 99),
                    adj=random.choice(adjs), name=random.choice(names))

def status(base, q):
    try:
        return S.get(base + "/search.php?q=" + urllib.parse.quote(q), timeout=8, allow_redirects=False).status_code
    except Exception:
        return -1

kept, rejected, seen, backend_bad, tries = [], [], set(), 0, 0
while len(kept) < 500 and tries < 6000:
    tries += 1
    q = make()
    if q in seen:
        continue
    seen.add(q)
    if status(CX, q) != 200:              # backend must accept it
        backend_bad += 1; continue
    off = logsize()
    if status(WAF, q) == 403:             # CRS baseline rejects it -> excluded; capture the triggering rule
        rid, rmsg = trigger_rule(off)
        rejected.append((q, rid, rmsg)); continue
    kept.append({"method": "GET", "url": WAF + "/search.php?q=" + urllib.parse.quote(q),
                 "body": None, "content_type": None})
    if len(kept) % 100 == 0:
        print(f"  kept {len(kept)}/500  (crs_rejected so far={len(rejected)}, backend_bad={backend_bad})", flush=True)

import csv
with open(f"{OUT}/benign_rich_text.jsonl", "w", encoding="utf-8") as f:
    for r in kept:
        f.write(json.dumps(r) + "\n")
with open(f"{OUT}/crs_baseline_rejections.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["benign_rich_text", "crs_rule_id", "crs_rule_msg"])
    for q, rid, rmsg in rejected:
        w.writerow([q, rid, rmsg])
print(f"\nDISTINCT generated={len(seen)}  backend_bad={backend_bad}  CRS_rejected(legit, excluded)={len(rejected)}  "
      f"baseline-passing kept={len(kept)}")
print(f"-> benign_rich_text.jsonl ({len(kept)} baseline-passing); crs_baseline_rejections.csv ({len(rejected)} rows)")
