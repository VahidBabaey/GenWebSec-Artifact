#!/usr/bin/env python3
"""R2.5 benign-diversity supplement: build + backend-validate two benign corpora.
   (A) nested JSON  -> Juice Shop sign-up POST /api/Users (nested securityQuestion object), keep 201.
   (B) rich text    -> custom XSS search GET /customxss search.php?q=, keep 200.
   Realistic 'tricky-but-benign' values (apostrophes, punctuation, <>&, quotes) so the rules are
   genuinely exercised. Validation hits the BACKEND directly (no WAF). Saves transport JSONL whose
   `url` targets the WAF (localhost) for the later FP replay. No attacks."""
import urllib.request, urllib.parse, json, time, random

JB = "http://127.0.0.1:3000"            # Juice backend (direct)
CX = "http://127.0.0.1:8094"            # custom XSS 'search' backend (direct)
WAF_JUICE = "http://localhost/juice"
WAF_CX = "http://localhost/customxss"
OUT = "/home/vahid/Projects/GenWebSec/results/V2/RevisionNewResults/R2.5/corpora"
import os; os.makedirs(OUT, exist_ok=True)
random.seed(20261006)
H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36",
     "Accept": "application/json"}

def hit(method, base, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    for k, v in H.items(): r.add_header(k, v)
    if body is not None: r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp: return resp.status
    except urllib.error.HTTPError as e: return e.code
    except Exception: return -1

# ---------- (A) nested JSON: Juice sign-ups ----------
sq_ids = [1, 2, 3, 4, 5]
try:
    raw = urllib.request.urlopen(urllib.request.Request(JB + "/api/SecurityQuestions", headers=H), timeout=10).read()
    sq_ids = [d["id"] for d in json.loads(raw)["data"]] or sq_ids
except Exception as e:
    print("  [warn] securityquestions fetch:", e)
print(f"[A] security-question ids: {sq_ids[:8]}")

first = ["alice","bob","carlos","dana","ella","mohammed","yuki","priya","liam","sofia","noah","mia","omar","lena","raj"]
last = ["smith","oBrien","garcia","nguyen","mueller","rossi","kim","dubois","silva","haddad","ivanov","tanaka"]
answers = ["O'Brien", "St. Mary's", "Côte d'Azur", "Mr. Smith-Jones", "n/a", "Paris, France",
           "my first pet: Rex!", "it's a secret", "Anne-Marie", "D'Angelo", "San José", "100% sure"]
nested_recs = []
tA = int(time.time())
for i in range(500):
    fn = random.choice(first); ln = random.choice(last)
    email = f"{fn}.{ln}.{tA}.{i}@benign-test.example"
    qid = random.choice(sq_ids)
    body = {"email": email, "password": "Benign-Pass_123!", "passwordRepeat": "Benign-Pass_123!",
            "securityQuestion": {"id": qid, "question": "Your eldest sibling's middle name?",
                                 "createdAt": "2026-01-01T00:00:00.000Z"},
            "securityAnswer": random.choice(answers)}
    st = hit("POST", JB, "/api/Users", body)                 # backend-validate (creates user)
    if st in (200, 201):
        nested_recs.append({"method": "POST", "url": WAF_JUICE + "/api/Users",
                            "body": json.dumps(body), "content_type": "application/json"})
    if (i + 1) % 100 == 0:
        print(f"  [A] {i+1}/500 tried, {len(nested_recs)} valid (201)")
with open(f"{OUT}/benign_nested_json.jsonl", "w", encoding="utf-8") as f:
    for r in nested_recs: f.write(json.dumps(r) + "\n")
print(f"[A] nested-JSON corpus: {len(nested_recs)} valid requests -> benign_nested_json.jsonl")

# ---------- (B) rich text: custom XSS search ----------
tmpl = [
    "Great product! {n}/5 <3 would buy again",
    "I love it -- it's {adj} & worth every cent!",
    "price range: ${a}-${b} (best value in {yr})",
    "{name}'s review: \"{adj}\", highly recommended :)",
    "works {adv}; 10/10 would recommend to friends & family",
    "size M/L fits well -- see photos <link in bio>",
    "rating: {n} stars | {adj} quality, fast shipping",
    "a < b > c, 2+2=4, 50% off today only!",
    "contact: mary-anne o'neil (st. john's) for details",
    "note: use code SAVE{n} => {b}% off; terms apply",
]
adjs = ["amazing","excellent","superb","great","lovely","fantastic","solid","wonderful","top-notch","decent"]
advs = ["perfectly","really well","flawlessly","as expected","great"]
names = ["Anne-Marie","O'Brien","J. Smith","María","D'Angelo","Lee"]
rich_recs = []
seen = set()
tries = 0
while len(rich_recs) < 500 and tries < 2000:
    tries += 1
    t = random.choice(tmpl)
    s = t.format(n=random.randint(1,5), adj=random.choice(adjs), adv=random.choice(advs),
                 a=random.randint(5,50), b=random.randint(51,99), yr=random.randint(2019,2026),
                 name=random.choice(names))
    if s in seen: continue
    seen.add(s)
    q = urllib.parse.quote(s)
    st = hit("GET", CX, "/search.php?q=" + q)                # backend-validate
    if st == 200:
        rich_recs.append({"method": "GET", "url": WAF_CX + "/search.php?q=" + q,
                          "body": None, "content_type": None})
    if tries % 100 == 0:
        print(f"  [B] {tries} tried, {len(rich_recs)} valid (200)")
with open(f"{OUT}/benign_rich_text.jsonl", "w", encoding="utf-8") as f:
    for r in rich_recs: f.write(json.dumps(r) + "\n")
print(f"[B] rich-text corpus: {len(rich_recs)} valid requests -> benign_rich_text.jsonl")
