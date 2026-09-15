"""
Generate a benign FP corpus for the custom app: 500 legitimate requests per page.
Each candidate is VERIFIED against the baseline WAF (:80) and only kept if it is NOT blocked
(HTTP != 403) — so every saved sample is genuinely benign (passes the baseline CRS).
Values use only benign characters (letters, digits, space, . _ - @) — no SQLi metacharacters.

Output: data/benign_<page>.txt  (one URL-encoded querystring per line)
"""
import os, random, urllib.parse, urllib.request, urllib.error

random.seed(123)
WAF = "http://localhost"
TARGET = 500
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

FIRST = ["john", "mary", "alice", "bob", "carol", "david", "emma", "frank", "grace", "henry",
         "ivy", "jack", "kate", "leo", "mia", "noah", "olivia", "peter", "quinn", "rose",
         "sam", "tina", "umar", "vera", "will", "xena", "yusuf", "zoe", "liam", "nora",
         "ethan", "ava", "lucas", "sophia", "mason", "isla", "logan", "ruby", "oscar", "lily"]
LAST = ["smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
        "martinez", "lopez", "wilson", "anderson", "taylor", "thomas", "moore", "jackson",
        "white", "harris", "clark", "lewis", "walker", "hall", "young", "king", "wright",
        "scott", "green", "baker", "adams", "nelson", "hill", "carter", "mitchell", "perez",
        "roberts", "turner", "phillips", "campbell", "parker", "evans"]
PROD = ["juice", "apple", "orange", "carrot", "smoothie", "tea", "coffee", "water", "bottle",
        "mug", "shirt", "tshirt", "cotton", "sticker", "notebook", "tote", "bag", "pack",
        "organic", "fresh", "green", "ceramic", "insulated", "dotted", "vinyl", "lemon",
        "mango", "berry", "cocoa", "mint", "ginger", "honey", "almond", "oat", "soy",
        "glass", "steel", "canvas", "leather", "wooden"]
ADJ = ["large", "small", "blue", "red", "green", "premium", "classic", "eco", "new", "mini",
       "deluxe", "soft", "warm", "cool", "light", "dark", "round", "slim", "bold", "pure"]
CATS = ["drinks", "beverages", "apparel", "clothing", "accessories", "stationery", "books",
        "toys", "electronics", "food", "home", "kitchen", "garden", "sports", "beauty",
        "health", "office", "gifts", "sale", "outdoor", "indoor", "travel", "kids", "men",
        "women", "seasonal", "organic", "fresh", "gadgets", "decor"]
DOM = ["example.com", "mail.com", "shop.lab", "test.org", "corp.net"]
PW_CH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#_."


def rand_pw():
    return "".join(random.choice(PW_CH) for _ in range(random.randint(8, 14)))


def gen_username():
    f, l = random.choice(FIRST), random.choice(LAST)
    return random.choice([f, f + l, f + "." + l, f + "_" + l, f + str(random.randint(1, 9999)),
                          f + "@" + random.choice(DOM), l + f[0] + str(random.randint(1, 99))])


def gen_search():
    return random.choice([random.choice(PROD),
                          random.choice(ADJ) + " " + random.choice(PROD),
                          random.choice(PROD) + " " + random.choice(PROD),
                          random.choice(PROD) + str(random.randint(1, 500)),
                          random.choice(ADJ)])


def gen_id():
    return str(random.choice([random.randint(1, 50), random.randint(1, 100000)]))


def gen_category():
    c = random.choice(CATS)
    return random.choice([c, random.choice(ADJ) + " " + c, c + "s",
                          random.choice(["men", "women", "kids"]) + " " + c,
                          c + str(random.randint(1, 50))])


PAGES = {
    "login":   ("POST", lambda: {"username": gen_username(), "password": rand_pw()}),
    "search":  ("GET",  lambda: {"q": gen_search()}),
    "product": ("GET",  lambda: {"id": gen_id()}),
    "filter":  ("GET",  lambda: {"category": gen_category()}),
}


def waf_status(page, method, sent):
    if method == "GET":
        req = urllib.request.Request(f"{WAF}/customapp/{page}.php?{sent}")
    else:
        req = urllib.request.Request(f"{WAF}/customapp/{page}.php", data=sent.encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


all_urls = []   # aggregated full-URL benign corpus (page encoded in the path)
for page, (method, gen) in PAGES.items():
    seen, clean, blocked, errors, attempts = set(), [], 0, 0, 0
    while len(clean) < TARGET and attempts < TARGET * 4:
        attempts += 1
        sent = urllib.parse.urlencode(gen())
        if sent in seen:
            continue
        seen.add(sent)
        st = waf_status(page, method, sent)
        if st == 403:
            blocked += 1
        elif st == -1:
            errors += 1
        else:
            clean.append(sent)
    out = os.path.join(DATA, f"benign_{page}.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(clean) + "\n")
    all_urls.extend(f"{WAF}/customapp/{page}.php?{s}" for s in clean)
    print(f"{page:8}: saved {len(clean)} benign  (baseline-blocked dropped={blocked}, errors={errors}, attempts={attempts}) -> data/benign_{page}.txt")

# aggregated one-file corpus (full URLs). The defense loader recovers page+method from the path
# (so login is still exercised as POST), but everything lives in a single file as requested.
agg = os.path.join(DATA, "benignurls.txt")
with open(agg, "w", encoding="utf-8") as f:
    f.write("\n".join(all_urls) + "\n")
print(f"{'ALL':8}: saved {len(all_urls)} benign -> data/benignurls.txt")
