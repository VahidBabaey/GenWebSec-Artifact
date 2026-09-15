# REDACTED PUBLIC COPY. Concrete injection-breakout templates / smoke-test
# payloads have been replaced with a [redacted for safety] marker; the
# instantiation logic and comments are intact. See ../README.md.

#!/usr/bin/env python3
"""
Item 8 (SQLi) -- step 1-3: STATIC extraction of sqlmap payload templates ->
deterministic placeholder instantiation -> per-page context wrapping ->
candidate corpus with full provenance.

Reads ONLY sqlmap's shipped XML templates. Touches no app, no WAF, no rules.
Deterministic: same inputs -> byte-identical output. No `re` module (WSL segfault).

Outputs (results/V2/NonLLM_Results/corpus/):
  candidates.tsv   one row per (page, payload) with provenance + final payload
  counts.txt       raw tests per family; per-page context-compatible; unresolved
"""
import os
import xml.etree.ElementTree as ET

ROOT = "/path/to/GenWebSec"
XMLDIR = os.path.join(ROOT, "tools/sqlmap/data/xml/payloads")
OUT = os.path.join(ROOT, "results/V2/NonLLM_Results/corpus")
os.makedirs(OUT, exist_ok=True)

SQLMAP_COMMIT = "a184c89a6bdb007502aed50f3d86862c4055f3b3"

FAMILY = {"1": "boolean_blind", "2": "error_based", "3": "inline_query",
          "4": "stacked_queries", "5": "time_blind", "6": "union_query"}

FILES = ["boolean_blind.xml", "error_based.xml", "inline_query.xml",
         "stacked_queries.xml", "time_blind.xml", "union_query.xml"]

# ---- deterministic placeholder table (fixed constants; from template syntax only) ----
SUBST = {
    "[RANDNUM]": "8801", "[RANDNUM1]": "8802", "[RANDNUM2]": "8803",
    "[RANDNUM3]": "8804", "[RANDNUM4]": "8805", "[RANDNUM5]": "8806",
    "[RANDSTR]": "qwqx", "[DELIMITER_START]": "qxqx", "[DELIMITER_STOP]": "xqxq",
    "[INFERENCE]": "8801=8801", "[SLEEPTIME]": "5", "[GENERIC_SQL_COMMENT]": "-- -",
    "[QUERY]": "(SELECT 8801)", "[DELAYED]": "(SELECT 8801)", "[ORIGVALUE]": "",
    "[UNION]": "NULL", "[CHAR]": "NULL", "[COLSTART]": "", "[COLSTOP]": "",
    "[SPACE_REPLACE]": " ", "[HASH_REPLACE]": "#", "[DOLLAR_REPLACE]": "$",
    "[AT_REPLACE]": "@",
}

# per-page fixed breakout (prefix, default trailing comment) -- from the query structure only
PAGE_WRAP = {
    "login":   ("[breakout redacted]", "[comment redacted]"),   # WHERE username='<in>' AND password='<in>'  (auth-bypass)
    "search":  ("[breakout redacted]", "[comment redacted]"),    # WHERE name LIKE '%<in>%'                    (full-table dump)
    "product": ("[breakout redacted]", "[comment redacted]"),    # WHERE id=<in>  (numeric)                    (full-table dump)
    "filter":  ("[breakout redacted]", "[comment redacted]"),    # WHERE category='<in>'                       (full-table dump)
}
PAGES = ["login", "search", "product", "filter"]


def instantiate(s):
    if s is None:
        return ""
    for k, v in SUBST.items():
        s = s.replace(k, v)
    return s


def unresolved_tokens(s):
    """Any remaining [UPPERCASE...] placeholder left after substitution (string ops, no re)."""
    out, i, n = [], 0, len(s)
    while i < n:
        a = s.find("[", i)
        if a < 0:
            break
        b = s.find("]", a)
        if b < 0:
            break
        tok = s[a:b + 1]
        inner = tok[1:-1]
        if inner and inner[0].isalpha() and inner.upper() == inner:
            out.append(tok)
        i = b + 1
    return out


def parse_tests(path):
    """Yield (title, family, where, clause, raw_payload, raw_comment) for each real <test>.
    ElementTree ignores XML comments, so the schema-doc example is not included."""
    tree = ET.parse(path)
    root = tree.getroot()
    for t in root.findall("test"):
        stype = (t.findtext("stype") or "").strip()
        title = (t.findtext("title") or "").strip()
        where = (t.findtext("where") or "").strip()
        clause = (t.findtext("clause") or "").strip()
        req = t.find("request")
        payload = (req.findtext("payload") if req is not None else "") or ""
        comment = (req.findtext("comment") if req is not None else "") or ""
        yield title, FAMILY.get(stype, "stype" + stype), where, clause, payload.strip(), comment.strip()


def main():
    rows = []                       # candidate rows (page x payload)
    raw_per_family = {}             # raw test count per family
    raw_total = 0

    for fn in FILES:
        path = os.path.join(XMLDIR, fn)
        for title, family, where, clause, raw_payload, raw_comment in parse_tests(path):
            raw_total += 1
            raw_per_family[family] = raw_per_family.get(family, 0) + 1
            if not raw_payload:
                continue
            core = instantiate(raw_payload)
            for page in PAGES:
                prefix, default_comment = PAGE_WRAP[page]
                comment = instantiate(raw_comment) if raw_comment else default_comment
                final = prefix + core + " " + comment
                final = " ".join(final.split())          # collapse whitespace, deterministic
                unres = unresolved_tokens(final)
                rows.append({
                    "page": page, "family": family, "source_file": fn, "test_title": title,
                    "where": where, "clause": clause, "raw_payload": raw_payload,
                    "final_payload": final, "unresolved": ",".join(unres),
                })

    # ---- write candidates.tsv ----
    cols = ["idx", "page", "family", "source_file", "test_title", "where", "clause",
            "raw_payload", "final_payload", "unresolved"]
    with open(os.path.join(OUT, "candidates.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for i, r in enumerate(rows):
            f.write("\t".join(str(r.get(c, "")) if c != "idx" else str(i)
                              for c in cols).replace("\r", " ") + "\n")

    # ---- counts ----
    fam_order = ["boolean_blind", "error_based", "inline_query",
                 "stacked_queries", "time_blind", "union_query"]
    fully = [r for r in rows if not r["unresolved"]]
    L = []
    L.append("Item 8 (SQLi) -- non-LLM corpus, extraction step (1-3)")
    L.append("sqlmap commit: " + SQLMAP_COMMIT)
    L.append("=" * 64)
    L.append("RAW sqlmap tests parsed (per family):")
    for fam in fam_order:
        L.append("  %-16s %4d" % (fam, raw_per_family.get(fam, 0)))
    L.append("  %-16s %4d" % ("TOTAL", raw_total))
    L.append("")
    L.append("Candidate (page x payload) rows = raw-with-payload x 4 pages: %d" % len(rows))
    L.append("Fully-instantiated (context-compatible, no leftover placeholder): %d" % len(fully))
    L.append("With unresolved placeholders (will fail Route A): %d" % (len(rows) - len(fully)))
    L.append("")
    L.append("Context-compatible per page (fully instantiated):")
    for page in PAGES:
        n = sum(1 for r in fully if r["page"] == page)
        L.append("  %-8s %4d" % (page, n))
    L.append("")
    L.append("Context-compatible per family (fully instantiated, all pages):")
    for fam in fam_order:
        n = sum(1 for r in fully if r["family"] == fam)
        L.append("  %-16s %4d" % (fam, n))
    L.append("")
    L.append("NOTE on union_query (0 payloads, reported N/A by design):")
    L.append("  sqlmap's UNION tests carry an empty <payload> because a UNION injection needs the")
    L.append("  target query's EXACT column count, so sqlmap builds those payloads dynamically at")
    L.append("  runtime (<char> + <columns> range + unionTest()); there is no static string to read.")
    L.append("  Reconstructing them would mean running sqlmap's construction algorithm, not static")
    L.append("  extraction, so UNION is excluded here. It is also outside this oracle's scope: a")
    L.append("  column-matched NULL-union appends one row, it does not return all rows or bypass")
    L.append("  auth. Excluded by design, not by omission.")
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[extract] wrote %d candidate rows -> %s" % (len(rows), os.path.join(OUT, "candidates.tsv")))


if __name__ == "__main__":
    main()
