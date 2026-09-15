#!/usr/bin/env python3
"""
Item 8 (SQLi), CSIC/Torpeda track -- step: extract + dedup + map.

Read the public CSIC/Torpeda SQLi attack partition (non-LLM, tool-generated),
extract the distinct injected SQLi payload values, and map each to our 4 pages
by AS-IS injection (each distinct payload is sent unchanged as that page's
parameter value; Route A later decides which contexts it is valid in).

Pure string ops only (WSL `re`/urllib segfault). Reads only the public dataset.

Reads : PublicDataset/SQLi.csv
Writes: csic/corpus/candidates.tsv   (distinct payload x 4 pages, with provenance)
        csic/corpus/counts.txt       (raw rows, distinct-by-value, distinct-by-structure)
"""
import csv
import os

ROOT = "/path/to/GenWebSec"
BASE = os.path.join(ROOT, "results/V2/NonLLM_Results")
SRC = os.path.join(BASE, "PublicDataset", "SQLi.csv")
OUT = os.path.join(BASE, "csic", "corpus")
os.makedirs(OUT, exist_ok=True)

PAGES = ["login", "search", "product", "filter"]
INJ = (" or ", " and ", "union", "select", "--", "#", "/*", "'", "\"", ";",
       "sleep", "benchmark", "waitfor", "concat", "char(", "cast(", "0x", "dbms_pipe")


def urldecode(s):
    s = s.replace("+", " ")
    parts = s.split("%")
    out = [parts[0]]
    for p in parts[1:]:
        if len(p) >= 2:
            try:
                out.append(chr(int(p[:2], 16)) + p[2:])
            except ValueError:
                out.append("%" + p)
        else:
            out.append("%" + p)
    return "".join(out)


def struct_key(s):
    """Collapse digit runs to '#' (random-literal-insensitive structure key)."""
    out, run = [], False
    for ch in s:
        if ch.isdigit():
            if not run:
                out.append("#")
                run = True
        else:
            out.append(ch)
            run = False
    return "".join(out)


def looks_injected(v):
    low = str(v).lower()
    for h in INJ:
        if str(h) in low:
            return True
    return False


def main():
    rows = 0
    seen = {}          # payload_value -> (src_file, src_id, src_param)
    with open(SRC, encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        for row in r:
            rows += 1
            q = row.get("query")
            if not isinstance(q, str):
                continue
            for pair in q.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                val = str(urldecode(v)).strip()
                if val and looks_injected(val) and val not in seen:
                    seen[val] = (row.get("file", ""), row.get("id", ""), k)

    payloads = list(seen.keys())
    structs = {}
    for p in payloads:
        structs.setdefault(struct_key(p), p)

    # ---- candidates: distinct-by-value payload x 4 pages, injected AS-IS ----
    cols = ["idx", "page", "payload_id", "final_payload", "src_file", "src_id", "src_param", "structure_key"]
    with open(os.path.join(OUT, "candidates.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        i = 0
        for pid, val in enumerate(payloads):
            sf, sid, sp = seen[val]
            sk = struct_key(val)
            safe = val.replace("\t", " ").replace("\r", " ").replace("\n", " ")
            for page in PAGES:
                f.write("\t".join([str(i), page, str(pid), safe, sf, sid, sp, sk]) + "\n")
                i += 1

    # ---- technique mix among distinct payloads ----
    def cnt(sub):
        return sum(1 for p in payloads if sub in p.lower())

    L = []
    L.append("Item 8 (SQLi) CSIC/Torpeda track -- extract + dedup + map")
    L.append("source: PublicDataset/SQLi.csv (public, tool-generated, non-LLM)")
    L.append("mapping: AS-IS injection (each distinct payload sent unchanged as each page's param value)")
    L.append("=" * 70)
    L.append("RAW rows (SQLi-labelled HTTP requests): %d" % rows)
    L.append("Distinct injected payload VALUES: %d" % len(payloads))
    L.append("Distinct payload STRUCTURES (digit runs -> '#'): %d" % len(structs))
    L.append("Candidate rows (distinct-by-value x 4 pages): %d" % (len(payloads) * 4))
    L.append("")
    L.append("Technique-indicator counts among distinct payloads:")
    for label, sub in [("OR ' or '", " or "), ("AND ' and '", " and "), ("UNION", "union"),
                       ("SELECT", "select"), ("line comment --", "--"), ("hash comment #", "#"),
                       ("block comment /*", "/*"), ("stacked ';'", ";"), ("SLEEP", "sleep"),
                       ("BENCHMARK", "benchmark"), ("WAITFOR", "waitfor"), ("CONCAT", "concat"),
                       ("CHAR(", "char("), ("CAST(", "cast("), ("hex 0x", "0x"),
                       ("DBMS_PIPE", "dbms_pipe")]:
        L.append("  %-20s %6d" % (label, cnt(sub)))
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[csic-extract] wrote %d candidate rows -> %s" % (len(payloads) * 4, os.path.join(OUT, "candidates.tsv")))


if __name__ == "__main__":
    main()
