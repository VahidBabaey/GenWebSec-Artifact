#!/usr/bin/env python3
"""
Item 8 (XSS) Dalfox track -- extract + map.

Statically extract Dalfox's JS-context XSS payloads from its Rust source
(src/payload/xss_javascript.rs: XSS_JAVASCRIPT_PAYLOADS "for inJS" and
XSS_JAVASCRIPT_PAYLOADS_SMALL), un-escape the Rust string literals, dedup, and
map each to our two JS-context pages using Dalfox's own breakout (js_breakout.rs):

  Search  (var query='<input>', single-quote JS string; app backslash-escapes ')
          -> escaped breakout   \\';<JS>//     (matches the app filter + seed)
          -> plain   breakout    ';<JS>//      (variant; Route A decides)
  Calculator (eval("document.write(<input>)"), JS expression position)
          -> <JS> direct

Pure string ops (WSL re/urllib segfault). Reads only Dalfox source.

Reads : tools/dalfox/src/payload/xss_javascript.rs
Writes: xss_dalfox/corpus/candidates.tsv, xss_dalfox/corpus/counts.txt
"""
import os

ROOT = "/path/to/GenWebSec"
SRC = os.path.join(ROOT, "tools/dalfox/src/payload/xss_javascript.rs")
OUT = os.path.join(ROOT, "results/V2/NonLLM_Results/xss_dalfox/corpus")
os.makedirs(OUT, exist_ok=True)
DALFOX_COMMIT = "ad2888756d87972acd021bc82adb44cf85698132"


def parse_rust_str(line):
    """Return the first double-quoted Rust string literal on the line, un-escaped."""
    i = line.find('"')
    if i < 0:
        return None
    i += 1
    out = []
    while i < len(line):
        c = line[i]
        if c == '\\' and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == '\\':
                out.append('\\'); i += 2; continue
            if nxt == '"':
                out.append('"'); i += 2; continue
            if nxt == "'":
                out.append("'"); i += 2; continue
            if nxt == 'n':
                out.append('\n'); i += 2; continue
            if nxt == 't':
                out.append('\t'); i += 2; continue
            if nxt == 'r':
                out.append('\r'); i += 2; continue
            # keep any other backslash-escape literally (e.g. \x61, \141 meant for JS)
            out.append('\\'); out.append(nxt); i += 2; continue
        if c == '"':
            return "".join(out)      # closing quote
        out.append(c); i += 1
    return "".join(out)


def extract_arrays(path):
    arrays = {}
    cur = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if ("XSS_JAVASCRIPT_PAYLOADS" in line) and ("&[" in line) and ("=" in line):
                name = line.split(":")[0].split()[-1]
                cur = name
                arrays[cur] = []
                continue
            if cur is not None:
                if line.strip().startswith("];"):
                    cur = None
                    continue
                if '"' in line:
                    p = parse_rust_str(line)
                    if p:
                        arrays[cur].append(p)
    return arrays


def main():
    arrays = extract_arrays(SRC)
    # provenance: payload -> first source array that had it
    js_payloads = {}
    for name in ("XSS_JAVASCRIPT_PAYLOADS", "XSS_JAVASCRIPT_PAYLOADS_SMALL"):
        for p in arrays.get(name, []):
            if p not in js_payloads:
                js_payloads[p] = name
    payloads = list(js_payloads.keys())

    # map each JS payload to the two pages via Dalfox's breakout
    VARIANTS = [
        ("search", "search_escaped", lambda js: "\\';" + js + "//"),
        ("search", "search_plain",   lambda js: "';" + js + "//"),
        ("calc",   "calc_direct",    lambda js: js),
    ]

    cols = ["idx", "page", "variant", "js_payload", "final_payload", "source_array"]
    rows = []
    i = 0
    for js in payloads:
        for page, variant, fn in VARIANTS:
            final = fn(js)
            safe_js = js.replace("\t", " ").replace("\r", " ").replace("\n", " ")
            safe_final = final.replace("\t", " ").replace("\r", " ").replace("\n", " ")
            rows.append([str(i), page, variant, safe_js, safe_final, js_payloads[js]])
            i += 1

    with open(os.path.join(OUT, "candidates.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    L = []
    L.append("Item 8 (XSS) Dalfox track -- extract + map")
    L.append("source: tools/dalfox/src/payload/xss_javascript.rs (non-LLM, public)")
    L.append("dalfox commit: " + DALFOX_COMMIT)
    L.append("=" * 66)
    for name in ("XSS_JAVASCRIPT_PAYLOADS", "XSS_JAVASCRIPT_PAYLOADS_SMALL"):
        L.append("  %-32s %3d payloads" % (name, len(arrays.get(name, []))))
    L.append("Distinct JS payloads (deduped across both arrays): %d" % len(payloads))
    L.append("Candidate rows (distinct x 3 variants): %d" % len(rows))
    L.append("")
    L.append("Variants: search_escaped (\\';<JS>//), search_plain (';<JS>//), calc_direct (<JS>)")
    L.append("")
    L.append("Sample mapped payloads:")
    for js in payloads[:6]:
        L.append("  JS: %s" % js[:80])
        L.append("     search_escaped: %s" % ("\\';" + js + "//")[:90])
        L.append("     calc_direct   : %s" % js[:90])
    with open(os.path.join(OUT, "counts.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")

    print("\n".join(L))
    print("\n[dalfox-extract] wrote %d candidate rows -> %s" % (len(rows), os.path.join(OUT, "candidates.tsv")))


if __name__ == "__main__":
    main()
