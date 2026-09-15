# =====================================================================
# REDACTED PUBLIC COPY. Concrete attack-payload examples and specific
# evasion recipes have been removed and replaced with a bracketed
# [... redacted for safety] marker. Defensive detection logic, sink and
# API name lists, transform lists, and the output/parsing format are kept
# intact. See prompts/defense/README.md for the full redaction policy and
# a line-by-line log. The unredacted prompts are not published.
# =====================================================================

"""
genwebsec-artifact/prompts/defense/xss_defense_prompts (REDACTED public copy)

Defense-agent prompts for the custom XSS app (behind ModSecurity + OWASP CRS). The bypassing
attacks are TAG-LESS JavaScript (no <script>/<img>/on...= handlers — CRS already blocks those) and
come in two families:
  (1) JS-STRING BREAKOUT (Search page): input lands in  var query='<input>';  where the app escapes
      ' -> \\' . A leading backslash makes \\' become \\\\' (escaped backslash + real closing quote),
      breaks out of the string, runs JS, and ends with //  e.g.   [payload example redacted for safety]
  (2) JS-EXECUTION SINK (Calculator page): input goes straight into  eval("document.write(<input>)")
      and runs as code, no quotes to break  e.g.   [payload example redacted for safety]

Both families ultimately INVOKE a JavaScript execution sink (alert/prompt/confirm/print/eval/
setTimeout/setInterval/Function/constructor/document.write), possibly OBFUSCATED. Rules must match the
STRUCTURE (transferable to other apps such as bWAPP xss_json / xss_eval), inspect
ARGS|REQUEST_URI|QUERY_STRING, and not hard-code one literal sink.

Public:
  build_defense_messages_for_payload(payload, previous_attempts_failed)
  build_cluster_defense_prompt(cluster_payloads, cluster_id)
  parse_cluster_defense_response(llm_response) -> (description, [SecRule, ...])
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple


_FAMILIES = """The bypassing XSS here is TAG-LESS JavaScript (no <script>/<img>/on...= handlers — those are already blocked by CRS) and comes in two families:
  (1) JS-STRING BREAKOUT: the input lands inside a single-quoted JavaScript string ( var query='<input>'; ) and the app escapes ' -> \\'. The attacker prefixes a BACKSLASH so \\' becomes \\\\' (an escaped backslash then a real closing quote), breaks out of the string, runs JavaScript, and ends with // to comment out the trailing quote.  e.g.   [payload example redacted for safety]
  (2) JS-EXECUTION SINK: the input is placed straight into a JavaScript execution sink ( eval("document.write(<input>)") ) and runs as code with no quotes to break.  e.g.   [payload example redacted for safety]

Both families ultimately INVOKE a JavaScript execution sink: a call to one of
  alert, prompt, confirm, print, eval, setTimeout, setInterval, Function, constructor, document.write / write
possibly OBFUSCATED via property/bracket access (window[...], top[...], self.alert, globalThis[...]),
string concatenation ([technique redacted for safety]), template-literal calls ([technique redacted for safety]), the array/function constructor
trick ([technique redacted for safety]), or String.fromCharCode."""

_GUIDE = """RULES OF THUMB:
- Match the STRUCTURE, never a single literal like `alert(1)`. Good structures to match:
  * a JS execution sink being CALLED: a sink NAME (alert|prompt|confirm|print|eval|setTimeout|setInterval|Function|constructor|write) followed (after optional whitespace/comments) by `(` OR a backtick ` (template-literal call);
  * the JS-STRING BREAKOUT marker: one-or-more backslashes then a single quote ( \\\\+' ) that closes the string;
  * an OBFUSCATED invocation: bracket/property access into a sink ( (window|top|self|globalThis|document)\\s*\\[ , or \\.constructor\\b , or the [technique redacted for safety] trick, or String.fromCharCode , or a `]` / `)` immediately followed by a backtick = call-via-template-literal ).
  * an INDIRECT INVOCATION (IMPORTANT — a large bypass family): the sink is NAMED but NOT written as
    sink( — it is handed to ANOTHER function that calls it. Examples: passed as a CALLBACK to a
    higher-order function ( .map / .forEach / .find / .flatMap / .some / .every / .reduce / Array.from /
    Reflect.apply / .then / .forEach.call ), or invoked via the comma or logical operators
    ( [payload examples redacted for safety] ), or via bracket access on a global
    ( window / top / self / globalThis / document / parent / frames / opener  followed by [ ). In ALL
    of these the bare sink IDENTIFIER appears (alert / prompt / confirm) even though there is no  sink(
    anywhere. Because benign traffic (product searches, arithmetic) NEVER contains these JavaScript
    sink words, you SHOULD ALSO match the BARE sink identifier as a whole word (a word-boundary regex
    on alert|prompt|confirm) — this is false-positive-safe here and blocks the entire
    indirect-invocation family at once.
  * NAME OBFUSCATION: the sink NAME itself may be assembled from pieces rather than written literally —
    hex escapes (backslash-x-HH), unicode escapes (backslash-u-HHHH), String.fromCharCode, or string
    concatenation ([technique redacted for safety]). Match these constructions where you can, since a name-obfuscated sink
    will not contain the literal word.
- Sink names AND obfuscation VARY across payloads — do NOT anchor on one literal. Match the FAMILY: ANY of the sink names, with optional whitespace before the `(` or backtick.
- INPUT IS DECODED BEFORE YOUR REGEX RUNS. Every rule MUST carry this transform list:
  t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:compressWhitespace
  so ModSecurity url-decodes, HTML-entity-decodes, JS-decodes (\\xHH, \\uHHHH), and compresses whitespace
  FIRST. Therefore an encoded sink name ([encoded examples redacted for safety]) arrives as the plain word alert:
  match the DECODED form (the literal sink word), and do NOT try to match the encodings yourself.
  Do NOT use t:lowercase: JavaScript is case-sensitive (AlErT does not run) and the benign corpus contains
  the word "print", so lowercasing plus a loose match would false-positive. Match sink names as written (lowercase).
- Inspect ARGS|REQUEST_URI|QUERY_STRING so the rule transfers across parameters and apps. Use @rx (no \\u escapes).
- AVOID false positives: benign traffic is normal search words (including apostrophes like O'Brien, men's) and arithmetic (2+2, 100*5, (7+8)/2). Do NOT match a bare apostrophe, a bare backslash, or arithmetic. Require the XSS EXECUTION structure (a sink call, or the backslash-quote breakout followed by JavaScript). In particular the word "print" appears in benign traffic (fingerprint, blueprint, ...), so NEVER match a bare `print` — require `print` immediately followed by `(` or a backtick.
- PERFORMANCE — no catastrophic backtracking (ReDoS): keep every regex CHEAP and LINEAR. Do NOT use
  nested or overlapping quantifiers such as (.*)* , (.+)+ , (a|a)* , or (.*?)+ , and do NOT place a .*
  on BOTH sides of a large alternation. Such patterns blow up ModSecurity's matching time, so benign
  requests TIME OUT and the rule is rejected as a self-inflicted DoS. Prefer anchored, bounded patterns
  and explicit negated character classes (e.g. [^']* rather than .*) so matching stays linear.
- Rule ID MUST be in 10000-999999. Include phase:2,deny,log,msg:'...' AND the transform list t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:compressWhitespace.

PORTABILITY (important): the SAME rule(s) will later be evaluated against DIFFERENT apps whose sink is wrapped differently (e.g. bWAPP xss_json's JS-string, xss_eval's eval(document.write(...))). Generalise to the XSS structural invariant; never assume this app's exact wrapper. Match the FAMILY, not the examples."""


_PP_SYSTEM = f"""You are a ModSecurity rule engineer protecting a web app behind ModSecurity + OWASP CRS.

You are given ONE Cross-Site Scripting (XSS) payload that currently BYPASSES the WAF (it arrives in a request argument). {_FAMILIES}

Your job: write ONE ModSecurity SecRule that BLOCKS this payload (and its obfuscation family) while NOT blocking benign traffic.

{_GUIDE}

OUTPUT:
- Output EXACTLY ONE line: the SecRule. No explanation, no markdown, no backticks."""

_PP_USER = """The following payload currently BYPASSES the WAF and must be blocked:

Raw payload:
{payload}

{previous_block}Write ONE SecRule that blocks this payload (and its obfuscation family) with no false positives on benign traffic. Output only the SecRule line."""

_PP_PREV = """Previous attempts for this payload FAILED (do not repeat them; try a different, more precise pattern):
{previous_attempts_failed}

"""


def build_defense_messages_for_payload(payload: str, previous_attempts_failed: str = "") -> List[Dict[str, str]]:
    prev = _PP_PREV.format(previous_attempts_failed=previous_attempts_failed) if previous_attempts_failed else ""
    user = _PP_USER.format(payload=payload, previous_block=prev)
    return [{"role": "system", "content": _PP_SYSTEM}, {"role": "user", "content": user}]


_CL_SYSTEM = f"""You are a ModSecurity rule optimisation expert protecting a web app behind ModSecurity + OWASP CRS.

You are given a GROUP of Cross-Site Scripting (XSS) payloads that currently BYPASS the WAF. {_FAMILIES}

Your task: propose the MINIMUM number of GENERALISED ModSecurity SecRules (ideally 1, at most 3) that block ALL payloads in the group, WITHOUT blocking benign traffic.

{_GUIDE}

OUTPUT FORMAT (exactly this, nothing else):
DESCRIPTION:
[one line: the pattern(s) your rule(s) target]

RULES:
SecRule ARGS|REQUEST_URI|QUERY_STRING "@rx [pattern]" "id:[id],phase:2,deny,log,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:compressWhitespace,msg:'[...]'"
[optional 2nd / 3rd SecRule]"""

_CL_USER = """Group #{cluster_id} contains {n} payloads that bypass the WAF:
{payload_list}

{previous_block}Propose the MINIMAL set of generalised SecRules (1-3) that block ALL of them with no false positives. Use the required DESCRIPTION / RULES output format."""

_CL_PREV = """YOUR PREVIOUS ATTEMPT(S) ON THIS GROUP FAILED — read carefully and FIX the cause, do not repeat them:
{previous_attempts_failed}

"""


def build_cluster_defense_prompt(cluster_payloads: List[str], cluster_id: int,
                                 previous_attempts_failed: str = "") -> List[Dict[str, str]]:
    payload_list = "\n".join(f"  {i+1}. {p}" for i, p in enumerate(cluster_payloads))
    prev = _CL_PREV.format(previous_attempts_failed=previous_attempts_failed) if previous_attempts_failed else ""
    user = _CL_USER.format(cluster_id=cluster_id, n=len(cluster_payloads),
                           payload_list=payload_list, previous_block=prev)
    return [{"role": "system", "content": _CL_SYSTEM}, {"role": "user", "content": user}]


def parse_cluster_defense_response(llm_response: str) -> Tuple[str, List[str]]:
    """Extract (description, [SecRule, ...]) from the cluster defense response."""
    description = ""
    rules: List[str] = []
    section = None
    for line in llm_response.split("\n"):
        up = line.upper().strip()
        if up.startswith("DESCRIPTION:"):
            section = "desc"
            rest = line.split(":", 1)[1].strip()
            if rest:
                description = rest
            continue
        if up.startswith("RULES:") or up.startswith("RULE:"):
            section = "rules"
            continue
        s = line.strip()
        if section == "desc" and s and not s.startswith("```"):
            description = (description + " " + s).strip()
        elif s.startswith("SecRule"):
            rules.append(s.replace("```", "").strip())
    if not rules:
        rules = [r.strip() for r in re.findall(r"SecRule\s+[^\n]+", llm_response, re.IGNORECASE)]
    return description.strip(), rules
