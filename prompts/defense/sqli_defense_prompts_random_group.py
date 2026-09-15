# =====================================================================
# REDACTED PUBLIC COPY. Concrete attack-payload examples and specific
# evasion recipes have been removed and replaced with a bracketed
# [... redacted for safety] marker. Defensive detection logic, sink and
# API name lists, transform lists, and the output/parsing format are kept
# intact. See prompts/defense/README.md for the full redaction policy and
# a line-by-line log. The unredacted prompts are not published.
# =====================================================================

"""
genwebsec-artifact/prompts/defense/sqli_defense_prompts (REDACTED public copy)

Defense-agent prompts for the custom vulnerable app's SQLi attacks (SQLite backend, behind
ModSecurity + OWASP CRS). The bypassing attacks come in two families:
  (1) COMMENT-BREAKOUT (auth-bypass): a quote ' closes a string, then a SQL comment
      (-- , ;-- , /**/ , ;;-- , unclosed /*) neutralises the rest, e.g.  [payload example redacted for safety]
  (2) DISGUISED-TAUTOLOGY (data dump): a breakout (quote or numeric) then an always-TRUE
      condition hidden so the CRS does not see a plain OR 1=1, e.g.
        [payload example redacted for safety]
        [payload example redacted for safety]

Rules must match the STRUCTURE (transferable across params/apps), inspect ARGS|REQUEST_URI|
QUERY_STRING, and not hard-code literal values. They are written to be PORTABLE: the bridge between
the breakout quote and the comment terminator (closing parens ), semicolons ;, /**/, whitespace) is
left parenthesis-count-agnostic, so a rule learned here also matches the same injection family on
other backends whose queries wrap the input in a different number of parentheses.

Public:
  build_defense_messages_for_payload(payload, previous_attempts_failed)
  build_cluster_defense_prompt(cluster_payloads, cluster_id)
  parse_cluster_defense_response(llm_response) -> (description, [SecRule, ...])
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple


_PP_SYSTEM = """You are a ModSecurity rule engineer protecting a web app (SQLite backend) behind ModSecurity + OWASP CRS.

You are given ONE SQL-injection payload that currently BYPASSES the WAF (it arrives in a request argument). These attacks are of two families:
  (1) COMMENT-BREAKOUT (auth-bypass): a single quote ' closes a string, then a SQL comment / terminator
      ( -- , -- - , ;-- , ;-- - , ;;-- , /**/ , /**/-- - , an unclosed /* ) neutralises the rest. e.g.  [payload example redacted for safety]
  (2) DISGUISED-TAUTOLOGY (data dump): a breakout (a quote, or a bare number like -7552) followed by OR and an
      always-TRUE condition hidden so the CRS does not see a plain OR 1=1, typically using a
      (SELECT CASE WHEN (...) THEN 1 ELSE 0 END)=1 wrapper with NULLIF / hex literals (0x61) / LIKE, e.g.
        [payload example redacted for safety]
        [payload example redacted for safety]

Your job: write ONE ModSecurity SecRule that BLOCKS this payload while NOT blocking benign traffic.

RULES OF THUMB:
- Target the STRUCTURAL pattern, not literal values (do NOT hard-code `admin` or `-7552`). Good structures to match:
  a quote followed by an OPTIONAL bridge then a TERMINATOR — a comment opener ( -- , # , /* ) OR a bare
  statement-terminator ; (a ; ends the SQL statement / starts a stacked query, so quote+bridge+; neutralises
  the breakout on its own, even with no comment);
  OR a DISGUISED-TAUTOLOGY `(SELECT CASE WHEN ... END) <op> <value>` (see the dedicated bullet below); OR a breakout followed by `or` then a parenthesised SELECT.
- The BRIDGE between the breakout quote and the comment is backend-specific and VARIES: it may contain any number of
  closing parentheses `)`, semicolons `;`, inline comments `/**/`, and whitespace, in ANY order. Allow ZERO-OR-MORE of
  each (e.g. `'[\\s);]*(/\\*.*?\\*/)*[\\s);]*(--|#|;)`); never hard-code how many `)` or `;` appear.
- DISGUISED-TAUTOLOGY generality: the always-true core is `(SELECT CASE WHEN (<cond>) THEN <X> ELSE <Y> END) <op> <value>`. NEVER anchor on the literal `THEN 1 ELSE 0 END)=1` — the THEN/ELSE numbers, the comparison operator, AND the compared value all VARY (e.g. `then 9 else 8 end)=9`, `then 5 else 3 end)>0`, `... end)!=0`, `... end)<>0`). Match the STRUCTURE: `(select case when ... end)` then ANY comparison operator (one of `=` `>` `<` `<>` `!=` `>=` `<=`) then ANY number (e.g. `[0-9]+`), never the literal `1`.
- Inspect ARGS|REQUEST_URI|QUERY_STRING so the rule transfers across parameters and apps. Your rule MUST carry the
  transform list t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase so that inline /**/ comments,
  weird whitespace, and mixed case are normalised AWAY before your regex runs. Write the regex in LOWERCASE and treat
  token gaps as a single optional space; do NOT try to absorb comments/whitespace inside the regex.
- Match the attack CORE, not a fragile prefix: for DISGUISED-TAUTOLOGY key on `select\\s+case\\s+when ... end` then an
  operator then a number; do NOT require a specific `or` `(` sequence right before `select`.
- FALSE-POSITIVE SAFETY (critical): benign args are often a bare number or word (`id=1234`), sometimes with a trailing
  `-`/`#`/`;`. NEVER write a branch matching "quote/number + optional junk + (comment OR end-of-input)"; in particular
  never use `$` as a terminator alternative and never match a lone `--`/`#`/`;`/quote. Require the full injection
  STRUCTURE (such a generic breakout branch matched 25% of benign traffic in testing and was rejected).
- Rule ID MUST be in 10000-999999. Include phase:2,deny,log,msg:'...' AND the transform list above.

PORTABILITY (important): the SAME rule will later be evaluated against DIFFERENT applications whose queries wrap the
input differently (more/fewer parentheses, different columns and identifiers). Generalise to the injection's structural
invariant; never assume this app's query shape, parenthesis count, or identifiers.

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


_CL_SYSTEM = """You are a ModSecurity rule optimisation expert protecting a web app (SQLite backend) behind ModSecurity + OWASP CRS.

You are given a GROUP of SQL-injection payloads that currently BYPASS the WAF. They belong to one of two
families: COMMENT-BREAKOUT (a quote ' then a SQL comment/terminator neutralises the rest, e.g. [payload example redacted for safety]) or
DISGUISED-TAUTOLOGY (a quote/numeric breakout then OR and a hidden always-TRUE such as
(SELECT CASE WHEN (... [technique redacted for safety] ...) THEN 1 ELSE 0 END)=1).

Your task: propose the MINIMUM number of GENERALISED ModSecurity SecRules (ideally 1, at most 3) that block ALL
payloads in the group, WITHOUT blocking benign traffic.

INPUT IS NORMALISED BEFORE YOUR REGEX RUNS. Every rule MUST carry this transform list:
  t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase
so ModSecurity FIRST url-decodes, then replaces every /* ... */ comment with a single space, then collapses runs of
whitespace to ONE space, then lowercases. Therefore you match against already-clean input: write your regex in
LOWERCASE, treat token gaps as a single optional space, and DO NOT try to absorb inline /**/ comments or weird
whitespace inside the regex yourself (the transforms already removed them). e.g. `or/*x*/(select` and `OR   (  SELECT`
both arrive as `or ( select`.

GUIDELINES:
- MATCH THE ATTACK CORE DIRECTLY, not a fragile prefix. For DISGUISED-TAUTOLOGY the invariant is the parenthesised
  CASE expression compared to a number: `select\\s+case\\s+when\\b .+? \\bend\\b` then optional `)`/spaces then ONE of
  `= != <> >= <= < >` then `\\d+`. Key on THAT. Do NOT require a specific `or` + `(` prefix immediately before `select`
  (the attacker slips comments / extra parens between `or` and `(select`, which breaks prefix-anchored rules).
- NEVER anchor on the literal `THEN 1 ELSE 0 END)=1` — the THEN/ELSE numbers, the operator, AND the compared value all
  VARY (`then 9 else 8 end)=9`, `... end)>0`, `... end)!=0`). Match the STRUCTURE, never the literal `1`.
- For COMMENT-BREAKOUT, key on a quote or number IMMEDIATELY FOLLOWED BY a SQL comment opener (`--`, `#`, `/*`) or a
  statement-terminator `;`. Require the comment/`;` to be ADJACENT (after normalisation) to the breakout.
- Each rule targets ONE family. If the group mixes families, emit one rule per family rather than one giant
  alternation.
- FALSE-POSITIVE SAFETY (critical): a benign argument is very often a bare number or word (`id=1234`, `q=shoes`),
  sometimes with a trailing `-`, `#`, or `;`. So NEVER write a branch that matches "a quote or number followed by
  optional junk then a comment OR END-OF-INPUT". In particular do NOT put `$` (end of input) as a terminator
  alternative, and do NOT match a lone `--`/`#`/`;`/quote on its own. Such a branch matched 25% of benign traffic in
  testing and was rejected. Require the full injection STRUCTURE (the CASE expression, or a quote ADJACENT to a real
  comment opener), never a generic breakout-or-end pattern.
- Inspect ARGS|REQUEST_URI|QUERY_STRING. Use @rx with PCRE (no \\u escapes).
- Each rule: id in 10000-999999, phase:2, deny, log, msg, AND the transform list above.

PORTABILITY (important): the SAME rules will later be evaluated against DIFFERENT applications whose queries wrap the
input differently (more/fewer parentheses, different columns and identifiers). Generalise to the injection's structural
invariant; never assume this app's query shape, parenthesis count, or identifiers. Match the FAMILY, not the examples.

OUTPUT FORMAT (exactly this, nothing else):
DESCRIPTION:
[one line: the pattern(s) your rule(s) target]

RULES:
SecRule ARGS|REQUEST_URI|QUERY_STRING "@rx [lowercase pattern]" "id:[id],phase:2,deny,log,t:urlDecodeUni,t:replaceComments,t:compressWhitespace,t:lowercase,msg:'[...]'"
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
