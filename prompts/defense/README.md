# Defense-agent prompts (redacted)

These are the prompts that turn confirmed WAF bypasses into ModSecurity rules.
They are released so that the defensive method can be inspected and reproduced.
Concrete attack-payload examples and a few specific evasion recipes have been
redacted; the detection logic is intact.

## Files

| File | Family | Grouping | Redacted from |
| --- | --- | --- | --- |
| `sqli_defense_prompts.py` | SQLi | per-payload and cluster-guided | `prompts/customapp_defense_prompts.py` |
| `xss_defense_prompts.py` | XSS | per-payload and cluster-guided | `prompts/xss_customapp_defense_prompts.py` |
| `sqli_defense_prompts_random_group.py` | SQLi | random-group control | `prompts/customapp_defense_prompts_rg.py` |
| `xss_defense_prompts_random_group.py` | XSS | random-group control | `prompts/xss_customapp_defense_prompts_rg.py` |

Each file is self-contained and holds the full set of §5 materials:

- **System prompts.** `_PP_SYSTEM` (per-payload) and `_CL_SYSTEM` (grouped).
- **User templates.** `_PP_USER` and `_CL_USER`, with `{payload}` / `{payload_list}` slots.
- **Retry prompts.** `_PP_PREV` and `_CL_PREV`, fed back after a rejected candidate so the model
  fixes the cause instead of repeating it.
- **Output format.** Described below and shown at the end of each system prompt.
- **Parsing logic.** `parse_cluster_defense_response()`, verbatim.

The random-group files are near-identical to the cluster-guided files; they differ
only in wording ("cluster" becomes "group", and the group-membership claim is
dropped). That difference is the mechanism-isolating control described in the
paper: same payloads, same group sizes, random membership.

## Generation parameters

Read from the experiment code, not the paper.

| Parameter | Value | Source (file:line) |
| --- | --- | --- |
| Model | `openai/gpt-4.1-mini` | `pilot_D1_customapp_defense_v2.py:58` |
| Temperature | 0.3 | `pilot_D1_customapp_defense_v2.py:373,452` |
| Max output tokens, grouped synthesis | 2048 | `pilot_D1_customapp_defense_v2.py:373` |
| Max output tokens, per-payload synthesis | 1024 | `pilot_D1_customapp_defense_v2.py:452` |
| Attempts per synthesis unit | 3 (`MAX_ATTEMPTS`) | `pilot_D1_customapp_defense_v2.py:60` |
| Cumulative FP tolerance | 1% (`MAX_FP_RATE`) | `pilot_D1_customapp_defense_v2.py:61` |
| Provider seed | `run_seed * 1e6 + per-call index` | `pilot_D1_customapp_defense_v2.py:527` |
| `top_p` | provider default (not set) | call sites above |

The XSS pilot (`pilot_D2_customxss_defense_v2.py`) uses the same values.

## Output format

The per-payload prompt asks for exactly one line: a single `SecRule`.

The grouped prompt asks for:

```
DESCRIPTION:
[one line: the shared pattern]

RULES:
SecRule ARGS|REQUEST_URI|QUERY_STRING "@rx [pattern]" "id:[id],phase:2,deny,log,...,msg:'[...]'"
[optional 2nd / 3rd SecRule]
```

There is no JSON response schema. The defense agent emits ModSecurity rule text,
which `parse_cluster_defense_response()` extracts. This is why the layout suggested
in `repository-materials.md` (`response-schema.json`) is intentionally absent: it
does not apply to a text-format agent, and inventing one would misrepresent what
ran.

## Redaction policy

**Redacted:** every complete or chained working attack payload, and every specific
evasion recipe (the hex-comparison tautology trick, the constructor chain, the
name-obfuscation constructions, and encoded sink-name examples). Each is replaced
in place with one of:

- `[payload example redacted for safety]`
- `[payload examples redacted for safety]`
- `[technique redacted for safety]`
- `[encoded examples redacted for safety]`

**Kept:** everything that constitutes the defense rather than an attack, namely
the detection-signature descriptions, the sink and API name lists (for example
`alert`, `eval`, `String.fromCharCode`), the SQL comment and terminator tokens,
the ModSecurity transform lists, the false-positive and ReDoS guidance, the
structural regex fragments the rules key on, the output format, and the parsing
code. These are kept for two reasons: they are the reproducible substance of the
defense, and the same detection patterns are published anyway as the generated
rules under `rules/`. Redacting them from the prompt while shipping them as rules
would be inconsistent and would add no protection.

Two harmless literals are kept because they are not attacks and are used only to
teach generalization: the username `admin` and the number `-7552`, both quoted in
a "do not hard-code these" instruction.

### What was removed, by source file

For the SQLi prompts (both the main and random-group files):

| Redacted item | Occurrences | Where |
| --- | --- | --- |
| Comment-breakout auth-bypass payload | 3 | docstring, per-payload system prompt, cluster system prompt |
| Disguised-tautology data-dump payload (numeric breakout) | 2 | docstring, per-payload system prompt |
| Disguised-tautology data-dump payload (quote breakout) | 2 | docstring, per-payload system prompt |
| Hex-comparison tautology recipe | 1 | cluster system prompt |

For the XSS prompts (both the main and random-group files):

| Redacted item | Occurrences | Where |
| --- | --- | --- |
| JS-string-breakout payload | 2 | docstring, families block |
| JS-execution-sink payload | 2 | docstring, families block |
| Comma/logical-operator invocation payloads | 1 (three snippets) | indirect-invocation guidance |
| Constructor-chain construction | 2 | families block, obfuscation guidance |
| String-concatenation name construction | 2 | families block, name-obfuscation guidance |
| Template-literal call construction | 1 | families block |
| Encoded sink-name examples | 1 (three encodings) | transform guidance |

The counts were enforced programmatically: the redaction script asserts the exact
number of occurrences for each item, and scans every output file for residual
attack tokens, before writing. A mismatch aborts the process.

## Faithfulness

Apart from the redactions above and a header banner, these files are byte-for-byte
the prompts that ran. The em-dashes and British spellings are original to the
prompts and are deliberately preserved; changing them would make the released
prompts differ from the ones used in the experiments.
