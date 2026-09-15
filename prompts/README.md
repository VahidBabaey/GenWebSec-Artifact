# Prompts

This directory holds the model prompt materials for GenWebSec. It reflects the
project's dual-use position directly: the defensive half is released, the
offensive half is not.

| Subdirectory | Contents |
| --- | --- |
| `defense/` | The defense-agent prompts, released with attack examples redacted. These are the prompts that turn confirmed bypasses into ModSecurity rules. |
| `attack/` | A statement only. The attack-agent prompts are withheld. |

## Why the split

The attack-agent prompts are the component that most directly transfers to
offensive use: they instruct a model to produce SQL-injection and cross-site
scripting payloads that evade a live WAF. Publishing them would be publishing a
payload generator. They are withheld permanently. See `attack/README.md`.

The defense-agent prompts instruct a model to write detection rules. They are
defensive, so they are released. But even a defensive prompt has to name the
attack it defends against, and ours contained concrete working payloads and a
few specific evasion recipes as teaching examples. Those examples are redacted.
The detection logic itself is kept. See `defense/README.md` for the exact policy
and a line-by-line account of what was removed.

## Generation parameters (both agents)

Read from the experiment code, not the paper.

| Parameter | Value | Source |
| --- | --- | --- |
| Provider interface | OpenRouter v1 chat-completions | `helpers/llm_client.py` |
| Client | OpenAI Python SDK 2.8.0 | `environment/requirements.txt` |
| Model (attacker, defender, baseline) | `openai/gpt-4.1-mini` | `WorkFlowV2/pilot_*_defense_v2.py` |
| `top_p` | provider default (not set) | " |

The defense-specific parameters (temperature, token limits, attempt budget) are
in `defense/README.md`. The attack-agent parameters are described in the paper's
setup and appendix; the prompts themselves are withheld.
