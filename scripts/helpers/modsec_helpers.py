"""
helpers.modsec_helpers

Utility functions for interacting with ModSecurity + Apache in the GenSQLi-Agentic project.

Responsibilities:
- Write ModSecurity rules to a custom rules file.
- Run apache2ctl configtest and report success / failure.
- Reload Apache.
- Probe URLs (e.g., to see if a request is blocked or allowed).
- Extract SecRule lines and payloads from LLM text.

NOTE:
- Default paths and commands are tuned for Ubuntu + Apache2 + ModSecurity,
  with a custom rules file under /etc/modsecurity/custom/.
- For portability, you can later route these through a central config module.
"""

from __future__ import annotations

import re
import time
import functools
import subprocess
import shlex
import random
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Tuple, Set

import requests

# =========================
# Configuration Defaults
# =========================

# Default path for the custom ModSecurity rules file.
# You are already using this path in your environment.
DEFAULT_RULE_PATH = Path("/etc/modsecurity/custom/sft_rule.conf")

# Commands used to test and reload Apache.
# Assumes:
#   - apache2ctl is installed at /usr/sbin/apache2ctl
#   - Apache is managed by systemd under the service name "apache2"
#   - The user running this has sudo permissions (preferably passwordless) for reload.
CONFIGTEST_CMD = "sudo /usr/sbin/apache2ctl configtest"
# Reload via `apache2ctl graceful` (a direct binary call) instead of `systemctl reload`: under a
# long run, systemctl's dbus round-trip can stall for many seconds in WSL and trip the timeout,
# even though the actual graceful reload takes ~0.1s. systemctl is kept as a fallback.
# Reload config with apache2ctl GRACEFUL (SIGUSR1 to the master). Graceful NEVER stops/starts Apache,
# so it cannot cause a :80 bind race or leave an orphaned listener (which `restart` does under WSL).
# Under WSL the apache2ctl wrapper can intermittently stall (process-table/pidof slowness); we bound
# each attempt and VERIFY Apache is serving via an HTTP probe (apache keeps serving across a graceful).
RELOAD_CMD = "sudo /usr/sbin/apache2ctl graceful"
# ROOT-CAUSE fix for the WSL reload wedge (process-table / pidof stall): signal the Apache master
# (SIGUSR1 == graceful) DIRECTLY via a tiny root wrapper that reads the pidfile — NO apache2ctl and
# NO pidof/process-table scan. reload_apache tries this first and falls back to RELOAD_CMD when the
# wrapper + its NOPASSWD sudoers rule are not installed, so behavior is unchanged until then.
# One-time install (run once, as a user with sudo):
#   sudo install -m 755 /dev/stdin /usr/local/sbin/apache-graceful <<'EOF'
#   #!/bin/sh
#   pid="$(cat /run/apache2/apache2.pid 2>/dev/null)"; [ -n "$pid" ] && exec /bin/kill -USR1 "$pid"; exit 3
#   EOF
#   printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/apache-graceful\n' "$USER" | sudo tee /etc/sudoers.d/apache-graceful >/dev/null
#   sudo chmod 440 /etc/sudoers.d/apache-graceful && sudo visudo -c
RELOAD_DIRECT_CMD = "sudo -n /usr/local/sbin/apache-graceful"
READINESS_URL = "http://localhost/"                 # any HTTP response here == Apache is serving

# Commands are fast in isolation (~0.04-0.09s) but can stall for seconds under WSL contention,
# so timeouts have headroom and configtest/reload retry on a stall (see CONFIGTEST_RETRIES above).
CONFIGTEST_RETRIES = 3          # retry on a transient timeout (NOT on a real syntax error)
DEFAULT_CONFIGTEST_TIMEOUT = 30.0
DEFAULT_RELOAD_TIMEOUT = 30.0
DEFAULT_PROBE_TIMEOUT = 5.0

# Regex + logging flag for payload extraction
_PAYLOAD_RE = re.compile(r"(?mi)^\s*Raw Input:\s*(.+?)\s*$")
ENABLE_DETAILED_LOGGING = True


# =========================
# Rule-Eval Time accounting
# =========================
# "Rule-Eval Time" = wall-clock the DEFENSE spends VALIDATING candidate rules:
#   - syntax/configuration checks (run_configtest),
#   - loading the candidate rule set so it can be exercised (reload_apache),
#   - replaying the attack + benign corpora through the WAF (timed in each pilot via
#     rule_eval_timer()).
# It is NOT the deployed WAF's per-request processing latency. Accumulated into a single
# global counter; snapshot per iteration (get_rule_eval_seconds) for per-step deltas.
_rule_eval_seconds: float = 0.0


def get_rule_eval_seconds() -> float:
    """Cumulative rule-evaluation wall-time (seconds) since the last reset."""
    return _rule_eval_seconds


def reset_rule_eval_seconds() -> None:
    """Zero the rule-eval accumulator (call once at the start of a run)."""
    global _rule_eval_seconds
    _rule_eval_seconds = 0.0


def add_rule_eval_seconds(dt: float) -> None:
    global _rule_eval_seconds
    _rule_eval_seconds += dt


@contextmanager
def rule_eval_timer():
    """Time a block of candidate-rule validation work (configtest / reload / corpus replay)."""
    t0 = time.perf_counter()
    try:
        yield
    finally:
        add_rule_eval_seconds(time.perf_counter() - t0)


def _timed_rule_eval(fn):
    """Decorator: add a function's wall-time to the rule-eval accumulator."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with rule_eval_timer():
            return fn(*args, **kwargs)
    return wrapper


# =========================
# Rule Writing
# =========================

def write_rules(
    rules: List[str],
    rule_path: Path = DEFAULT_RULE_PATH,
) -> bool:
    """
    Overwrite the ModSecurity rules file with the provided rules (one per line).

    Parameters
    ----------
    rules : List[str]
        A list of raw SecRule lines (or other ModSecurity directives).
    rule_path : Path
        Path to the rules file. Defaults to DEFAULT_RULE_PATH.

    Returns
    -------
    bool
        True on success, False on failure.
    """
    try:
        # Normalize whitespace and strip trailing spaces on each rule. Also strip a trailing
        # line-continuation backslash (a stray `\` after the closing quote): it is harmless on a
        # lone rule but in a combined file it merges the rule with the next one, triggering
        # "SecRule takes two or three arguments". A trailing `\` is never legitimate at the end of a
        # complete SecRule, so always remove it.
        normalized_rules = [re.sub(r"\\+\s*$", "", r.strip()).strip() for r in rules if r and r.strip()]
        text = "\n".join(normalized_rules) + "\n"
        rule_path.write_text(text, encoding="utf-8")
        if ENABLE_DETAILED_LOGGING:
            print(f"[modsec_helpers] Wrote {len(normalized_rules)} rule(s) to {rule_path}")
        return True
    except Exception as e:
        print(f"[modsec_helpers] Error writing rules to {rule_path}: {e}")
        return False


# =========================
# Apache / ModSecurity Control
# =========================

@_timed_rule_eval
def run_configtest(timeout: float = DEFAULT_CONFIGTEST_TIMEOUT) -> Tuple[bool, str]:
    """
    Run 'apache2ctl configtest' and return whether the configuration is valid.

    Parameters
    ----------
    timeout : float
        Timeout in seconds for the subprocess call.

    Returns
    -------
    (ok, output) : Tuple[bool, str]
        ok     : True if output contains 'Syntax OK', False otherwise.
        output : Combined stdout + stderr from apache2ctl.
    """
    # Retry ONLY on a timeout/stall (transient WSL contention); a completed run is trusted as-is,
    # so a genuine syntax error returns immediately without wasteful retries.
    last = "CONFIGTEST: no attempt"
    for attempt in range(1, CONFIGTEST_RETRIES + 2):
        try:
            proc = subprocess.run(
                shlex.split(CONFIGTEST_CMD),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            ok = "Syntax OK" in output
            if ENABLE_DETAILED_LOGGING:
                print(f"[modsec_helpers] configtest ok={ok}")
                if not ok:
                    print(f"[modsec_helpers] configtest output:\n{output}")
            return ok, output
        except subprocess.TimeoutExpired:
            last = f"CONFIGTEST TIMEOUT (timeout={timeout}s)"
            print(f"[modsec_helpers] {last} on attempt {attempt} — retrying")
            time.sleep(0.5)
            continue
        except Exception as e:
            msg = f"CONFIGTEST ERROR: {e}"
            print(f"[modsec_helpers] {msg}")
            return False, msg
    return False, last


def _apache_serving(timeout: float = 2.0) -> bool:
    """True iff Apache answers on :80 with ANY HTTP status (i.e. it is up and serving)."""
    try:
        requests.get(READINESS_URL, timeout=timeout)
        return True              # got an HTTP response (200/403/404/...) -> Apache is serving
    except Exception:
        return False             # connection refused / timeout -> Apache is down


@_timed_rule_eval
def reload_apache(timeout: float = DEFAULT_RELOAD_TIMEOUT) -> Tuple[bool, str]:
    """
    Make Apache pick up the current rules by RESTARTING via systemd, then VERIFY by probing :80.

    Why not `apache2ctl graceful` / `systemctl reload`: under WSL, Apache's control path runs Debian's
    `pidof` status check, which intermittently HANGS for *minutes*, stalling the reload and wedging the
    process table. We therefore (a) use `systemctl restart` (cgroup-based, no pidof), (b) do NOT trust
    the client's exit code or a stall — the systemd job runs asynchronously — and instead POLL until
    Apache actually serves an HTTP response. A start-limit failure is cleared by a short wait + `start`.

    Returns (ok, detail) where ok == "Apache is serving after the reload".
    """
    deadline = time.time() + max(timeout, 15.0)
    last = "no attempt"
    for attempt in range(1, 5):
        try:
            # try the direct master-signal wrapper first (no pidof); fall back to apache2ctl graceful
            proc = subprocess.run(shlex.split(RELOAD_DIRECT_CMD), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=min(timeout, 15.0))
            used = "direct-signal"
            if proc.returncode != 0:
                proc = subprocess.run(shlex.split(RELOAD_CMD), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, timeout=min(timeout, 15.0))
                used = "apache2ctl-graceful"
            last = (used + ": " + (((proc.stdout or "") + (proc.stderr or "")).strip() or f"rc={proc.returncode}"))
        except subprocess.TimeoutExpired:
            last = "graceful client stalled (apache keeps serving old config); will verify + retry"
        except Exception as e:
            last = f"graceful error: {e}"
        if ENABLE_DETAILED_LOGGING:
            print(f"[modsec_helpers] reload_apache graceful attempt {attempt}: {last[:80]}")
        # Graceful never stops Apache, so a serving probe == success (and we never restart -> no :80 orphan).
        if _apache_serving():
            return True, last
        if time.time() >= deadline:
            break
        time.sleep(1.0)
    ok = _apache_serving()
    print(f"[modsec_helpers] reload_apache {'ok' if ok else 'FAILED'} (serving={ok}); last={last[:120]}")
    return ok, last


# =========================
# HTTP Probe
# =========================

def probe_url(url: str, timeout: float = DEFAULT_PROBE_TIMEOUT) -> int:
    """
    Send a simple GET request to the given URL and return the status code.

    Parameters
    ----------
    url : str
        Target URL.
    timeout : float
        Request timeout in seconds.

    Returns
    -------
    int
        HTTP status code on success, or -1 if there was an exception.

    NOTE:
    - In your WAF test logic, a 403 often indicates that ModSecurity blocked the request.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code
    except Exception as e:
        if ENABLE_DETAILED_LOGGING:
            print(f"[modsec_helpers] probe_url error for {url}: {e}")
        return -1


# =========================
# ModSecurity internal-failure detection
# =========================
# Advisor item 2 requires recording "timeouts, server errors, and ModSecurity internal
# failures SEPARATELY from WAF false positives." A ModSecurity rule-EXECUTION failure
# (e.g. "Execution error - PCRE limits exceeded (-8)" from a pathological @rx pattern)
# is written to the Apache error log but does NOT change the HTTP status, so a benign
# classifier that only inspects the response status silently misses it. We count such
# lines in the error-log window spanning a single benign-corpus replay.

MODSEC_ERROR_LOG = Path("/var/log/apache2/error.log")

# Match GENUINE rule execution/processing failures only. Normal operation lines
# ("ModSecurity: Access denied ..." = a 403 block; "ModSecurity: Warning. ..." = a
# paranoia-level pattern match) never contain these phrases, so they are excluded by
# construction, as are the one-time startup banners (compiled-version / StatusEngine).
_MODSEC_INTERNAL_RE = re.compile(
    r"ModSecurity:[^\n]*?"
    r"(?:Execution error|Rule execution error|PCRE limits exceeded|PCRE match limit"
    r"|match limit exceeded|recursion limit|regex error|failed to (?:compile|match)"
    r"|internal error)",
    re.IGNORECASE,
)


def modsec_error_log_offset(log_path: Path = MODSEC_ERROR_LOG) -> int:
    """Current byte size of the Apache error log (0 if unreadable). Snapshot this
    BEFORE a benign replay, then pass it to count_modsec_internal_failures() after."""
    try:
        return log_path.stat().st_size
    except Exception:
        return 0


def count_modsec_internal_failures(since_offset: int,
                                   log_path: Path = MODSEC_ERROR_LOG) -> Tuple[int, int]:
    """Count ModSecurity rule-execution / internal-failure log lines appended since
    `since_offset`. Returns (new_offset, count). Never raises: on any read error, or a
    log rotation (current size < since_offset), it degrades gracefully -- a rotation
    reads the fresh file from 0, an unreadable log returns (since_offset, 0). Only the
    delta since the offset is read, so the multi-hundred-MB error log is never slurped."""
    try:
        size = log_path.stat().st_size
        start = since_offset if size >= since_offset else 0   # rotation/truncation guard
        with open(log_path, "rb") as f:
            f.seek(start)
            chunk = f.read()
        text = chunk.decode("utf-8", errors="replace")
        count = sum(1 for line in text.splitlines() if _MODSEC_INTERNAL_RE.search(line))
        return size, count
    except Exception:
        return since_offset, 0


# =========================
# SecRule & Payload Extraction
# =========================

def extract_secrule(text: str, normalize_space: bool = True) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract a single SecRule line from a block of text (e.g., LLM output).

    The function tries, in order:
    1) A line like: 'rule: SecRule ...'
    2) Any line starting with 'SecRule'
    3) A 'SecRule ... \"...\"' pattern anywhere in the text

    Parameters
    ----------
    text : str
        Input text (e.g., full LLM response).
    normalize_space : bool
        If True, collapse multiple spaces into single spaces and strip ends.

    Returns
    -------
    (rule, error) : Tuple[Optional[str], Optional[str]]
        rule  : The extracted SecRule line (normalized if requested), or None if not found.
        error : None if a rule was found, otherwise a string reason like "no SecRule found".
    """
    if not isinstance(text, str):
        return None, "no SecRule found"

    # Priority 1: Look for "rule: SecRule..."
    m = re.search(r"(?im)^\s*rule\s*:\s*(SecRule[^\r\n]*)", text, re.MULTILINE)
    if m:
        rule = m.group(1)
        if normalize_space:
            rule = re.sub(r"\s+", " ", rule).strip()
        return rule, None

    # Priority 2: Any line starting with SecRule
    m = re.search(r"(?im)^\s*(SecRule[^\r\n]*)", text, re.MULTILINE)
    if m:
        rule = m.group(1)
        if normalize_space:
            rule = re.sub(r"\s+", " ", rule).strip()
        return rule, None

    # Priority 3: SecRule anywhere in double quotes
    m = re.search(r"SecRule\s+[^\n\"]+\s+\"[^\"]*\"", text, re.DOTALL)
    if m:
        rule = m.group(0)
        if normalize_space:
            rule = re.sub(r"\s+", " ", rule).strip()
        return rule, None

    return None, "no SecRule found"


def extract_payload_from_prompt(prompt_text: str) -> Optional[str]:
    """
    Extract the attack payload from mixed prompt/response text.

    Looks for lines of the form:
        Raw Input: <payload>

    Returns the LAST such payload found.

    Parameters
    ----------
    prompt_text : str
        Full text (prompt + response) to search.

    Returns
    -------
    Optional[str]
        The extracted payload string, or None if not found.
    """
    if not isinstance(prompt_text, str):
        return None

    matches = _PAYLOAD_RE.findall(prompt_text or "")
    if not matches:
        return None

    payload = matches[-1].strip()
    if ENABLE_DETAILED_LOGGING and payload:
        print(f"[modsec_helpers] Extracted payload: {payload[:80]}...")
    return payload


# =========================
# Rule ID Management
# =========================

def extract_rule_id(rule: str) -> Optional[int]:
    """
    Extract the rule ID from a SecRule line.

    Parameters
    ----------
    rule : str
        A SecRule line (e.g., 'SecRule ARGS "@rx ..." "id:123456,phase:2,..."')

    Returns
    -------
    Optional[int]
        The extracted ID as an integer, or None if not found.

    Example
    -------
    >>> extract_rule_id('SecRule ARGS "@rx test" "id:123456,phase:2,deny"')
    123456
    """
    if not isinstance(rule, str):
        return None

    # Look for id:<number> pattern in the rule
    m = re.search(r'\bid:(\d+)\b', rule, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def replace_rule_id(rule: str, new_id: int) -> str:
    """
    Replace the rule ID in a SecRule line with a new ID.

    Parameters
    ----------
    rule : str
        A SecRule line containing an id:<number> pattern.
    new_id : int
        The new ID to use.

    Returns
    -------
    str
        The rule with the ID replaced.

    Example
    -------
    >>> replace_rule_id('SecRule ARGS "@rx test" "id:900001,phase:2,deny"', 123456)
    'SecRule ARGS "@rx test" "id:123456,phase:2,deny"'
    """
    if not isinstance(rule, str):
        return rule

    # Replace id:<old_number> with id:<new_id>
    return re.sub(r'\bid:\d+\b', f'id:{new_id}', rule, flags=re.IGNORECASE)


def generate_unique_rule_id(used_ids: Set[int], min_id: int = 10000, max_id: int = 999999) -> int:
    """
    Generate a unique random rule ID that hasn't been used.

    Parameters
    ----------
    used_ids : Set[int]
        Set of IDs that are already in use.
    min_id : int
        Minimum ID value (default: 10000).
    max_id : int
        Maximum ID value (default: 999999).

    Returns
    -------
    int
        A unique random ID in the range [min_id, max_id].

    Raises
    ------
    RuntimeError
        If no unique ID can be found after 10000 attempts.
    """
    # Try up to 10000 times to find a unique ID
    for _ in range(10000):
        new_id = random.randint(min_id, max_id)
        if new_id not in used_ids:
            return new_id

    # If we couldn't find a unique ID after 10000 attempts, raise an error
    raise RuntimeError(f"Could not generate unique rule ID after 10000 attempts. Used IDs: {len(used_ids)}/{max_id - min_id + 1}")


def ensure_unique_rule_id(rule: str, used_ids: Set[int]) -> Tuple[str, int]:
    """
    Ensure a SecRule has a unique ID, replacing it if necessary.

    This function:
    1. Extracts the current ID from the rule
    2. If the ID is already used or not in range 10000-999999, generates a new unique ID
    3. Replaces the ID in the rule
    4. Returns the updated rule and the final ID

    Parameters
    ----------
    rule : str
        A SecRule line.
    used_ids : Set[int]
        Set of IDs that are already in use.

    Returns
    -------
    (updated_rule, final_id) : Tuple[str, int]
        updated_rule : The rule with a unique ID.
        final_id     : The ID that was assigned.

    Example
    -------
    >>> used = {123456, 234567}
    >>> ensure_unique_rule_id('SecRule ARGS "@rx test" "id:123456,phase:2,deny"', used)
    ('SecRule ARGS "@rx test" "id:345678,phase:2,deny"', 345678)
    """
    current_id = extract_rule_id(rule)

    # Check if we need to replace the ID
    needs_replacement = (
        current_id is None or
        current_id in used_ids or
        current_id < 10000 or
        current_id > 999999
    )

    if needs_replacement:
        new_id = generate_unique_rule_id(used_ids)
        updated_rule = replace_rule_id(rule, new_id)
        if ENABLE_DETAILED_LOGGING:
            print(f"[modsec_helpers] Replaced rule ID {current_id} -> {new_id}")
        return updated_rule, new_id
    else:
        # ID is valid and unique, keep it
        return rule, current_id


def ensure_transforms(rule: str, transforms: List[str]) -> str:
    """Ensure a SecRule's action list applies the given input-normalisation transforms
    (e.g. t:removeComments, t:compressWhitespace, t:lowercase). LLM-generated rules routinely
    OMIT these, which lets trivial comment / whitespace / case obfuscation defeat an otherwise
    correct regex (empirically: a tautology rule blocked 374/385 obfuscated attacks WITHOUT
    transforms vs 385/385 WITH them, at 0 FP either way). This rewrites the action list so it
    carries EXACTLY `transforms`: any pre-existing t:... tokens are stripped, then the canonical
    set is inserted right after the id: token. The operator/regex segment is left untouched.

    If the rule does not parse into the expected `SecRule <targets> "<operator>" "<actions>"`
    shape it is returned unchanged (a later configtest catches anything malformed)."""
    if not transforms:
        return rule
    m = re.match(r'^(SecRule\s+\S+\s+"(?:[^"\\]|\\.)*"\s+")(.*)("\s*)$', rule, re.S)
    if not m:
        return rule
    head, actions, tail = m.group(1), m.group(2), m.group(3)
    actions = re.sub(r'\s*,?\s*t:[A-Za-z]+', '', actions)     # strip transforms the model emitted
    tstr = ",".join(transforms)
    if re.search(r'id:\d+', actions):                          # insert canonically after id:NNN
        actions = re.sub(r'(id:\d+)', r'\1,' + tstr, actions, count=1)
    else:
        actions = tstr + "," + actions
    actions = re.sub(r',\s*,', ',', actions)                   # tidy any doubled commas
    return head + actions + tail
