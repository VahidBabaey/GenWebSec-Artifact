"""
NewWorkFlow.pilot_D1_customapp_defense

Defense-Only (D1) rule learning for the custom vulnerable app, COMBINED in one script:
  - PAGE  in {login, search, product, filter}  -> which corpus + which WAF param/endpoint
  - MODE  in {per_payload, clustering}         -> how rules are generated

Corpus = the page's VALID + WAF-BYPASSING attacks (from the A1 attack run). A RANDOM,
non-duplicate sample of up to MAX_CORPUS is used.

Per iteration:
  1. apply all accepted rules; find which corpus attacks still BYPASS the WAF.
  2. PER_PAYLOAD : one SecRule per unblocked attack (<=3 attempts), accepted if it blocks the
                  attack AND keeps FP <= MAX_FP_RATE on benign traffic.
     CLUSTERING : DBSCAN-cluster the unblocked attacks, generate 1-3 GENERALISED rules per
                  cluster, accepted on the same criteria.
  3. converge when all attacks are blocked (or MAX_ITERATIONS).
The attack is sent to the WAF exactly as the A1 experiment sent it (same param/method).
"""
from __future__ import annotations

import sys
import os
import random
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple

import numpy as np
import Levenshtein
# Clustering (CG-Static) uses DBSCAN with min_samples=1, which is by definition connected-components
# of the eps-neighborhood graph; computed directly in cluster_payloads() (no sklearn) because the
# sklearn/scipy C-extension import segfaults intermittently (~90%) on this WSL box. Verified
# label-identical to scikit-learn's DBSCAN across eps in {0.1..0.5}.

sys.path.insert(0, str(Path(__file__).parent.parent))

from helpers.llm_client import call_llm, get_llm_stats, reset_llm_stats
from helpers.modsec_helpers import (
    write_rules, run_configtest, reload_apache, extract_secrule, ensure_unique_rule_id,
    ensure_transforms,
    rule_eval_timer, get_rule_eval_seconds, reset_rule_eval_seconds,
    modsec_error_log_offset, count_modsec_internal_failures,
)
from prompts.customapp_defense_prompts_rg import (   # RG-dedicated prompts: identical to CG except they do NOT claim the payloads form a similar cluster
    build_defense_messages_for_payload, build_cluster_defense_prompt, parse_cluster_defense_response,
)

# ============================================================================
# CONFIGURATION
# ============================================================================
PAGE = os.environ.get("D1_PAGE", "product")   # "login" | "search" | "product" | "filter"
MODE = os.environ.get("D1_MODE", "per_payload")  # "per_payload" | "clustering"

MODEL = "openai/gpt-4.1-mini"
MAX_ITERATIONS = 10
MAX_ATTEMPTS = 3          # attempts per attack (per_payload) or per cluster (clustering)
MAX_FP_RATE = 0.01        # 1% false-positive tolerance
# item (defense-robustness): IDENTICAL defense agent to the co-evolution pilot (C1). Every generated
# rule is normalised with these transforms so obfuscation (inline /**/ comments, whitespace, case)
# collapses before the regex runs. Enforced on EVERY rule (LLMs routinely omit transforms).
DEFENSE_TRANSFORMS = ["t:urlDecodeUni", "t:replaceComments", "t:compressWhitespace", "t:lowercase"]
MAX_CORPUS = 300          # RANDOM, non-duplicate sample
RANDOM_SEED = int(os.environ.get("D1_SEED", "42"))   # item 1: seed for independent repeated runs (reproducible corpus sample)
# random-group control (reviewer PP-vs-CG): dedicated RNG for the random partition, seeded from
# RANDOM_SEED so the shuffle is reproducible and INDEPENDENT of the corpus-sampling RNG above.
_RG_RNG = random.Random(RANDOM_SEED)

# item 1: give every defense LLM call a distinct, reproducible provider seed derived from RANDOM_SEED
# (mirrors the attack agent's RUN_SEED-derived per-call seed) so BOTH agents are fully seed-controlled.
_llm_call_idx = 0
def defense_llm_seed() -> int:
    global _llm_call_idx
    _llm_call_idx += 1
    return RANDOM_SEED * 1_000_000 + _llm_call_idx

CLUSTERING_EPS = float(os.environ.get("D1_EPS", "0.3"))   # item 6: sweepable DBSCAN threshold
CLUSTER_COVERAGE = float(os.environ.get("D1_COVERAGE", "1.0"))   # item 7: min fraction of a cluster its rules must cover
# item 10: budget/efficiency accounting (additive; existing metrics untouched)
_ITEM10 = {"def_calls": 0, "candidates": 0, "accepted": 0, "failed_clusters": 0,
           "cluster_attempts": 0, "clusters_processed": 0}   # item 10: faithful accepted/rejected + per-cluster retry counters
_PRICE_IN, _PRICE_OUT = 0.40, 1.60   # openai/gpt-4.1-mini USD per 1M tokens (approx; cost estimate)
CLUSTERING_MIN_SAMPLES = 1   # 1 => NO noise: every attack is clustered (isolated ones become
                             # singleton clusters), so a rule is generated for ALL selected attacks
MAX_PAYLOADS_PER_PROMPT = 15

RELOAD_TIMEOUT = 10.0
PROBE_TIMEOUT = 5.0

WAF = "http://localhost"   # Apache + ModSecurity + OWASP CRS

PAGE_CFG = {
    "login":   {"param": "username", "method": "POST", "extra": {"password": "x"}},
    "search":  {"param": "q",        "method": "GET",  "extra": {}},
    "product": {"param": "id",       "method": "GET",  "extra": {}},
    "filter":  {"param": "category", "method": "GET",  "extra": {}},
}
CFG = PAGE_CFG[PAGE]
PARAM, METHOD, EXTRA = CFG["param"], CFG["method"], CFG["extra"]

CORPUS_DIR = Path(__file__).parent.parent / "results" / "V2" / "_item1_corpus"   # item 1/10: pooled union of the 5 A1 attack seeds' winners (shared by PP-Static & CG-Static)
CORPUS_FILE = CORPUS_DIR / f"A1_customapp_{PAGE}_winners.txt"

DATA_DIR = Path(__file__).parent.parent / "data"   # verified-benign FP corpus lives here

RESULTS_DIR = Path(__file__).parent.parent / "results" / "V2" / os.environ.get("D1_OUTBASE", "Random-Groups") / ("CustomApp_D1" + (f"_eps{CLUSTERING_EPS}" if MODE in ("clustering", "random_group") else "") + (f"_seed{RANDOM_SEED}" if os.environ.get("D1_SEED") else ""))   # random-group control: default output under results/V2/Random-Groups/ (eps- and seed-tagged)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = RESULTS_DIR / f"D1_customapp_{PAGE}_{MODE}.txt"
RULES_FILE = RESULTS_DIR / f"D1_customapp_{PAGE}_{MODE}_rules.txt"

# advisor item 2: CRS-only benign baseline (set in main) + benign requests already blocked, so the
# final FP report can show the FP ADDED over CRS and which benign requests become NEWLY blocked.
CRS_FP: Dict[str, float] = {"fp": 0, "errors": 0, "tested": 0, "fp_rate": 0.0, "modsec_internal": 0}
PREV_BLOCKED_IDS: Set[str] = set()


def log_print(msg: str):
    print(msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


# ============================================================================
# corpus (random, non-duplicate 300-sample) + benign FP corpus
# ============================================================================
def load_corpus() -> List[str]:
    attacks = [l.strip() for l in CORPUS_FILE.read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.startswith("#")]
    attacks = list(dict.fromkeys(attacks))         # de-duplicate, preserve order
    import re as _re
    _struct = _re.compile(r"""['"<>();=/*#\\]|--""")
    if len(attacks) > MAX_CORPUS:
        if RANDOM_SEED is not None:
            random.seed(RANDOM_SEED)
        _sample = random.sample(attacks, MAX_CORPUS)   # per-seed sample (unchanged from before)
        _clean = [a for a in _sample if _struct.search(a)]
        _need = MAX_CORPUS - len(_clean)
        if _need > 0:   # corpus hygiene: a degenerate non-injection token (e.g. 'epsilon') was sampled;
                        # drop it and top back up to MAX_CORPUS with clean draws so the corpus stays 300.
            _dropped = [a for a in _sample if not _struct.search(a)]
            _in = set(_sample)
            _remaining = [a for a in attacks if a not in _in and _struct.search(a)]
            _repl = random.sample(_remaining, _need)   # deterministic top-up (continues the seeded RNG)
            log_print(f"  [corpus hygiene] replaced degenerate {_dropped} with clean draw(s) {_repl} to keep {MAX_CORPUS}")
            _clean = _clean + _repl
        attacks = _clean
    else:
        attacks = [a for a in attacks if _struct.search(a)]
    return attacks


def _build_benign_inline() -> List[Tuple[str, str, str]]:
    """Minimal hand-written fallback if the generated benign files are missing."""
    out: List[Tuple[str, str, str]] = []
    for u, pw in [("admin", "Sup3rS3cret!Admin"), ("mmuster", "Pa$$w0rd1"),
                  ("jdoe", "wrongpw"), ("guest", "guest"), ("alice", "alice123")]:
        out.append(("login", "POST", urllib.parse.urlencode({"username": u, "password": pw})))
    for q in ["juice", "mug", "shirt", "water", "tea", "apple", "orange", "bottle",
              "sticker", "notebook", "coffee", "tote", "smoothie", "green"]:
        out.append(("search", "GET", urllib.parse.urlencode({"q": q})))
    for i in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 25, 999]:
        out.append(("product", "GET", urllib.parse.urlencode({"id": i})))
    for c in ["drinks", "apparel", "accessories", "stationery", "books", "toys"]:
        out.append(("filter", "GET", urllib.parse.urlencode({"category": c})))
    return out


BENIGN_FILE = DATA_DIR / "benignurls.txt"   # single aggregated FP corpus (full URLs)


def build_benign() -> List[Tuple[str, str, str]]:
    """Load the verified-benign FP corpus produced by customapp/generate_benign.py — every line
    was confirmed to PASS the baseline WAF, so it is genuinely benign. Returns (page, method,
    querystring) for ALL four pages, so a global rule that over-blocks ANY page's normal traffic
    is caught. The page (and thus the original method, e.g. login=POST) is recovered from the URL
    path, so fidelity is preserved even though everything lives in one file.

    Order of preference: aggregated data/benignurls.txt -> per-page data/benign_<page>.txt -> inline."""
    out: List[Tuple[str, str, str]] = []
    if BENIGN_FILE.exists():
        for line in BENIGN_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = urllib.parse.urlparse(line)
            page = parsed.path.rsplit("/", 1)[-1].replace(".php", "")
            cfg = PAGE_CFG.get(page)
            if cfg and parsed.query:
                out.append((page, cfg["method"], parsed.query))
        if out:
            return out
    for page, cfg in PAGE_CFG.items():          # fallback: per-page files
        f = DATA_DIR / f"benign_{page}.txt"
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append((page, cfg["method"], line))
    if not out:
        log_print("  WARNING: no benign corpus found — falling back to small inline benign set")
        return _build_benign_inline()
    return out


# ============================================================================
# WAF probe (same transport the A1 experiment used)
# ============================================================================
def probe(page: str, method: str, sent: str, timeout: float = 8.0) -> Tuple[int, bool]:
    """Returns (status, errored). errored=True on timeout/connection failure."""
    if method == "GET":
        req = urllib.request.Request(f"{WAF}/customapp/{page}?{sent}")   # app.py serves non-.php routes (matches the A1 corpus endpoint)
    else:
        req = urllib.request.Request(f"{WAF}/customapp/{page}", data=sent.encode(), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with rule_eval_timer():     # WAF replay of attack/benign corpus = rule-eval work
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, False
        except urllib.error.HTTPError as e:
            return e.code, False
        except Exception:
            return -1, True


def attack_blocked(payload: str) -> bool:
    params = dict(EXTRA); params[PARAM] = payload
    st, _ = probe(PAGE, METHOD, urllib.parse.urlencode(params))
    return st == 403


def test_benign(benign: List[Tuple[str, str, str]], full: bool = False) -> Dict[str, object]:
    """Replay the benign corpus through the WAF and CLASSIFY each response (advisor item 2):
      - HTTP 403                              = false positive (a real WAF block of legitimate traffic);
      - HTTP 5xx / timeout / transport error  = SERVER ERROR, recorded SEPARATELY, never a FP;
      - ModSecurity rule-EXECUTION failures (e.g. "Execution error - PCRE limits exceeded") that are
        logged to the Apache error log but return HTTP 200: counted SEPARATELY as modsec_internal, by
        diffing the error log over the replay window. These are silent (status-invisible) so a status-only
        classifier would miss them (advisor item 2: record ModSec internal failures separately from FPs).
    full=False early-stops once (fp + errors) exceed the 1% budget (fast reject during acceptance);
    full=True replays the whole corpus for the reported cumulative rate and returns the exact set of
    benign requests that were blocked (used to flag NEWLY-blocked traffic per iteration)."""
    fp_budget = int(MAX_FP_RATE * len(benign))
    tested = fp = errors = 0
    blocked_ids: List[str] = []
    _log_off = modsec_error_log_offset()     # item 2: snapshot the error log before the replay window
    for page, method, sent in benign:
        tested += 1
        st, err = probe(page, method, sent, timeout=PROBE_TIMEOUT)
        if err:
            st, err = probe(page, method, sent, timeout=PROBE_TIMEOUT)   # retry once: a transient Apache hiccup is not a FP
        if err:
            errors += 1
        elif st == 403:
            fp += 1
            blocked_ids.append(f"{page}?{sent}")
        elif st >= 500:
            errors += 1
        if not full and (fp + errors) > fp_budget:
            break
    _, modsec_internal = count_modsec_internal_failures(_log_off)   # item 2: silent ModSec exec failures this window
    return {"tested": tested, "fp": fp, "errors": errors,
            "modsec_internal": modsec_internal, "blocked_ids": blocked_ids}


def apply_accepted_rules(accepted_rules: List[str]) -> List[str]:
    """Write all accepted rules + configtest; if the combined set fails, drop the offender; reload."""
    if not accepted_rules:
        write_rules([]); run_configtest(); reload_apache(timeout=RELOAD_TIMEOUT)
        return accepted_rules
    write_rules(accepted_rules)
    ok, _ = run_configtest()
    if not ok:
        log_print("ERROR: configtest failed with accumulated rules; finding the offender...")
        for rule in list(accepted_rules):
            write_rules([rule])
            if not run_configtest()[0]:
                log_print(f"  dropping problematic rule:\n{rule}")
                accepted_rules = [r for r in accepted_rules if r != rule]
        write_rules(accepted_rules); run_configtest()
    reload_apache(timeout=RELOAD_TIMEOUT)
    return accepted_rules


# ============================================================================
# clustering (DBSCAN on 1 - Levenshtein.ratio) -- only used in MODE="clustering"
# With min_samples=1 there are NO noise points: similar attacks group together and every
# isolated attack forms its own singleton cluster, so EVERY selected attack ends up in a cluster.
# ============================================================================
def _distance_matrix(payloads: List[str]) -> np.ndarray:
    n = len(payloads)
    d = np.zeros((n, n))
    for i in range(n):
        for j in range(i + 1, n):
            d[i, j] = d[j, i] = 1.0 - Levenshtein.ratio(payloads[i], payloads[j])
    return d


def cluster_payloads(payloads: List[str]) -> Dict[int, List[str]]:
    if not payloads:
        return {}
    if len(payloads) == 1:
        return {0: payloads}
    # DBSCAN(eps=CLUSTERING_EPS, min_samples=1, metric='precomputed') is, by definition, the connected
    # components of the graph where dist(i,j) <= eps: with min_samples=1 every point is a core point, so
    # there are no noise points and clusters are exactly the eps-connected groups. We compute that directly
    # from the Levenshtein distance matrix (verified label-identical to scikit-learn's DBSCAN across
    # eps in {0.1..0.5} and n in {300,800}) because the sklearn/scipy/numpy.f2py import segfaults
    # intermittently (~90%) under WSL. CLUSTERING_MIN_SAMPLES stays 1; this is the same clustering.
    d = _distance_matrix(payloads)
    n = len(payloads)
    parent = list(range(n))
    def _find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for i in range(n):
        for j in range(i + 1, n):
            if d[i, j] <= CLUSTERING_EPS:
                ri, rj = _find(i), _find(j)
                if ri != rj:
                    parent[ri] = rj
    # label clusters 0..k-1 in first-appearance order (matches scikit-learn DBSCAN's labeling)
    clusters: Dict[int, List[str]] = {}
    label_of: Dict[int, int] = {}
    for i in range(n):
        root = _find(i)
        if root not in label_of:
            label_of[root] = len(label_of)
        clusters.setdefault(label_of[root], []).append(payloads[i])
    return clusters


def random_group_partition(payloads: List[str]) -> Dict[int, List[str]]:
    """Random-group control (reviewer's proposed baseline for PP-vs-CG). Partition `payloads`
    into groups whose SIZES equal the real DBSCAN cluster sizes on the SAME payloads (identical
    size multiset), but with RANDOM membership. This isolates whether cluster-guided synthesis
    benefits from structural coherence (true clusters) or merely from being shown several attacks
    jointly (any grouping of the same sizes). Everything downstream is identical to clustering."""
    if not payloads:
        return {}
    real = cluster_payloads(payloads)                       # real cluster SIZE distribution at CLUSTERING_EPS
    sizes = sorted((len(v) for v in real.values()), reverse=True)
    items = list(payloads)
    _RG_RNG.shuffle(items)                                  # randomise membership; sizes preserved below
    groups: Dict[int, List[str]] = {}
    idx = 0
    for gi, sz in enumerate(sizes):
        groups[gi] = items[idx:idx + sz]
        idx += sz
    if idx < len(items):                                    # safety: never drop a payload
        groups[len(sizes) - 1].extend(items[idx:])
    return groups


def cluster_rep(cluster: List[str]) -> List[str]:
    if len(cluster) <= MAX_PAYLOADS_PER_PROMPT:
        return cluster
    idx = np.linspace(0, len(cluster) - 1, MAX_PAYLOADS_PER_PROMPT, dtype=int)
    return [cluster[i] for i in idx]


def _fp_reject_note(attempt: int, rid: int, fp: Dict[str, object], fp_rate: float) -> str:
    """Actionable feedback for the NEXT attempt: which benign requests the rejected rule wrongly
    blocked, so the LLM drops the offending branch instead of re-emitting it blind."""
    samples = ", ".join(list(fp.get("blocked_ids", []))[:4])   # type: ignore[arg-type]
    return (f"attempt {attempt} id={rid}: FALSE-POSITIVED on {fp['fp']} benign request(s) "
            f"({fp_rate*100:.2f}%), e.g. {samples}. One branch of your rule matches BENIGN input "
            f"(often a bare number/word, or a value ending in -/#/;). REMOVE that branch and match ONLY "
            f"the full injection structure; never match a bare number/quote followed by a comment or end-of-input.")


def generate_rules_for_cluster(cluster: List[str], cluster_id: int, used_ids: Set[int],
                               benign, accepted_rules: List[str], cluster_size: int) -> Tuple[List[str], List[str]]:
    # item 7: `cluster` = members of the observed cluster C still bypassing R_t; `cluster_size` = |C|.
    # Keep rules until ClusterCoverage(R_t u accepted, C) >= CLUSTER_COVERAGE (default 100%), accepting only
    # rules that add MARGINAL coverage; still-uncovered members are returned and carried forward (never dropped).
    already = cluster_size - len(cluster)           # members of C already covered by R_t
    log_print(f"\n  [GROUP {cluster_id}] size {cluster_size}: {already} covered by R_t, {len(cluster)} to cover")
    for i, p in enumerate(cluster, 1):                  # item 7(f): full cluster membership (not truncated)
        log_print(f"      {i}. {p}")
    accepted: List[str] = []
    blocked: Set[str] = set()                       # cluster members now blocked by R_t u accepted
    failed_notes: List[str] = []                    # feedback: rejected candidates + WHY (fed back to the LLM next attempt)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        remaining = [p for p in cluster if p not in blocked]
        reps = cluster_rep(remaining)               # item 7(f): the ACTUAL representatives shown to the LLM this attempt
        log_print(f"      attempt {attempt}: {len(reps)} representative(s) of {len(remaining)} uncovered sent to LLM:")
        for i, rp in enumerate(reps, 1):
            log_print(f"          rep {i}. {rp}")
        # identical defense agent to C1: feed prior rejections (+ the benign strings they wrongly blocked)
        # back to the LLM so it fixes the cause instead of re-emitting the same FP-prone rule.
        messages = build_cluster_defense_prompt(reps, cluster_id, previous_attempts_failed="\n".join(failed_notes))
        try:
            resp = call_llm(model=MODEL, messages=messages, max_tokens=2048, temperature=0.3, seed=defense_llm_seed())
            _ITEM10["def_calls"] += 1   # item 10
        except Exception as e:
            log_print(f"      attempt {attempt}: LLM error {e}"); continue
        log_print("      [raw LLM response — full, untruncated]:\n" + resp)
        desc, candidate_rules = parse_cluster_defense_response(resp)
        _ITEM10["candidates"] += len(candidate_rules)   # item 10
        log_print(f"      attempt {attempt}: {len(candidate_rules)} candidate rule(s) — {desc}")
        for rule_text in candidate_rules:
            rule_text, rid = ensure_unique_rule_id(rule_text, used_ids)
            rule_text = ensure_transforms(rule_text, DEFENSE_TRANSFORMS)   # enforce input-normalisation transforms
            log_print(f"        candidate id={rid}: {rule_text}")   # item 7(f): full text of EVERY candidate (accepted or rejected)
            # cumulative (item 2): load R_t u accepted u {candidate}; coverage + FP measured on that whole set.
            write_rules(accepted_rules + accepted + [rule_text])
            ok, out = run_configtest()
            if not ok:
                log_print(f"        x syntax error: {out}")
                failed_notes.append(f"attempt {attempt} id={rid}: SYNTAX ERROR ({out[:60]}). Emit ONE valid single-line SecRule.")
                continue
            if not reload_apache(timeout=RELOAD_TIMEOUT)[0]:
                log_print("        x apache reload failed"); continue
            now = {p for p in cluster if attack_blocked(p)}
            marginal = len(now - blocked)           # item 7: NEW cluster members this rule covers
            if marginal <= 0:
                log_print(f"        x no marginal coverage (covers {len(now)}/{len(cluster)} already-known); id={rid}")
                failed_notes.append(f"attempt {attempt} id={rid}: matched 0 NEW group members (too narrow / wrong anchor). "
                                    f"Key on the tautology CORE `select case when ... end <op> number` directly, not on an `or (` prefix before select.")
                continue
            fp = test_benign(benign)
            fp_rate = fp["fp"] / fp["tested"] if fp["tested"] else 0.0
            cov = already + len(now)
            log_print(f"        +{marginal} new -> coverage {cov}/{cluster_size} ({100.0*cov/cluster_size:.0f}%); "
                      f"cumFP {fp['fp']}/{fp['tested']} ({fp_rate*100:.2f}%); errors {fp['errors']}; id={rid}")
            if fp_rate <= MAX_FP_RATE and fp["errors"] <= CRS_FP["errors"]:
                # item 2 (2c): confirm on the COMPLETE benign corpus (unconditional full replay) before
                # accepting, exactly as the per-payload path does, so the accept always reflects the full corpus.
                fp = test_benign(benign, full=True)
                fp_rate = fp["fp"] / fp["tested"] if fp["tested"] else 0.0
                if fp_rate <= MAX_FP_RATE and fp["errors"] <= CRS_FP["errors"]:
                    log_print(f"        ACCEPTED (adds coverage; full-corpus confirm cumFP={fp['fp']}/{fp['tested']} ({fp_rate*100:.2f}%))")
                    accepted.append(rule_text); used_ids.add(rid); blocked = now
                    _ITEM10["accepted"] += 1   # item 10
                else:
                    log_print(f"        x REJECTED: full-corpus confirm cumFP {fp_rate*100:.2f}% errors {fp['errors']} over budget")
                    failed_notes.append(_fp_reject_note(attempt, rid, fp, fp_rate))
            elif fp["errors"] > CRS_FP["errors"]:
                log_print(f"        x REJECTED: adds {fp['errors'] - CRS_FP['errors']} server error(s) on benign (not a FP)")
                failed_notes.append(f"attempt {attempt} id={rid}: caused {fp['errors'] - CRS_FP['errors']} server error(s) on benign traffic; simplify the regex (avoid catastrophic backtracking).")
            else:
                log_print(f"        x REJECTED: cumFP {fp_rate*100:.2f}% over budget")
                failed_notes.append(_fp_reject_note(attempt, rid, fp, fp_rate))
        if already + len(blocked) >= CLUSTER_COVERAGE * cluster_size:   # item 7: stop once coverage met
            break
    _ITEM10["cluster_attempts"] += attempt   # item 10: attempts (retries) used on this cluster
    _ITEM10["clusters_processed"] += 1
    uncovered = [p for p in cluster if p not in blocked]
    if uncovered:
        _ITEM10["failed_clusters"] += 1   # item 10
    cov = already + len(blocked)
    log_print(f"  [GROUP {cluster_id}] coverage {already}/{cluster_size} -> {cov}/{cluster_size} "
              f"({100.0*cov/cluster_size:.0f}%); rules={len(accepted)}; uncovered={len(uncovered)} (carried forward)")
    for up in uncovered:                                # item 7(f): identities of still-uncovered members (not just the count)
        log_print(f"        uncovered (carried forward): {up}")
    return accepted, uncovered


# ============================================================================
# per-payload rule generation -- only used in MODE="per_payload"
# ============================================================================
def generate_rule_for_payload(p: str, used_ids: Set[int], benign, failed: List[str],
                              accepted_rules: List[str]) -> str | None:
    """Per-payload defense: one SecRule for ONE bypassing attack, <=MAX_ATTEMPTS attempts. Two-stage
    acceptance: (1) the rule must block its OWN attack when deployed ALONE (CRS + this rule only), so
    the block is unambiguously this rule's doing, not an earlier accepted rule; (2) with the rule added
    to the kept set, the CUMULATIVE benign false-positive rate must stay <= MAX_FP_RATE with no new
    server errors (advisor item 2)."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        prev = "\n".join(failed)
        messages = build_defense_messages_for_payload(payload=p, previous_attempts_failed=prev)
        try:
            resp = call_llm(model=MODEL, messages=messages, max_tokens=1024, temperature=0.3, seed=defense_llm_seed())
            _ITEM10["def_calls"] += 1   # item 10
        except Exception as e:
            log_print(f"      attempt {attempt}: LLM error {e}"); continue
        rule_text, err = extract_secrule(resp.strip())
        if not rule_text:
            failed.append(f"attempt {attempt}: extraction failed ({err})"); continue
        rule_text, rid = ensure_unique_rule_id(rule_text, used_ids)
        rule_text = ensure_transforms(rule_text, DEFENSE_TRANSFORMS)   # enforce input-normalisation transforms
        _ITEM10["candidates"] += 1   # item 10
        # STEP 1 (attribution): does THIS rule block the attack ON ITS OWN? Deploy the candidate ALONE
        # (CRS + this rule only, no accepted rules). Because p is a CRS-bypassing payload, CRS never
        # blocks it, so a block here is unambiguously THIS rule's doing (not an earlier accepted rule).
        write_rules([rule_text])
        if not run_configtest()[0]:
            failed.append(f"attempt {attempt}: syntax error; rule: {rule_text}"); continue
        if not reload_apache(timeout=RELOAD_TIMEOUT)[0]:
            failed.append(f"attempt {attempt}: apache reload failed"); continue
        if not attack_blocked(p):
            log_print(f"      attempt {attempt}: rule-alone blocks_attack=False -> reject  id={rid}")
            failed.append(f"attempt {attempt}: rule does not block its own attack; rule: {rule_text}")
            continue
        # STEP 2 (item 2 gate): deploy the kept set + this candidate together and require the CUMULATIVE
        # benign FPR of the whole ruleset to stay <= MAX_FP_RATE with no new server errors.
        write_rules(accepted_rules + [rule_text])
        if not run_configtest()[0]:
            failed.append(f"attempt {attempt}: cumulative syntax error; rule: {rule_text}"); continue
        if not reload_apache(timeout=RELOAD_TIMEOUT)[0]:
            failed.append(f"attempt {attempt}: apache reload failed (cumulative)"); continue
        fp = test_benign(benign)
        fp_rate = fp["fp"] / fp["tested"] if fp["tested"] else 0.0
        log_print(f"      attempt {attempt}: rule-alone blocks_attack=True  cumFP={fp['fp']}/{fp['tested']} "
                  f"({fp_rate*100:.2f}%)  errors={fp['errors']}  id={rid}")
        if fp_rate <= MAX_FP_RATE and fp["errors"] <= CRS_FP["errors"]:
            # item 2 (2c): confirm acceptance on the COMPLETE benign corpus before accepting
            # (unconditional full replay — the accept decision always reflects the full corpus).
            fp = test_benign(benign, full=True)
            fp_rate = fp["fp"] / fp["tested"] if fp["tested"] else 0.0
            if fp_rate <= MAX_FP_RATE and fp["errors"] <= CRS_FP["errors"]:
                log_print(f"      attempt {attempt}: full-corpus confirm OK cumFP={fp['fp']}/{fp['tested']} ({fp_rate*100:.2f}%) id={rid} -> ACCEPT")
                used_ids.add(rid); _ITEM10["accepted"] += 1   # item 10
                return rule_text
            log_print(f"      attempt {attempt}: full-corpus confirm FAILED cumFP={fp_rate*100:.2f}% errors={fp['errors']} -> reject")
        if fp["errors"] > CRS_FP["errors"]:
            failed.append(f"attempt {attempt}: adds {fp['errors'] - CRS_FP['errors']} server error(s) on benign; rule: {rule_text}")
        else:
            _samples = ", ".join(list(fp.get("blocked_ids", []))[:4])   # benign requests this rule wrongly blocked
            failed.append(f"attempt {attempt}: cumFP {fp_rate*100:.2f}% -- wrongly blocked benign e.g. {_samples}; "
                          f"remove the branch matching benign input (never match a bare number/quote + comment/end); rule: {rule_text}")
    return None


# ============================================================================
# main
# ============================================================================
def _tok_io():
    """Cumulative (input_tokens, output_tokens) consumed so far — used for per-step deltas."""
    s = get_llm_stats()
    return s["total_input_tokens"], s["total_output_tokens"]


def pct(n: int, d: int) -> float:
    return 100.0 * n / d if d else 0.0


def main():
    for f in (LOG_FILE, RULES_FILE):
        if f.exists():
            f.unlink()
    log_print("=" * 80)
    log_print(f"D1 Custom-App Defense — page={PAGE}  mode={MODE}")
    log_print("=" * 80)
    log_print(f"Model: {MODEL}   Corpus: {CORPUS_FILE.name}")
    log_print(f"Max iterations: {MAX_ITERATIONS}   Max attempts: {MAX_ATTEMPTS}   Max FP: {MAX_FP_RATE*100}%   "
              f"sample: random {MAX_CORPUS} (seed={RANDOM_SEED})")
    log_print(f"[item9] defense LLM provider seed = RANDOM_SEED*1e6 + per-call index (run seed={RANDOM_SEED}); temperature=0.3")
    log_print("=" * 80)

    reset_llm_stats()
    _run_start = datetime.now()   # item 10
    corpus = load_corpus()
    benign = build_benign()
    log_print(f"Loaded {len(corpus)} attack payloads (deduped, random sample) and {len(benign)} benign requests\n")

    write_rules([]); run_configtest(); reload_apache(timeout=RELOAD_TIMEOUT)

    # advisor item 2: CRS-only benign baseline (full replay, no early-stop) so the final FP report
    # can show the false positives ADDED over CRS and flag benign requests NEWLY blocked by our rules.
    _crs = test_benign(benign, full=True)
    CRS_FP.update({"fp": _crs["fp"], "errors": _crs["errors"], "tested": _crs["tested"],
                   "fp_rate": pct(_crs["fp"], _crs["tested"]), "modsec_internal": _crs["modsec_internal"]})
    PREV_BLOCKED_IDS.update(_crs["blocked_ids"])
    log_print(f"[baseline] CRS-only benign FP: {_crs['fp']}/{_crs['tested']} "
              f"({CRS_FP['fp_rate']:.2f}%); server errors {_crs['errors']}; "
              f"ModSec internal failures {_crs['modsec_internal']}\n")

    accepted_rules: List[str] = []
    used_ids: Set[int] = set()
    failed_notes: Dict[str, List[str]] = {p: [] for p in corpus}
    history = []

    reset_rule_eval_seconds()                    # exclude the baseline (clean-CRS) reload above
    for it in range(MAX_ITERATIONS):
        log_print("\n" + "=" * 80)
        log_print(f"ITERATION {it}   ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})")
        log_print("=" * 80)

        _in0, _out0 = _tok_io()                  # token snapshot before this iteration's defense LLM calls
        _re0 = get_rule_eval_seconds()           # rule-eval-time snapshot
        _s0 = get_llm_stats(); _lat0 = _s0["total_latency_s"]; _calls0 = _s0["num_llm_calls"]  # latency/call snapshot
        _cand0 = _ITEM10["candidates"]           # candidate-rule snapshot
        accepted_rules = apply_accepted_rules(accepted_rules)
        unblocked = [p for p in corpus if not attack_blocked(p)]
        log_print(f"Blocked: {len(corpus)-len(unblocked)}/{len(corpus)}   Unblocked: {len(unblocked)}")
        if not unblocked:
            log_print("\nAll attacks blocked -> defense converged.")
            _in1, _out1 = _tok_io(); _s1 = get_llm_stats()
            history.append({"iter": it, "blocked": len(corpus), "rules": len(accepted_rules), "clusters": 0, "fp": 0.0,
                            "modsec_internal": 0, "added_modsec": 0,
                            "in_tokens": _in1 - _in0, "out_tokens": _out1 - _out0,
                            "rule_eval_s": get_rule_eval_seconds() - _re0,
                            "latency_s": _s1["total_latency_s"] - _lat0, "llm_calls": _s1["num_llm_calls"] - _calls0,
                            "candidates": _ITEM10["candidates"] - _cand0})
            break

        rules_added = 0
        n_clusters = 0
        if MODE == "per_payload":
            for idx, p in enumerate(unblocked, 1):
                log_print(f"\n[{idx}/{len(unblocked)}] attack: {p}")
                rule = generate_rule_for_payload(p, used_ids, benign, failed_notes[p], accepted_rules)
                if rule:
                    accepted_rules.append(rule); rules_added += 1
                    log_print(f"  ACCEPTED: {rule}")
                else:
                    log_print(f"  FAILED after {MAX_ATTEMPTS} attempts")
        else:  # clustering OR random_group (reviewer control): same pipeline, different grouping
            if MODE == "random_group":
                clusters = random_group_partition(unblocked)
                log_print(f"[random-group] eps={CLUSTERING_EPS}: sizes matched to the real DBSCAN cluster sizes, membership randomised")
            else:
                clusters = cluster_payloads(unblocked)
            n_clusters = len(clusters)
            sizes = sorted((len(v) for v in clusters.values()), reverse=True)
            singles = sum(1 for v in clusters.values() if len(v) == 1)
            _stats_tag = "random-group stats" if MODE == "random_group" else "cluster-stats"
            log_print(f"[{_stats_tag} eps={CLUSTERING_EPS}] groups={n_clusters}  "
                      f"singleton%={100.0*singles/n_clusters if n_clusters else 0.0:.1f}  "
                      f"mean={float(np.mean(sizes)) if sizes else 0.0:.2f}  median={float(np.median(sizes)) if sizes else 0.0:.1f}  max={max(sizes) if sizes else 0}")
            if MODE == "random_group":
                log_print(f"RANDOM GROUPS: {n_clusters} group(s) covering ALL {len(unblocked)} attack(s); "
                          f"{singles} singleton(s); all sizes: {sizes}  "
                          f"(sizes are COPIED from the real DBSCAN cluster sizes so the control is size-matched; "
                          f"GROUP MEMBERSHIP IS RANDOM — no clustering is used to assign payloads to groups)")
            else:
                log_print(f"DBSCAN(min_samples={CLUSTERING_MIN_SAMPLES}): {n_clusters} cluster(s) "
                          f"covering ALL {len(unblocked)} attack(s) — no noise; "
                          f"{singles} singleton(s); all sizes: {sizes}")
            # FULL, UNTRUNCATED record of the partition in the LOG (.txt): every group -> ALL its member
            # payloads, logged UNCONDITIONALLY so groups later skipped because already covered are still
            # stored in full. Nothing here is truncated.
            log_print(f"[FULL partition dump] iter {it}: {n_clusters} groups; sizes {sizes}; every member of every group listed below:")
            for _cid in sorted(clusters.keys()):
                log_print(f"  group {_cid} (size {len(clusters[_cid])}):")
                for _gi, _gp in enumerate(clusters[_cid], 1):
                    log_print(f"    {_gi}. {_gp}")
            for cid in sorted(clusters.keys()):
                still = [p for p in clusters[cid] if not attack_blocked(p)]
                if not still:
                    continue
                new_rules, _uncov = generate_rules_for_cluster(still, cid, used_ids, benign, accepted_rules, len(clusters[cid]))
                accepted_rules.extend(new_rules); rules_added += len(new_rules)
                apply_accepted_rules(accepted_rules)   # keep accumulated set live for next cluster

        # metrics with ALL accepted rules
        accepted_rules = apply_accepted_rules(accepted_rules)
        blocked_now = sum(1 for p in corpus if attack_blocked(p))
        # advisor item 2: full benign replay (no early-stop) against the WHOLE accepted set = true
        # cumulative FP + server-error rate; report the FP ADDED over the CRS-only baseline, and the
        # benign requests NEWLY blocked this iteration.
        fp = test_benign(benign, full=True)
        fp_rate = pct(fp["fp"], fp["tested"])
        err_rate = pct(fp["errors"], fp["tested"])
        added_fp_rate = max(0.0, fp_rate - CRS_FP["fp_rate"])
        mi = fp["modsec_internal"]                                # item 2: silent ModSec internal failures on benign
        added_mi = max(0, mi - int(CRS_FP["modsec_internal"]))    # added over the CRS-only baseline
        newly = [b for b in fp["blocked_ids"] if b not in PREV_BLOCKED_IDS]
        PREV_BLOCKED_IDS.update(fp["blocked_ids"])
        if newly:
            log_print(f"  [benign] {len(newly)} benign request(s) NEWLY blocked this iteration:")
            for b in newly:
                log_print(f"        {b}")
        log_print(f"\nITER {it} SUMMARY: blocked={blocked_now}/{len(corpus)} ({100*blocked_now/len(corpus):.1f}%)  "
                  f"rules={len(accepted_rules)}  rules_added={rules_added}  "
                  f"{'clusters='+str(n_clusters)+'  ' if MODE=='clustering' else ''}"
                  f"FP={fp_rate:.2f}% (added {added_fp_rate:.2f}% vs CRS; errors {fp['errors']} = {err_rate:.2f}%; "
                  f"modsecFail {mi} added {added_mi})")
        # full audit (per request): the COMPLETE list of accepted rules at the end of this iteration
        log_print(f"\n  Accepted rules after iteration {it} ({len(accepted_rules)} total):")
        for _ri, _r in enumerate(accepted_rules, 1):
            log_print(f"    [{_ri}] {_r}")
        _in1, _out1 = _tok_io()
        step_in, step_out = _in1 - _in0, _out1 - _out0
        step_eval = get_rule_eval_seconds() - _re0
        _s1 = get_llm_stats()
        step_lat = _s1["total_latency_s"] - _lat0
        step_calls = _s1["num_llm_calls"] - _calls0
        step_cand = _ITEM10["candidates"] - _cand0
        log_print(f"  [tokens] defense agent  input={step_in:,}  output={step_out:,}   "
                  f"calls={step_calls}  candidates={step_cand}  [rule-eval] {step_eval:.2f}s  [llm-latency] {step_lat:.2f}s")
        history.append({"iter": it, "blocked": blocked_now, "rules": len(accepted_rules),
                        "clusters": n_clusters, "fp": fp_rate / 100.0,
                        "modsec_internal": mi, "added_modsec": added_mi,
                        "in_tokens": step_in, "out_tokens": step_out, "rule_eval_s": step_eval,
                        "latency_s": step_lat, "llm_calls": step_calls, "candidates": step_cand})

        if blocked_now == len(corpus):
            log_print("\nAll attacks blocked -> defense converged.")
            break

    # ---- final summary ----
    log_print("\n" + "=" * 80)
    log_print("FINAL SUMMARY")
    log_print("=" * 80)
    head = f"{'Iter':>4} | {'Blocked':>8} | {'Rules':>5} | {'FP%':>6}"
    if MODE == "clustering":
        head = f"{'Iter':>4} | {'Blocked':>8} | {'Rules':>5} | {'Clusters':>8} | {'FP%':>6}"
    log_print(head)
    log_print("-" * 55)
    for h in history:
        if MODE == "clustering":
            log_print(f"{h['iter']:>4} | {h['blocked']:>3}/{len(corpus):<4} | {h['rules']:>5} | {h['clusters']:>8} | {h['fp']*100:>6.2f}")
        else:
            log_print(f"{h['iter']:>4} | {h['blocked']:>3}/{len(corpus):<4} | {h['rules']:>5} | {h['fp']*100:>6.2f}")
    log_print("-" * 55)
    final_blocked = history[-1]["blocked"] if history else 0
    log_print(f"Final: {final_blocked}/{len(corpus)} blocked with {len(accepted_rules)} rule(s)")

    if accepted_rules:
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            for r in accepted_rules:
                f.write(r + "\n\n")
        log_print(f"Rules saved to: {RULES_FILE}")
        log_print(f"\nAll {len(accepted_rules)} accepted rule(s) (full):")
        for _ri, _r in enumerate(accepted_rules, 1):
            log_print(f"  [{_ri}] {_r}")

    # ---- token + rule-eval accounting (defense agent) ----
    log_print("\n" + "=" * 80)
    log_print("TOKENS + RULE-EVAL TIME per step  (defense agent)")
    log_print("  input/output = prompt/generated tokens;  rule_eval_s = wall-time validating candidate rules")
    log_print("  (configtest + reload + attack/benign corpus replay) — NOT deployed WAF request latency")
    log_print("=" * 80)
    log_print(f"{'Iter':>4} | {'input':>12} | {'output':>12} | {'calls':>6} | {'cand':>6} | {'rule_eval_s':>12} | {'llm_lat_s':>10}")
    log_print("-" * 78)
    sum_in = sum_out = sum_calls = sum_cand = 0; sum_eval = sum_lat = 0.0
    for h in history:
        ti, to, te = h.get("in_tokens", 0), h.get("out_tokens", 0), h.get("rule_eval_s", 0.0)
        tc, tk, tl = h.get("llm_calls", 0), h.get("candidates", 0), h.get("latency_s", 0.0)
        sum_in += ti; sum_out += to; sum_eval += te; sum_calls += tc; sum_cand += tk; sum_lat += tl
        log_print(f"{h['iter']:>4} | {ti:>12,} | {to:>12,} | {tc:>6} | {tk:>6} | {te:>12.2f} | {tl:>10.2f}")
    log_print("-" * 78)
    log_print(f"{'TOT':>4} | {sum_in:>12,} | {sum_out:>12,} | {sum_calls:>6} | {sum_cand:>6} | {sum_eval:>12.2f} | {sum_lat:>10.2f}")

    stats = get_llm_stats()
    log_print(f"\nTOTAL input tokens:   {stats['total_input_tokens']:,}")
    log_print(f"TOTAL output tokens:  {stats['total_output_tokens']:,}")
    log_print(f"TOTAL rule-eval time: {get_rule_eval_seconds():.2f}s")
    log_print(f"\nLLM: calls={stats['num_llm_calls']}  in={stats['total_input_tokens']:,}  out={stats['total_output_tokens']:,}  tokens={stats['total_tokens']:,}  latency={stats['total_latency_s']:.1f}s")

    # item 10: budget / efficiency (additive)
    log_print("\n" + "=" * 80)
    log_print("ITEM 10 - BUDGET / EFFICIENCY (additive)")
    log_print("=" * 80)
    _s10 = get_llm_stats()
    _cost10 = (_s10["total_input_tokens"] * _PRICE_IN + _s10["total_output_tokens"] * _PRICE_OUT) / 1e6
    _R10 = len(accepted_rules)
    _rej10 = _ITEM10['candidates'] - _ITEM10['accepted']   # item 10: candidates generated but never accepted (offender-drops excluded)
    _unit = "groups" if MODE == "random_group" else "clusters"
    log_print(f"  wall-clock {(datetime.now() - _run_start).total_seconds():.1f}s   defense LLM calls {_ITEM10['def_calls']}   candidate rules {_ITEM10['candidates']}   accepted {_ITEM10['accepted']}   rejected {_rej10}   failed {_unit} {_ITEM10['failed_clusters']}")
    if MODE in ("clustering", "random_group") and _ITEM10['clusters_processed']:
        log_print(f"  {_unit} processed {_ITEM10['clusters_processed']}   total {_unit[:-1]} attempts {_ITEM10['cluster_attempts']}   mean attempts/{_unit[:-1]} {_ITEM10['cluster_attempts']/_ITEM10['clusters_processed']:.2f}")
    log_print(f"  tokens in={_s10['total_input_tokens']:,} out={_s10['total_output_tokens']:,}   est. cost ${_cost10:.4f}  (@ {_PRICE_IN}/{_PRICE_OUT} per 1M)")
    log_print(f"  |R|={_R10}   rules per 100 bypasses = {100.0*_R10/len(corpus) if corpus else 0:.2f}   LLM-calls per accepted rule = {_ITEM10['def_calls'] / _R10 if _R10 else 0:.2f}")
    log_print("=" * 80)


if __name__ == "__main__":
    main()
