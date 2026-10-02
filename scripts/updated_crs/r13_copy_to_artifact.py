#!/usr/bin/env python3
"""Copy R1.3 (updated-CRS) artifacts into the LOCAL public repo working tree (content-based).
   NO git add/commit/push. Excludes raw *_PRIVATE residual-payload files; per-request payloads are hashed."""
import os, shutil, glob, subprocess

R = "/mnt/c/Projects/genwebsec-artifact"
B = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.3"
H = "/home/vahid"
RES, CFG, LOG, SCR, MAN = f"{R}/results/updated_crs", f"{R}/configs/updated_crs", f"{R}/logs/updated_crs", f"{R}/scripts/updated_crs", f"{R}/manifests"
for d in [RES, f"{RES}/attack_replay", f"{RES}/rq4_bwapp_juice", f"{RES}/benign", CFG, LOG, SCR, MAN]:
    os.makedirs(d, exist_ok=True)

def cp(src, dst):
    shutil.copy2(src, dst)

# results root: consolidated tables + README
for f in ["R13_attack_persistence.csv", "R13_benign_fp.csv", "R13_rq4_bwapp_juice_persistence.csv", "README.md"]:
    cp(f"{B}/{f}", f"{RES}/{f}")
# attack_replay: hashed per-request + summary (NOT *_PRIVATE)
for f in ["rq1_through_crs429_perrequest.csv", "rq1_through_crs429_summary.csv"]:
    cp(f"{B}/attack_replay/{f}", f"{RES}/attack_replay/{f}")
# rq4 bwapp/juice: hashed per-request + summaries (NOT *_PRIVATE)
for f in ["rq4_bwapp_juice_through_crs429_perrequest.csv", "rq4_bwapp_juice_through_crs429_summary.csv",
          "rq4_bwapp_xss_through_crs429_perrequest.csv", "rq4_bwapp_xss_through_crs429_summary.csv"]:
    cp(f"{B}/rq4_bwapp_juice/{f}", f"{RES}/rq4_bwapp_juice/{f}")
# benign: all CSVs (publishable)
for f in glob.glob(f"{B}/benign/*.csv"):
    cp(f, f"{RES}/benign/{os.path.basename(f)}")
# configs: container/config metadata
cp(f"{B}/metadata/crs429_container_metadata.md", f"{CFG}/crs429_container_metadata.md")
# logs: audit
for f in ["audit_summary.csv", "audit_sample_redacted.jsonl"]:
    cp(f"{B}/audit/{f}", f"{LOG}/{f}")
# scripts: r13 drivers
for f in sorted(glob.glob(f"{H}/r13_*.py")):
    cp(f, f"{SCR}/{os.path.basename(f)}")

MANIFEST = """# Updated-CRS evaluation (OWASP CRS 4.29.0)

Maps the "persistence under an updated CRS" evaluation to its files. Every attack that bypassed the study
baseline (OWASP CRS 3.3.2) is replayed through the current CRS (4.29.0); benign false positives are reported
alongside; container/configuration metadata and representative audit logs are included. Supports the response
to reviewer comment R1.3 of the Frontiers revision.

## Updated-CRS replay (per request; attack payloads hashed)
`results/updated_crs/`
- `attack_replay/rq1_through_crs429_perrequest.csv` (12,051) + `_summary.csv` -- custom-application attacks
  (RQ1 CRS-only winners) through CRS 4.29.0: SQLi 9,119/9,159 blocked (99.56%), XSS 2,448/2,892 (84.65%).
- `rq4_bwapp_juice/rq4_bwapp_juice_through_crs429_*.csv` -- bWAPP + Juice SQLi held-out attacks (RQ4):
  bWAPP 3,562/3,763 blocked (94.66%), Juice 1,416/4,280 (33.08%; Juice search 0%).
- `rq4_bwapp_juice/rq4_bwapp_xss_through_crs429_*.csv` -- bWAPP XSS (xss_eval) via the live bWAPP backend
  with a bee/bug session (inbound+outbound): 780/1,278 blocked (61.03%).
- `R13_attack_persistence.csv`, `R13_rq4_bwapp_juice_persistence.csv` -- consolidated persistence tables.
- `README.md` -- overview + reproduction.

## Benign results (false positives under CRS 4.29.0)
`results/updated_crs/benign/`
- `benign_through_crs429_*.csv` -- custom-application + custom-XSS corpora (0/2,000 each).
- `benign_extra_through_crs429_*.csv` -- bWAPP, Juice, CSIC-2012 (0/4,000, 0/2,000, 6/8,363 = 0.072%).
- `benign_extra_false_positives.csv` -- the six CSIC requests blocked (Latin-1 encoded accents).
- `R13_benign_fp.csv` -- consolidated FP table.

## Configuration / container metadata
`configs/updated_crs/crs429_container_metadata.md` -- image reference and digest, CRS/ModSecurity/Apache
versions, applied paranoia and anomaly configuration, exact docker run commands, reverse-proxy wiring.

## Audit logs
`logs/updated_crs/` -- `audit_summary.csv` (matched rule IDs, anomaly score, inspected fields; blocked vs
passed) and `audit_sample_redacted.jsonl` (representative JSON audit records; payloads redacted).

## Generating scripts
`scripts/updated_crs/` -- deploy, replay, benign, audit, metadata, and report drivers (`r13_*.py`).

## Notes
- The updated CRS runs in a container (OWASP CRS 4.29.0, ModSecurity 2.9.15, Apache 2.4.68) beside the
  unchanged study host (Apache 2.4.52 + ModSecurity 2.9.5 + CRS 3.3.2), at matched configuration
  (paranoia 1, inbound anomaly 5, outbound 4). All requests use `Host: localhost`.
- Raw attack payloads are not published: per-request files identify payloads only by `payload_sha1`;
  residual-attack lists (`*_PRIVATE`) are withheld. Benign corpora are retained in the clear.
- A few scripts carry canonical textbook probes (`alert(1)`, `' OR '1'='1`) used as sanity checks; these
  are not from the generated corpus.
"""
with open(f"{MAN}/updated_crs.md", "w", encoding="utf-8") as fh:
    fh.write(MANIFEST)

def sh(cmd):
    return subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True).stdout.strip()

print("=== copied file counts ===")
for label, d in [("results/updated_crs", RES), ("configs/updated_crs", CFG), ("logs/updated_crs", LOG), ("scripts/updated_crs", SCR)]:
    print(f"  {label}: {sh(f'find {d} -type f | wc -l')} files")
print(f"  manifests/updated_crs.md: {'present' if os.path.exists(f'{MAN}/updated_crs.md') else 'MISSING'}")

print("=== safety: any *PRIVATE* copied? (must be empty) ===")
print(repr(sh(f"find {RES} {LOG} {CFG} -iname '*PRIVATE*'")))
print("=== redaction scan: raw-payload signatures in attack/rq4 CSVs + audit (benign excluded, publishable) ===")
print(repr(sh(f"grep -rIlnE 'union[[:space:]]+select|<script|onerror=|OR .1.=.1|CASE WHEN|;--' {RES}/attack_replay {RES}/rq4_bwapp_juice {LOG} 2>/dev/null")))
print("=== sample payload_sha1 column (should be 16-hex) ===")
print(" ", sh(f"tail -n +2 {RES}/attack_replay/rq1_through_crs429_perrequest.csv | head -1 | cut -d, -f5"))
print(" ", sh(f"tail -n +2 {RES}/rq4_bwapp_juice/rq4_bwapp_xss_through_crs429_perrequest.csv | head -1 | cut -d, -f3"))
print("=== git state (UNTRACKED only; nothing added/committed/pushed) ===")
print(sh(f"git -C {R} status --short | head -30"))
print("untracked/modified entries:", sh(f"git -C {R} status --porcelain | wc -l"))
print("=== done (no git add/commit/push performed) ===")
