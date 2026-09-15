#!/usr/bin/env python3
"""
Replay the uploaded CSIC normal-request CSV through a ModSecurity-protected HTTP server.

Important semantics preserved from this CSV:
  * GET  -> `query` is appended to the request URL.
  * POST -> `query` is sent verbatim as an application/x-www-form-urlencoded body.
            It is NOT appended to the URL and is NOT parsed/re-encoded by Python.

The script sends requests sequentially and records every response.
"""

import argparse
import time
from pathlib import Path
from urllib.parse import urljoin

import pandas as pd
import requests


REQUIRED_COLUMNS = {"id", "label", "method", "path", "query", "url"}


def nonempty_query(value):
    if pd.isna(value):
        return None
    value = str(value)
    return value if value != "" else None


def validate_dataframe(df: pd.DataFrame) -> None:
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    bad_methods = sorted(set(df["method"].astype(str).str.upper()) - {"GET", "POST"})
    if bad_methods:
        raise ValueError(f"Unsupported HTTP methods found: {bad_methods}")

    # Validate that the flattened `url` column is consistent with method/path/query.
    def reconstruct(row):
        q = nonempty_query(row["query"])
        return f'{str(row["method"]).upper()} {row["path"]}' + (f"?{q}" if q else "")

    reconstructed = df.apply(reconstruct, axis=1)
    mismatches = df["url"].astype(str) != reconstructed

    if mismatches.any():
        bad_ids = df.loc[mismatches, "id"].head(10).tolist()
        raise ValueError(
            "The `url` column does not match method/path/query for some rows. "
            f"First mismatching IDs: {bad_ids}"
        )


def make_target(base_url: str, path: str) -> str:
    # Keep the dataset path intact while replacing only the original host.
    return base_url.rstrip("/") + "/" + str(path).lstrip("/")


def replay_row(session, row, base_url, timeout, verify_tls):
    method = str(row["method"]).upper()
    path = str(row["path"])
    query = nonempty_query(row["query"])

    target = make_target(base_url, path)
    headers = {}
    body = None

    if method == "GET":
        if query:
            # For this uploaded file the GET query strings contain no percent-encoded
            # bytes, so direct concatenation preserves them exactly.
            target = f"{target}?{query}"

    elif method == "POST":
        # CRITICAL: do not use data={...}. That would parse/re-encode the dataset.
        # All POST bodies in the uploaded file are ASCII form-encoded strings,
        # including literal sequences such as %F1, %E9, %40, etc.
        body = query.encode("ascii") if query is not None else b""
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    start = time.perf_counter()

    response = session.request(
        method=method,
        url=target,
        data=body,
        headers=headers,
        allow_redirects=False,
        timeout=timeout,
        verify=verify_tls,
    )

    elapsed_ms = (time.perf_counter() - start) * 1000

    return {
        "sent_url": response.request.url,
        "sent_method": response.request.method,
        "sent_body": (
            response.request.body.decode("ascii", errors="replace")
            if isinstance(response.request.body, bytes)
            else (response.request.body or "")
        ),
        "status_code": response.status_code,
        "elapsed_ms": round(elapsed_ms, 2),
        "response_bytes": len(response.content),
    }


def parse_statuses(text: str):
    return {int(x.strip()) for x in text.split(",") if x.strip()}


def main():
    parser = argparse.ArgumentParser(
        description="Replay CSIC normal requests through ModSecurity."
    )
    parser.add_argument(
        "csv",
        nargs="?",
        default="all.csv",
        help="Input CSV file (default: all.csv)",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost",
        help="ModSecurity-protected origin, e.g. http://localhost or http://localhost:8080",
    )
    parser.add_argument(
        "--output",
        default="waf_results.csv",
        help="Output CSV (default: waf_results.csv)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between requests in seconds (default: 0)",
    )
    parser.add_argument(
        "--block-statuses",
        default="403",
        help="Comma-separated HTTP statuses treated as WAF blocks (default: 403)",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Optional limit for a test run, e.g. --max-rows 20",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (only relevant for HTTPS)",
    )
    args = parser.parse_args()

    input_path = Path(args.csv)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    df = pd.read_csv(input_path, low_memory=False)
    validate_dataframe(df)

    if args.max_rows is not None:
        df = df.head(args.max_rows).copy()

    block_statuses = parse_statuses(args.block_statuses)

    session = requests.Session()
    # Avoid accidentally sending localhost traffic through environment proxy settings.
    session.trust_env = False

    results = []

    total = len(df)
    print(f"Loaded {total} rows")
    print(f"Sending to: {args.base_url}")
    print("Redirect following: disabled")
    print(f"Block-status heuristic: {sorted(block_statuses)}")
    print()

    for position, (_, row) in enumerate(df.iterrows(), start=1):
        record = {
            "id": row["id"],
            "label": row["label"],
            "original_method": row["method"],
            "original_path": row["path"],
            "original_query": "" if pd.isna(row["query"]) else row["query"],
            "original_url_column": row["url"],
        }

        try:
            sent = replay_row(
                session=session,
                row=row,
                base_url=args.base_url,
                timeout=args.timeout,
                verify_tls=not args.insecure,
            )
            record.update(sent)
            record["blocked_by_status"] = sent["status_code"] in block_statuses
            record["error"] = ""
        except requests.RequestException as exc:
            record.update(
                {
                    "sent_url": "",
                    "sent_method": str(row["method"]).upper(),
                    "sent_body": "",
                    "status_code": "",
                    "elapsed_ms": "",
                    "response_bytes": "",
                    "blocked_by_status": "",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

        results.append(record)

        status = record["status_code"] if record["status_code"] != "" else "ERROR"
        blocked = record["blocked_by_status"]
        print(
            f"[{position:>5}/{total}] "
            f"id={row['id']} {row['method']} {row['path']} "
            f"-> {status} blocked={blocked}"
        )

        if args.delay > 0:
            time.sleep(args.delay)

    out = pd.DataFrame(results)
    out.to_csv(args.output, index=False)

    successful = pd.to_numeric(out["status_code"], errors="coerce").notna()
    blocked = out.loc[successful, "blocked_by_status"].eq(True)

    print()
    print("Finished")
    print(f"Results: {args.output}")
    print(f"Requests attempted: {len(out)}")
    print(f"Responses received: {int(successful.sum())}")
    print(f"Errors: {int((~successful).sum())}")
    print(f"Blocked by configured status: {int(blocked.sum())}")

    if successful.any():
        print("HTTP status counts:")
        print(out.loc[successful, "status_code"].value_counts().sort_index().to_string())


if __name__ == "__main__":
    main()
