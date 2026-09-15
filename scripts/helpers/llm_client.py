"""
helpers.llm_client

OpenRouter LLM client wrapper for GenSQLi-Agentic project.

Responsibilities:
- Load OPENROUTER_API_KEY from .env
- Provide a cached OpenAI client configured for OpenRouter
- Expose simple call_llm() interface for all agents

Usage:
    from helpers.llm_client import call_llm, get_client

    response = call_llm(
        model="anthropic/claude-3.5-sonnet",
        messages=[{"role": "user", "content": "Summarize the following text: ..."}],
        max_tokens=2048,
        temperature=0.7
    )
"""

from __future__ import annotations

import os
import json
import time
import random
from typing import List, Dict

from dotenv import load_dotenv
from openai import OpenAI, RateLimitError, APIError

# =========================
# Configuration
# =========================

# Load environment variables from .env file
load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "OPENROUTER_API_KEY not found in environment. "
        "Please set it in your .env file."
    )

# Retry configuration for rate limiting
MAX_RETRIES = 5
INITIAL_RETRY_DELAY = 10.0  # seconds (OpenRouter often suggests 8s, so use 10s)
MAX_RETRY_DELAY = 60.0  # seconds
DELAY_BETWEEN_CALLS = 0.3  # seconds - small delay between successful calls

# =========================
# Cached OpenAI Client
# =========================

# Create a single cached client instance configured for OpenRouter
_client: OpenAI = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=API_KEY,
    default_headers={
        "HTTP-Referer": "http://localhost",
        "X-Title": "GenSQLi-Agentic",
    },
)

print("[llm_client] OpenRouter client initialized successfully.")

# =========================
# Global Token & Latency Tracking
# =========================

# Accumulators for total token usage and latency across all LLM calls
_total_input_tokens: int = 0
_total_output_tokens: int = 0
_total_tokens: int = 0
_total_latency_s: float = 0.0  # Changed to seconds
_num_llm_calls: int = 0


# =========================
# Public API
# =========================

def get_client() -> OpenAI:
    """
    Get the cached OpenAI client configured for OpenRouter.

    Returns
    -------
    OpenAI
        The configured OpenAI client instance.
    """
    return _client


def get_llm_stats() -> Dict[str, float | int]:
    """
    Get accumulated LLM usage statistics across all calls.

    Returns
    -------
    Dict[str, float | int]
        Dictionary containing:
        - total_input_tokens: Total input tokens across all calls
        - total_output_tokens: Total output tokens across all calls
        - total_tokens: Total tokens across all calls
        - total_latency_s: Total latency in seconds
        - num_llm_calls: Number of LLM calls made
        - avg_latency_s: Average latency per call in seconds
    """
    global _total_input_tokens, _total_output_tokens, _total_tokens, _total_latency_s, _num_llm_calls

    avg_latency = _total_latency_s / _num_llm_calls if _num_llm_calls > 0 else 0.0

    return {
        "total_input_tokens": _total_input_tokens,
        "total_output_tokens": _total_output_tokens,
        "total_tokens": _total_tokens,
        "total_latency_s": _total_latency_s,
        "num_llm_calls": _num_llm_calls,
        "avg_latency_s": avg_latency,
    }


def reset_llm_stats() -> None:
    """
    Reset all accumulated LLM usage statistics to zero.

    Useful for starting fresh tracking for a new experiment run.
    """
    global _total_input_tokens, _total_output_tokens, _total_tokens, _total_latency_s, _num_llm_calls

    _total_input_tokens = 0
    _total_output_tokens = 0
    _total_tokens = 0
    _total_latency_s = 0.0
    _num_llm_calls = 0

    print("[llm_client] Reset LLM statistics")


def call_llm(
    model: str,
    messages: List[Dict[str, str]],
    max_tokens: int = 1024,
    temperature: float = 0.3,
    seed: int | None = None,   # item 1: provider-supported sampling seed; forwarded to the API only when set (backward-compatible)
) -> str:
    """
    Call the OpenRouter LLM API and return the assistant's response as a plain string.

    This function includes automatic retry with exponential backoff for rate limits.
    It tracks and prints:
    - Input tokens (prompt_tokens)
    - Output tokens (completion_tokens)
    - Total tokens
    - Latency (time taken for API call)

    Parameters
    ----------
    model : str
        The model identifier (e.g., "anthropic/claude-3.5-sonnet",
        "openai/gpt-4", "meta-llama/llama-3.1-70b-instruct").
    messages : List[Dict[str, str]]
        List of message dicts with "role" and "content" keys.
        Example: [{"role": "user", "content": "Hello"}]
    max_tokens : int, optional
        Maximum tokens in the response (default: 1024).
    temperature : float, optional
        Sampling temperature, 0.0-2.0 (default: 0.3).

    Returns
    -------
    str
        The assistant's message content as a plain string.

    Raises
    ------
    Exception
        If the API call fails after all retries or returns unexpected format.
    """
    # Declare global variables at the start of the function
    global _total_input_tokens, _total_output_tokens, _total_tokens, _total_latency_s, _num_llm_calls

    retry_delay = INITIAL_RETRY_DELAY
    last_exception = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            # Track start time
            start_time = time.time()

            _extra = {"seed": seed} if seed is not None else {}   # item 1: only pass seed when set
            response = _client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                **_extra,
            )

            # Track end time and calculate latency
            end_time = time.time()
            latency_s = end_time - start_time  # Latency in seconds

            # Defensive check: ensure latency is non-negative
            if latency_s < 0:
                print(f"[llm_client] WARNING: Negative latency detected ({latency_s:.2f}s), setting to 0")
                latency_s = 0.0

            # Check if response has valid choices
            if response.choices is None or len(response.choices) == 0:
                # Retry on empty choices (could be transient issue)
                if attempt < MAX_RETRIES:
                    jitter = random.uniform(0, retry_delay * 0.1)
                    wait_time = retry_delay + jitter
                    print(f"[llm_client] Empty response. Waiting {wait_time:.1f}s before retry {attempt + 1}/{MAX_RETRIES}...")
                    time.sleep(wait_time)
                    retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
                    continue
                raise ValueError("LLM returned empty choices after all retries")

            # Extract the assistant's message content
            content = response.choices[0].message.content

            if content is None:
                # Retry on None content (could be transient issue)
                if attempt < MAX_RETRIES:
                    jitter = random.uniform(0, retry_delay * 0.1)
                    wait_time = retry_delay + jitter
                    print(f"[llm_client] None content. Waiting {wait_time:.1f}s before retry {attempt + 1}/{MAX_RETRIES}...")
                    time.sleep(wait_time)
                    retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
                    continue
                raise ValueError("LLM returned None content after all retries")

            # Extract token usage information
            usage = response.usage
            if usage:
                input_tokens = usage.prompt_tokens
                output_tokens = usage.completion_tokens
                total_tokens = usage.total_tokens

                # Update global accumulators
                _total_input_tokens += input_tokens
                _total_output_tokens += output_tokens
                _total_tokens += total_tokens
                _total_latency_s += latency_s
                _num_llm_calls += 1

                # Print token usage and latency
                print(f"[llm_client] LLM Call Stats:")
                print(f"[llm_client]   Model: {model}")
                print(f"[llm_client]   Input tokens: {input_tokens}")
                print(f"[llm_client]   Output tokens: {output_tokens}")
                print(f"[llm_client]   Total tokens: {total_tokens}")
                print(f"[llm_client]   Latency: {latency_s:.2f}s")
            else:
                # If usage is not available, still print latency and update counters
                _total_latency_s += latency_s
                _num_llm_calls += 1

                print(f"[llm_client] LLM Call Stats:")
                print(f"[llm_client]   Model: {model}")
                print(f"[llm_client]   Token usage: Not available")
                print(f"[llm_client]   Latency: {latency_s:.2f}s")

            # Add small delay between calls to prevent rate limiting
            time.sleep(DELAY_BETWEEN_CALLS)

            return content

        except RateLimitError as e:
            last_exception = e
            if attempt < MAX_RETRIES:
                # Add jitter to prevent thundering herd
                jitter = random.uniform(0, retry_delay * 0.1)
                wait_time = retry_delay + jitter
                print(f"[llm_client] Rate limit hit. Waiting {wait_time:.1f}s before retry {attempt + 1}/{MAX_RETRIES}...")
                time.sleep(wait_time)
                # Exponential backoff
                retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
            else:
                print(f"[llm_client] Rate limit error after {MAX_RETRIES} retries: {e}")
                raise

        except APIError as e:
            # Check if it's a rate limit related error (429)
            if hasattr(e, 'status_code') and e.status_code == 429:
                last_exception = e
                if attempt < MAX_RETRIES:
                    jitter = random.uniform(0, retry_delay * 0.1)
                    wait_time = retry_delay + jitter
                    print(f"[llm_client] API rate limit (429). Waiting {wait_time:.1f}s before retry {attempt + 1}/{MAX_RETRIES}...")
                    time.sleep(wait_time)
                    retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
                else:
                    print(f"[llm_client] API error after {MAX_RETRIES} retries: {e}")
                    raise
            else:
                print(f"[llm_client] API error calling LLM with model {model}: {e}")
                raise

        except json.JSONDecodeError as e:
            # OpenRouter returned non-JSON (HTML error page, truncated body, etc.)
            last_exception = e
            if attempt < MAX_RETRIES:
                jitter = random.uniform(0, retry_delay * 0.1)
                wait_time = retry_delay + jitter
                print(f"[llm_client] JSONDecodeError (model={model}, likely bad gateway or model unavailable). "
                      f"Waiting {wait_time:.1f}s before retry {attempt + 1}/{MAX_RETRIES}... Error: {e}")
                time.sleep(wait_time)
                retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
            else:
                print(f"[llm_client] JSONDecodeError after {MAX_RETRIES} retries. "
                      f"Check that model '{model}' exists on OpenRouter and your API key is valid.")
                raise

        except Exception as e:
            error_str = str(e).lower()
            # Check if error message indicates rate limiting
            if 'rate' in error_str or 'limit' in error_str or '429' in error_str:
                last_exception = e
                if attempt < MAX_RETRIES:
                    jitter = random.uniform(0, retry_delay * 0.1)
                    wait_time = retry_delay + jitter
                    print(f"[llm_client] Rate limit detected in error. Waiting {wait_time:.1f}s before retry {attempt + 1}/{MAX_RETRIES}...")
                    time.sleep(wait_time)
                    retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
                else:
                    print(f"[llm_client] Error after {MAX_RETRIES} retries: {e}")
                    raise
            else:
                print(f"[llm_client] Error calling LLM with model {model}: {e}")
                raise

    # Should not reach here, but just in case
    if last_exception:
        raise last_exception
    raise RuntimeError("Unexpected error in call_llm retry loop")
