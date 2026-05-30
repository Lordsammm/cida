"""Polite HTTP utilities for intel adapters: caching + retries + UA."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import httpx

CACHE_DIR = Path(os.environ.get("CIDA_CACHE_DIR", Path.home() / ".cida_cache")) / "intel"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "CIDA/0.1 (Aajimatics cyber-underwriting research)"
DEFAULT_TIMEOUT = 10.0
CACHE_TTL_SECONDS = 60 * 60 * 6   # 6h
MAX_RETRIES = 3
BACKOFF_BASE = 1.5


def _cache_path(key: str) -> Path:
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
    return CACHE_DIR / f"{h}.json"


def cached_get(url: str, params: dict | None = None, ttl: int = CACHE_TTL_SECONDS,
               client: httpx.Client | None = None) -> str | None:
    """GET with on-disk cache + retries. Returns response text or None on failure."""
    cache_key = f"{url}?{json.dumps(params or {}, sort_keys=True)}"
    cp = _cache_path(cache_key)
    if cp.exists() and (time.time() - cp.stat().st_mtime) < ttl:
        try:
            return json.loads(cp.read_text(encoding="utf-8")).get("body")
        except Exception:
            pass

    owns_client = client is None
    client = client or httpx.Client(
        timeout=DEFAULT_TIMEOUT, follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json"},
    )
    try:
        for attempt in range(MAX_RETRIES):
            try:
                resp = client.get(url, params=params)
                if resp.status_code == 200:
                    cp.write_text(json.dumps({"body": resp.text}), encoding="utf-8")
                    return resp.text
                if resp.status_code in (429, 503):
                    time.sleep(BACKOFF_BASE ** (attempt + 1))
                    continue
                return None
            except (httpx.TimeoutException, httpx.ConnectError):
                time.sleep(BACKOFF_BASE ** (attempt + 1))
                continue
        return None
    finally:
        if owns_client:
            client.close()
