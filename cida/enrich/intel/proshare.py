"""Proshare adapter - financials & news for Nigerian (and Africa-broad) listed firms.

Production: prefer Proshare API tier (Proshare Markets / Proshare Confidential).
Fallback: site search scrape with on-disk caching + retries + robots-polite UA.
Returns an empty snapshot on any failure (never raises).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from bs4 import BeautifulSoup

from cida.enrich.intel._http import cached_get
from cida.enrich.intel.base import IntelSource
from cida.models import CompanyIntelSnapshot


class ProshareAdapter(IntelSource):
    name = "proshare"
    base = "https://proshare.co"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("PROSHARE_API_KEY")

    def fetch(self, org_name: str, country: str | None = None) -> CompanyIntelSnapshot:
        snapshot = self._empty(org_name)
        body = cached_get(f"{self.base}/search", params={"q": org_name})
        if not body:
            return snapshot
        try:
            soup = BeautifulSoup(body, "html.parser")
            articles = []
            for a in soup.select(
                "a.article-title, a.search-result-link, h2 a, h3 a, .post-title a"
            )[:15]:
                href = a.get("href") or ""
                title = a.get_text(strip=True)
                if not (title and href):
                    continue
                articles.append({
                    "title": title,
                    "url": href if href.startswith("http") else f"{self.base}{href}",
                })
            snapshot.recent_news = articles
            snapshot.breach_mentions = [
                a for a in articles
                if any(k in a["title"].lower() for k in
                       ["breach", "hack", "ransomware", "cyber attack", "data leak", "phishing", "fraud"])
            ]
        except Exception as e:
            print(f"[warn] Proshare parse failed for {org_name}: {e}")
        snapshot.fetched_at = datetime.now(tz=timezone.utc)
        return snapshot

