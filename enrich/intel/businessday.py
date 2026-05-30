"""BusinessDay Intelligence adapter - sector reports, exec moves, breach coverage.

Returns empty snapshot on any failure; uses cached_get + UA + retries.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from bs4 import BeautifulSoup

from enrich.intel._http import cached_get
from enrich.intel.base import IntelSource
from models import CompanyIntelSnapshot


class BusinessDayAdapter(IntelSource):
    name = "businessday_intelligence"
    base = "https://businessdayintelligence.ng"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("BD_INTELLIGENCE_API_KEY")

    def fetch(self, org_name: str, country: str | None = None) -> CompanyIntelSnapshot:
        snapshot = self._empty(org_name)
        body = cached_get(f"{self.base}/", params={"s": org_name})
        if not body:
            return snapshot
        try:
            soup = BeautifulSoup(body, "html.parser")
            articles = []
            for a in soup.select("h2 a, h3 a, .post-title a, article a.title")[:15]:
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
                if any(k in a["title"].lower() for k in ["breach", "hack", "ransomware", "cyber", "fraud"])
            ]
        except Exception as e:
            print(f"[warn] BusinessDay parse failed for {org_name}: {e}")
        snapshot.fetched_at = datetime.now(tz=timezone.utc)
        return snapshot

