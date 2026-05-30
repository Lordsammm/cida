"""CVE / EPSS / KEV enrichment.

Online sources (all free, no key):
  - OSV.dev      → CVE metadata, affected packages
  - EPSS (FIRST) → exploit probability score (0-1)
  - CISA KEV     → known-exploited vulnerabilities catalog

Network calls are best-effort and cached. If offline, enrichment degrades
gracefully (returns finding unchanged).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

import httpx

from models import Finding, Severity
from enrich.cwe import CWEEnricher


CACHE_DIR = Path(os.environ.get("CIDA_CACHE_DIR", Path.home() / ".cida_cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_URL = "https://api.osv.dev/v1/vulns/"

_HTTP_TIMEOUT = 10.0


class CVEEnricher:
    def __init__(self, offline: bool = False):
        self.offline = offline
        self._kev_set: set[str] | None = None
        self._epss_cache: dict[str, float] = {}
        self._client = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True)
        self._cwe_enricher = CWEEnricher(offline=offline)

    def close(self) -> None:
        self._client.close()
        self._cwe_enricher.close()

    # ---------- KEV ----------
    def _load_kev(self) -> set[str]:
        if self._kev_set is not None:
            return self._kev_set
        cache_path = CACHE_DIR / "kev.json"
        kev: set[str] = set()
        if cache_path.exists() and (time.time() - cache_path.stat().st_mtime) < 86400 * 7:
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
            except Exception:
                pass
        if not kev and not self.offline:
            try:
                resp = self._client.get(KEV_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    cache_path.write_text(json.dumps(data), encoding="utf-8")
                    kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
            except Exception as e:
                print(f"[warn] KEV fetch failed: {e}")
        self._kev_set = kev
        return kev

    # ---------- EPSS ----------
    def _fetch_epss(self, cves: list[str]) -> dict[str, float]:
        if not cves or self.offline:
            return {}
        # batch up to 100 per request
        out: dict[str, float] = {}
        for i in range(0, len(cves), 100):
            batch = cves[i:i + 100]
            try:
                resp = self._client.get(EPSS_URL, params={"cve": ",".join(batch)})
                if resp.status_code != 200:
                    continue
                for row in resp.json().get("data", []):
                    out[row["cve"]] = float(row["epss"])
            except Exception as e:
                print(f"[warn] EPSS fetch failed: {e}")
        return out

    # ---------- enrich ----------
    def enrich(self, findings: Iterable[Finding]) -> list[Finding]:
        findings = list(findings)
        cves = sorted({f.cve_id for f in findings if f.cve_id})
        kev = self._load_kev()
        epss = {**self._epss_cache, **self._fetch_epss([c for c in cves if c not in self._epss_cache])}
        self._epss_cache.update(epss)
        for f in findings:
            if not f.cve_id:
                continue
            if f.cve_id in kev:
                f.kev_listed = True
                # Promote severity to CRITICAL if it's KEV-listed
                if f.severity in (Severity.LOW, Severity.MEDIUM, Severity.INFO):
                    f.severity = Severity.HIGH
            if f.cve_id in epss:
                f.epss_score = epss[f.cve_id]
        # CWE + OWASP enrichment (best-effort, layered on top)
        findings = self._cwe_enricher.enrich(findings)
        return findings


def enrich_findings(findings: Iterable[Finding], offline: bool = False) -> list[Finding]:
    enricher = CVEEnricher(offline=offline)
    try:
        return enricher.enrich(findings)
    finally:
        enricher.close()
