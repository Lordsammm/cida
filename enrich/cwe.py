"""CWE enrichment - maps CVE IDs to CWE weakness classes and OWASP Top 10 2021.

Sources (all free, no API key required):
  - NVD CVE API v2  → CWE IDs per CVE
  - Static map      → CWE → OWASP Top 10 2021 category

Network calls are best-effort and cached (7-day TTL).
If offline or NVD unavailable, enrichment degrades gracefully.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

import httpx

from models import Finding


CACHE_DIR = Path(os.environ.get("CIDA_CACHE_DIR", Path.home() / ".cida_cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_HTTP_TIMEOUT = 15.0

# CWE number (int) → OWASP Top 10 2021 category string.
# Built from OWASP CWE mappings published at owasp.org/Top10.
_CWE_TO_OWASP: dict[int, str] = {
    # A01:2021 - Broken Access Control
    22: "A01:2021 Broken Access Control",
    23: "A01:2021 Broken Access Control",
    35: "A01:2021 Broken Access Control",
    59: "A01:2021 Broken Access Control",
    200: "A01:2021 Broken Access Control",
    201: "A01:2021 Broken Access Control",
    219: "A01:2021 Broken Access Control",
    264: "A01:2021 Broken Access Control",
    275: "A01:2021 Broken Access Control",
    276: "A01:2021 Broken Access Control",
    284: "A01:2021 Broken Access Control",
    285: "A01:2021 Broken Access Control",
    352: "A01:2021 Broken Access Control",
    359: "A01:2021 Broken Access Control",
    377: "A01:2021 Broken Access Control",
    402: "A01:2021 Broken Access Control",
    425: "A01:2021 Broken Access Control",
    441: "A01:2021 Broken Access Control",
    497: "A01:2021 Broken Access Control",
    538: "A01:2021 Broken Access Control",
    540: "A01:2021 Broken Access Control",
    548: "A01:2021 Broken Access Control",
    552: "A01:2021 Broken Access Control",
    566: "A01:2021 Broken Access Control",
    601: "A01:2021 Broken Access Control",
    639: "A01:2021 Broken Access Control",
    651: "A01:2021 Broken Access Control",
    668: "A01:2021 Broken Access Control",
    706: "A01:2021 Broken Access Control",
    732: "A01:2021 Broken Access Control",
    # A02:2021 - Cryptographic Failures
    261: "A02:2021 Cryptographic Failures",
    296: "A02:2021 Cryptographic Failures",
    310: "A02:2021 Cryptographic Failures",
    311: "A02:2021 Cryptographic Failures",
    312: "A02:2021 Cryptographic Failures",
    319: "A02:2021 Cryptographic Failures",
    321: "A02:2021 Cryptographic Failures",
    322: "A02:2021 Cryptographic Failures",
    323: "A02:2021 Cryptographic Failures",
    324: "A02:2021 Cryptographic Failures",
    325: "A02:2021 Cryptographic Failures",
    326: "A02:2021 Cryptographic Failures",
    327: "A02:2021 Cryptographic Failures",
    328: "A02:2021 Cryptographic Failures",
    329: "A02:2021 Cryptographic Failures",
    330: "A02:2021 Cryptographic Failures",
    331: "A02:2021 Cryptographic Failures",
    335: "A02:2021 Cryptographic Failures",
    338: "A02:2021 Cryptographic Failures",
    340: "A02:2021 Cryptographic Failures",
    347: "A02:2021 Cryptographic Failures",
    523: "A02:2021 Cryptographic Failures",
    720: "A02:2021 Cryptographic Failures",
    757: "A02:2021 Cryptographic Failures",
    759: "A02:2021 Cryptographic Failures",
    760: "A02:2021 Cryptographic Failures",
    780: "A02:2021 Cryptographic Failures",
    818: "A02:2021 Cryptographic Failures",
    916: "A02:2021 Cryptographic Failures",
    # A03:2021 - Injection (SQL, OS, LDAP, XSS, etc.)
    20: "A03:2021 Injection",
    74: "A03:2021 Injection",
    75: "A03:2021 Injection",
    77: "A03:2021 Injection",
    78: "A03:2021 Injection",
    79: "A03:2021 Injection",
    80: "A03:2021 Injection",
    83: "A03:2021 Injection",
    87: "A03:2021 Injection",
    88: "A03:2021 Injection",
    89: "A03:2021 Injection",
    90: "A03:2021 Injection",
    91: "A03:2021 Injection",
    93: "A03:2021 Injection",
    94: "A03:2021 Injection",
    95: "A03:2021 Injection",
    96: "A03:2021 Injection",
    97: "A03:2021 Injection",
    98: "A03:2021 Injection",
    99: "A03:2021 Injection",
    116: "A03:2021 Injection",
    138: "A03:2021 Injection",
    184: "A03:2021 Injection",
    470: "A03:2021 Injection",
    564: "A03:2021 Injection",
    610: "A03:2021 Injection",
    643: "A03:2021 Injection",
    917: "A03:2021 Injection",
    943: "A03:2021 Injection",
    # A04:2021 - Insecure Design
    73: "A04:2021 Insecure Design",
    183: "A04:2021 Insecure Design",
    209: "A04:2021 Insecure Design",
    213: "A04:2021 Insecure Design",
    235: "A04:2021 Insecure Design",
    256: "A04:2021 Insecure Design",
    257: "A04:2021 Insecure Design",
    266: "A04:2021 Insecure Design",
    269: "A04:2021 Insecure Design",
    280: "A04:2021 Insecure Design",
    311: "A04:2021 Insecure Design",
    312: "A04:2021 Insecure Design",
    313: "A04:2021 Insecure Design",
    316: "A04:2021 Insecure Design",
    419: "A04:2021 Insecure Design",
    430: "A04:2021 Insecure Design",
    434: "A04:2021 Insecure Design",
    444: "A04:2021 Insecure Design",
    451: "A04:2021 Insecure Design",
    472: "A04:2021 Insecure Design",
    501: "A04:2021 Insecure Design",
    522: "A04:2021 Insecure Design",
    525: "A04:2021 Insecure Design",
    539: "A04:2021 Insecure Design",
    579: "A04:2021 Insecure Design",
    598: "A04:2021 Insecure Design",
    602: "A04:2021 Insecure Design",
    642: "A04:2021 Insecure Design",
    646: "A04:2021 Insecure Design",
    650: "A04:2021 Insecure Design",
    653: "A04:2021 Insecure Design",
    656: "A04:2021 Insecure Design",
    657: "A04:2021 Insecure Design",
    799: "A04:2021 Insecure Design",
    1021: "A04:2021 Insecure Design",
    1173: "A04:2021 Insecure Design",
    # A05:2021 - Security Misconfiguration
    2: "A05:2021 Security Misconfiguration",
    11: "A05:2021 Security Misconfiguration",
    13: "A05:2021 Security Misconfiguration",
    15: "A05:2021 Security Misconfiguration",
    16: "A05:2021 Security Misconfiguration",
    260: "A05:2021 Security Misconfiguration",
    315: "A05:2021 Security Misconfiguration",
    520: "A05:2021 Security Misconfiguration",
    526: "A05:2021 Security Misconfiguration",
    537: "A05:2021 Security Misconfiguration",
    541: "A05:2021 Security Misconfiguration",
    547: "A05:2021 Security Misconfiguration",
    611: "A05:2021 Security Misconfiguration",
    614: "A05:2021 Security Misconfiguration",
    756: "A05:2021 Security Misconfiguration",
    776: "A05:2021 Security Misconfiguration",
    942: "A05:2021 Security Misconfiguration",
    1004: "A05:2021 Security Misconfiguration",
    1174: "A05:2021 Security Misconfiguration",
    # A06:2021 - Vulnerable and Outdated Components
    1035: "A06:2021 Vulnerable and Outdated Components",
    1104: "A06:2021 Vulnerable and Outdated Components",
    # A07:2021 - Identification and Authentication Failures
    255: "A07:2021 Identification and Authentication Failures",
    259: "A07:2021 Identification and Authentication Failures",
    287: "A07:2021 Identification and Authentication Failures",
    288: "A07:2021 Identification and Authentication Failures",
    290: "A07:2021 Identification and Authentication Failures",
    294: "A07:2021 Identification and Authentication Failures",
    295: "A07:2021 Identification and Authentication Failures",
    297: "A07:2021 Identification and Authentication Failures",
    300: "A07:2021 Identification and Authentication Failures",
    302: "A07:2021 Identification and Authentication Failures",
    304: "A07:2021 Identification and Authentication Failures",
    306: "A07:2021 Identification and Authentication Failures",
    307: "A07:2021 Identification and Authentication Failures",
    346: "A07:2021 Identification and Authentication Failures",
    384: "A07:2021 Identification and Authentication Failures",
    521: "A07:2021 Identification and Authentication Failures",
    613: "A07:2021 Identification and Authentication Failures",
    620: "A07:2021 Identification and Authentication Failures",
    640: "A07:2021 Identification and Authentication Failures",
    798: "A07:2021 Identification and Authentication Failures",
    940: "A07:2021 Identification and Authentication Failures",
    1216: "A07:2021 Identification and Authentication Failures",
    # A08:2021 - Software and Data Integrity Failures
    345: "A08:2021 Software and Data Integrity Failures",
    353: "A08:2021 Software and Data Integrity Failures",
    426: "A08:2021 Software and Data Integrity Failures",
    494: "A08:2021 Software and Data Integrity Failures",
    502: "A08:2021 Software and Data Integrity Failures",
    565: "A08:2021 Software and Data Integrity Failures",
    784: "A08:2021 Software and Data Integrity Failures",
    829: "A08:2021 Software and Data Integrity Failures",
    830: "A08:2021 Software and Data Integrity Failures",
    913: "A08:2021 Software and Data Integrity Failures",
    # A09:2021 - Security Logging and Monitoring Failures
    117: "A09:2021 Security Logging and Monitoring Failures",
    223: "A09:2021 Security Logging and Monitoring Failures",
    532: "A09:2021 Security Logging and Monitoring Failures",
    778: "A09:2021 Security Logging and Monitoring Failures",
    # A10:2021 - Server-Side Request Forgery
    918: "A10:2021 Server-Side Request Forgery",
}


def _cwe_num(cwe_str: str) -> int | None:
    """Parse 'CWE-89' or '89' → 89. Returns None if unparseable."""
    try:
        return int(cwe_str.upper().replace("CWE-", "").strip())
    except (ValueError, AttributeError):
        return None


def cwe_to_owasp(cwe_id: str) -> str | None:
    """Map a single CWE ID string (e.g. 'CWE-89') to its OWASP Top 10 2021 category."""
    n = _cwe_num(cwe_id)
    if n is None:
        return None
    return _CWE_TO_OWASP.get(n)


class CWEEnricher:
    """Fetches CWE IDs for CVEs from the NVD API and maps them to OWASP Top 10.

    Results are cached per CVE ID (7-day TTL) to keep NVD load low.
    All network calls are best-effort: enrichment degrades gracefully on failure.
    """

    def __init__(self, offline: bool = False):
        self.offline = offline
        self._client = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True)
        self._cache: dict[str, list[str]] = {}  # cve_id → list of CWE IDs

    def close(self) -> None:
        self._client.close()

    def _cache_path(self, cve_id: str) -> Path:
        safe = cve_id.replace("/", "_")
        return CACHE_DIR / "cwe" / f"{safe}.json"

    def _load_cached(self, cve_id: str) -> list[str] | None:
        p = self._cache_path(cve_id)
        if p.exists() and (time.time() - p.stat().st_mtime) < 86400 * 7:
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None

    def _save_cached(self, cve_id: str, cwe_ids: list[str]) -> None:
        p = self._cache_path(cve_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            p.write_text(json.dumps(cwe_ids), encoding="utf-8")
        except Exception:
            pass

    def _fetch_cwe_for_cve(self, cve_id: str) -> list[str]:
        """Query NVD CVE API v2 and extract CWE IDs. Returns empty list on error."""
        if self.offline:
            return []
        cached = self._load_cached(cve_id)
        if cached is not None:
            return cached
        try:
            resp = self._client.get(NVD_CVE_URL, params={"cveId": cve_id})
            if resp.status_code != 200:
                return []
            vulns = resp.json().get("vulnerabilities", [])
            cwe_ids: list[str] = []
            for vuln in vulns:
                for weakness in vuln.get("cve", {}).get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        val = desc.get("value", "")
                        if val.startswith("CWE-") and val not in cwe_ids:
                            cwe_ids.append(val)
            self._save_cached(cve_id, cwe_ids)
            return cwe_ids
        except Exception as e:
            print(f"[warn] CWE fetch failed for {cve_id}: {e}")
            return []

    def enrich(self, findings: Iterable[Finding]) -> list[Finding]:
        """Add CWE IDs and OWASP category to findings that have a CVE ID."""
        findings = list(findings)
        for f in findings:
            if not f.cve_id:
                # Non-CVE finding: try to derive OWASP from existing cwe_id
                if f.cwe_id and not f.owasp_category:
                    f.owasp_category = cwe_to_owasp(f.cwe_id)
                continue

            # Pull CWE IDs for this CVE
            if f.cve_id not in self._cache:
                self._cache[f.cve_id] = self._fetch_cwe_for_cve(f.cve_id)

            cwe_ids = self._cache[f.cve_id]
            if cwe_ids:
                # Keep the existing single cwe_id if already set; otherwise use first
                if not f.cwe_id:
                    f.cwe_id = cwe_ids[0]
                f.cwe_ids = cwe_ids

            # OWASP category from the first mappable CWE
            if not f.owasp_category:
                for cwe in (f.cwe_ids or ([f.cwe_id] if f.cwe_id else [])):
                    cat = cwe_to_owasp(cwe)
                    if cat:
                        f.owasp_category = cat
                        break

        return findings


def enrich_cwe(findings: Iterable[Finding], offline: bool = False) -> list[Finding]:
    enricher = CWEEnricher(offline=offline)
    try:
        return enricher.enrich(findings)
    finally:
        enricher.close()
