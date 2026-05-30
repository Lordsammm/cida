"""Dark-web intelligence ingest - credential leaks, stealer logs, breach mentions.

Designed to be vendor-agnostic. Accepts CSV or JSON in three logical shapes
(auto-detected from columns / keys):

1) Credential leak / breach exposure
   Common vendors: SpyCloud, DeHashed, HaveIBeenPwned, IntelX, Flare.
   Expected columns (any case, any subset):
     email, username, password_status (plaintext|hashed|unknown),
     source_breach (e.g. "LinkedIn 2021"), date (YYYY-MM-DD),
     ip, severity, password_plaintext_exposed (bool).
   → Emits one Finding per record, domain=IDENTITY.
   Severity: plaintext-credential or executive email → CRITICAL/HIGH;
             hashed/unknown → MEDIUM; very old (>5y) → LOW.

2) Stealer log / infostealer infection
   Common vendors: Hudson Rock, Russian Market, Genesis Market (historical),
   Flare. Expected columns:
     victim_email, malware_family (RedLine/Raccoon/Vidar/Lumma/...),
     first_seen (date), affected_domain, credentials_count (int),
     country, machine_id.
   → Emits one Finding per infected machine. Severity HIGH by default,
     CRITICAL if `affected_domain` matches an org email_domain.
   Domain = ENDPOINT (machine compromise) with secondary IDENTITY flag.

3) Brand / breach / leak chatter (forum / Telegram / paste)
   Expected columns:
     mention_text (or text), source (forum/telegram/paste/marketplace),
     date, sentiment (negative|neutral|positive),
     keywords (comma-separated, e.g. "ransomware,leak").
   → Emits one Finding per mention. Severity MEDIUM by default, HIGH if
     keywords include "ransomware", "auction", "exfil"; CRITICAL if both
     "auction" and "internal data".
   Domain = ASSET_DATA (data-exposure rollup) or GOVERNANCE if reputational.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from models import Domain, Finding, Severity


_RANSOM_KEYWORDS = ("ransom", "ransomware", "lockbit", "blackcat", "alphv", "clop", "akira", "play")
_AUCTION_KEYWORDS = ("auction", "for sale", "sell access", "broker", "rdp access", "vpn access")
_EXFIL_KEYWORDS = ("exfil", "data leak", "data dump", "internal data", "stolen data", "database leak")

_EXEC_PREFIXES = ("ceo", "cfo", "coo", "cto", "ciso", "cio", "cmo", "chro", "managing director", "md")


# ---------- shared helpers ----------

def _to_severity(label: Any, default: Severity = Severity.MEDIUM) -> Severity:
    if label is None:
        return default
    s = str(label).strip().lower()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
        "info": Severity.INFO,
    }.get(s, default)


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in ("true", "1", "yes", "y", "t")


def _years_since(date_str: str) -> float:
    if not date_str:
        return 0.0
    try:
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                dt = datetime.strptime(date_str, fmt)
                break
            except ValueError:
                continue
        else:
            return 0.0
        return (datetime.now(tz=timezone.utc) - dt.replace(tzinfo=timezone.utc)).days / 365.25
    except Exception:  # noqa: BLE001
        return 0.0


def _is_executive(email: str) -> bool:
    if not email or "@" not in email:
        return False
    local = email.split("@", 1)[0].lower()
    return any(local.startswith(p) for p in _EXEC_PREFIXES) or any(p in local for p in ("ceo", "cfo", "ciso", "cto"))


# ---------- record-type classifier ----------

def _classify(rec: dict) -> str:
    keys = {str(k).lower() for k in rec.keys()}
    if {"malware_family", "victim_email"} & keys or "stealer" in " ".join(keys):
        return "stealer"
    if {"mention_text", "text"} & keys and ("source" in keys or "keywords" in keys):
        return "mention"
    if {"email", "username", "password_status", "source_breach"} & keys:
        return "credential"
    # Heuristic fallback
    if "email" in keys:
        return "credential"
    if "mention_text" in keys or "text" in keys:
        return "mention"
    return "credential"


# ---------- parsers per record type ----------

def _parse_credential(rec: dict, org_email_domains: Iterable[str] = ()) -> Finding:
    email = (rec.get("email") or rec.get("Email") or rec.get("username") or "").strip()
    breach = rec.get("source_breach") or rec.get("breach") or rec.get("source") or "unknown"
    status = (rec.get("password_status") or rec.get("status") or "unknown").lower()
    plaintext = _bool(rec.get("password_plaintext_exposed")) or (status == "plaintext")
    date_str = str(rec.get("date") or rec.get("breach_date") or "")
    age = _years_since(date_str)

    # Severity heuristic
    if plaintext and _is_executive(email):
        sev = Severity.CRITICAL
    elif plaintext:
        sev = Severity.HIGH
    elif _is_executive(email):
        sev = Severity.HIGH
    elif status == "hashed":
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW if age > 5 else Severity.MEDIUM

    # Override with explicit severity field if provided
    if rec.get("severity"):
        sev = _to_severity(rec.get("severity"), default=sev)

    title = f"Credential leak: {email} via {breach}"
    return Finding(
        source="darkweb_credentials",
        asset=f"identity:{email or 'unknown'}",
        title=title[:240],
        severity=sev,
        domain=Domain.IDENTITY,
        exposure="internet",
        evidence=f"Status={status} age={age:.1f}y" + (" (plaintext)" if plaintext else ""),
        raw={
            "email": email,
            "breach": breach,
            "status": status,
            "plaintext": plaintext,
            "date": date_str,
            "org_match": any(email.lower().endswith("@" + d.lower().lstrip("@")) for d in org_email_domains),
        },
    )


def _parse_stealer(rec: dict, org_email_domains: Iterable[str] = ()) -> Finding:
    email = (rec.get("victim_email") or rec.get("email") or "").strip()
    family = rec.get("malware_family") or rec.get("family") or "infostealer"
    first_seen = str(rec.get("first_seen") or rec.get("date") or "")
    affected = (rec.get("affected_domain") or rec.get("domain") or "").lower()
    creds = int(rec.get("credentials_count") or rec.get("creds") or 0)
    machine_id = rec.get("machine_id") or rec.get("hwid") or "unknown-machine"

    org_match = any(affected == d.lower().lstrip("@") for d in org_email_domains) or any(
        email.lower().endswith("@" + d.lower().lstrip("@")) for d in org_email_domains
    )
    sev = Severity.CRITICAL if org_match else Severity.HIGH

    title = f"Infostealer infection ({family}) - {creds} creds from {affected or 'unknown domain'}"
    return Finding(
        source="darkweb_stealer",
        asset=f"machine:{machine_id}",
        title=title[:240],
        severity=sev,
        domain=Domain.ENDPOINT,
        exposure="internet",
        evidence=f"victim={email} domain={affected} first_seen={first_seen} creds={creds}",
        raw={
            "family": family,
            "victim_email": email,
            "domain": affected,
            "creds": creds,
            "first_seen": first_seen,
            "org_match": org_match,
        },
    )


def _parse_mention(rec: dict, org_email_domains: Iterable[str] = ()) -> Finding:
    text = rec.get("mention_text") or rec.get("text") or ""
    source = rec.get("source") or rec.get("forum") or "darkweb"
    date_str = str(rec.get("date") or "")
    keywords_raw = rec.get("keywords") or ""
    if isinstance(keywords_raw, str):
        keywords = [k.strip().lower() for k in keywords_raw.split(",") if k.strip()]
    elif isinstance(keywords_raw, list):
        keywords = [str(k).strip().lower() for k in keywords_raw]
    else:
        keywords = []

    blob = (text + " " + " ".join(keywords)).lower()
    is_ransom = any(k in blob for k in _RANSOM_KEYWORDS)
    is_auction = any(k in blob for k in _AUCTION_KEYWORDS)
    is_exfil = any(k in blob for k in _EXFIL_KEYWORDS)

    if is_auction and is_exfil:
        sev = Severity.CRITICAL
    elif is_ransom or is_auction or is_exfil:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM
    if rec.get("severity"):
        sev = _to_severity(rec.get("severity"), default=sev)

    title = f"Dark-web mention ({source}): {text[:120]}".strip()
    return Finding(
        source="darkweb_mention",
        asset=f"intel:{source}",
        title=title[:240],
        severity=sev,
        domain=Domain.ASSET_DATA,
        exposure="internet",
        evidence=text[:500] or None,
        raw={
            "source": source,
            "date": date_str,
            "keywords": keywords,
            "is_ransom": is_ransom,
            "is_auction": is_auction,
            "is_exfil": is_exfil,
        },
    )


# ---------- public API ----------

def parse_darkweb(
    path: str | Path,
    org_email_domains: Iterable[str] = (),
) -> list[Finding]:
    """Parse a dark-web intel feed (CSV or JSON) → list[Finding].

    `org_email_domains` lets the parser tag findings affecting the org directly
    (e.g. infostealer infections on @acme.com).
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []

    records: list[dict] = []
    suffix = p.suffix.lower()
    if suffix == ".csv" or text.startswith("email,") or text.startswith("victim_email,") or text.startswith("mention_text,"):
        reader = csv.DictReader(text.splitlines())
        records = [dict(row) for row in reader]
    else:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("records", "findings", "results", "data", "items"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            else:
                data = [data]
        if isinstance(data, list):
            records = [r for r in data if isinstance(r, dict)]

    out: list[Finding] = []
    for rec in records:
        kind = _classify(rec)
        if kind == "stealer":
            out.append(_parse_stealer(rec, org_email_domains))
        elif kind == "mention":
            out.append(_parse_mention(rec, org_email_domains))
        else:
            out.append(_parse_credential(rec, org_email_domains))
    return out
