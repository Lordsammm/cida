"""GCP Cloud Security Posture Management (CSPM) ingest.

Supported input formats (auto-detected from JSON structure):

1) GCP Security Command Center (SCC) export
   - Array (or {"findings":[...]}) of objects shaped like:
     {
       "name": "organizations/123/sources/456/findings/789",
       "parent": "...",
       "resourceName": "//cloudresourcemanager.googleapis.com/projects/abc",
       "state": "ACTIVE|INACTIVE",
       "category": "PUBLIC_BUCKET_ACL",
       "severity": "CRITICAL|HIGH|MEDIUM|LOW",
       "findingClass": "VULNERABILITY|MISCONFIGURATION|THREAT|...",
       "description": "..."
     }
   - Only ACTIVE state emits findings.

2) ScoutSuite GCP (same structure as Azure: services.<svc>.findings.<rule>.items)

Domain rollup (GCP-specific):
- iam / sa / serviceaccount / role / privileged → IDENTITY
- storage / bigquery / spanner / sql / firestore / kms → ASSET_DATA
- vpc / firewall / network / dns / loadbalancer → NETWORK
- compute / instance / gke / boot-disk → ENDPOINT (compute nodes)
- appengine / cloudrun / cloudfunctions → APPSEC
- audit / log / scc / chronicle → DETECT_RESPOND
- backup / snapshot → RESILIENCE
- otherwise → CLOUD
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import Domain, Finding, Severity


_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "severity_unspecified": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "warning": Severity.MEDIUM,
    "danger": Severity.HIGH,
}

_IAM_HINTS = ("iam", "service_account", "sa_", "role", "privileg", "owner", "mfa")
_DATA_HINTS = ("storage", "bucket", "bigquery", "spanner", "sql", "firestore", "datastore", "kms")
_NET_HINTS = ("vpc", "firewall", "network", "dns", "loadbalancer", "armor")
_END_HINTS = ("compute", "instance", "boot_disk", "vm")
_APP_HINTS = ("appengine", "cloudrun", "cloudfunctions", "gke", "container")
_LOG_HINTS = ("audit", "log", "scc", "chronicle", "monitoring")
_RES_HINTS = ("backup", "snapshot", "recovery")

_INTERNET_HINTS = ("public", "internet", "0.0.0.0/0", "::/0", "publicly", "allusers", "allauthenticatedusers")


def _severity_from(value: Any) -> Severity:
    return _SEV_MAP.get(str(value or "").strip().lower(), Severity.LOW)


def _domain_for(text: str) -> Domain:
    t = (text or "").lower()
    if any(h in t for h in _IAM_HINTS):
        return Domain.IDENTITY
    if any(h in t for h in _LOG_HINTS):
        return Domain.DETECT_RESPOND
    if any(h in t for h in _DATA_HINTS):
        return Domain.ASSET_DATA
    if any(h in t for h in _APP_HINTS):
        return Domain.APPSEC
    if any(h in t for h in _NET_HINTS):
        return Domain.NETWORK
    if any(h in t for h in _END_HINTS):
        return Domain.ENDPOINT
    if any(h in t for h in _RES_HINTS):
        return Domain.RESILIENCE
    return Domain.CLOUD


def _looks_internet_exposed(*texts: str) -> bool:
    blob = " ".join((t or "").lower() for t in texts)
    return any(h in blob for h in _INTERNET_HINTS)


def _parse_scc_record(rec: dict) -> Finding | None:
    state = (rec.get("state") or "ACTIVE").upper()
    if state != "ACTIVE":
        return None
    sev = _severity_from(rec.get("severity"))
    category = rec.get("category") or "GCP_SCC_FINDING"
    desc = rec.get("description") or rec.get("externalUri") or ""
    resource = rec.get("resourceName") or rec.get("resource_name") or rec.get("name") or "unknown-resource"
    asset = f"gcp:{resource}"
    exposure = "internet" if _looks_internet_exposed(category, desc, resource) else "internal"
    return Finding(
        source="gcp_scc",
        asset=asset,
        title=str(category)[:240],
        severity=sev,
        domain=_domain_for(f"{category} {resource}"),
        exposure=exposure,
        evidence=str(desc)[:500] or None,
        raw={"finding_class": rec.get("findingClass") or rec.get("finding_class"),
             "category": category,
             "name": rec.get("name")},
    )


def _parse_scoutsuite_gcp(data: dict) -> list[Finding]:
    out: list[Finding] = []
    services = (data.get("services") or {})
    for svc_name, svc in services.items():
        findings = (svc or {}).get("findings") or {}
        for rule_id, rule in findings.items():
            if not isinstance(rule, dict):
                continue
            items = rule.get("items") or []
            if not items:
                continue
            sev = _severity_from(rule.get("level"))
            title = rule.get("description") or rule_id
            for item in items:
                asset = f"gcp:{svc_name}:{item}"
                exposure = "internet" if _looks_internet_exposed(title, item) else "internal"
                out.append(Finding(
                    source="scoutsuite_gcp",
                    asset=asset,
                    title=str(title)[:240],
                    severity=sev,
                    domain=_domain_for(f"{svc_name} {title}"),
                    exposure=exposure,
                    evidence=(rule.get("rationale") or "")[:500] or None,
                    raw={"rule": rule_id, "service": svc_name},
                ))
    return out


def parse_gcp_cspm(path: str | Path) -> list[Finding]:
    """Parse GCP SCC or ScoutSuite GCP JSON → list[Finding]."""
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    if text.startswith("scoutsuite_results"):
        text = text.split("=", 1)[1].rstrip(";\n ")
    data = json.loads(text)

    # ScoutSuite
    if isinstance(data, dict) and "services" in data and isinstance(data["services"], dict):
        return _parse_scoutsuite_gcp(data)

    # SCC
    if isinstance(data, dict):
        for key in ("findings", "Findings", "results", "value"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        return []
    out: list[Finding] = []
    for rec in data:
        if not isinstance(rec, dict):
            continue
        # SCC findings are usually wrapped in {"finding": {...}, "resource": {...}}
        if "finding" in rec and isinstance(rec["finding"], dict):
            rec = rec["finding"]
        f = _parse_scc_record(rec)
        if f is not None:
            out.append(f)
    return out
