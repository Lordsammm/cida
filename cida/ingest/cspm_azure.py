"""Azure Cloud Security Posture Management (CSPM) ingest.

Supported input formats (auto-detected from JSON structure):

1) Azure Defender for Cloud (Microsoft Defender Security Recommendations export)
   - Array of objects with shape:
     {
       "id": "/subscriptions/.../providers/Microsoft.Security/assessments/<guid>",
       "name": "...",
       "properties": {
         "displayName": "...",
         "status": {"code": "Healthy|Unhealthy|NotApplicable", "cause": ...},
         "severity": "Low|Medium|High",
         "resourceDetails": {"id": "<resource arn>"},
         "description": "...",
         "remediationDescription": "...",
         "additionalData": {...}
       }
     }
   - Only Unhealthy status emits findings.

2) ScoutSuite Azure (JSON exported from `scoutsuite-results-*.js`)
   - Nested under `services.<service>.findings.<rule>`:
     {
       "description": "...",
       "level": "warning|danger",
       "items": [list of affected resource paths]
     }

Domain rollup:
- iam / aad / role / privileged → IDENTITY
- storage / sql / cosmos / keyvault → ASSET_DATA
- network / nsg / firewall / appgw / loadbalancer → NETWORK
- vm / disk / patch → ENDPOINT
- appservice / functions / aks → APPSEC
- monitor / sentinel / log / defender → DETECT_RESPOND
- backup / recovery → RESILIENCE
- otherwise → CLOUD
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cida.models import Domain, Finding, Severity


_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "warning": Severity.MEDIUM,
    "danger": Severity.HIGH,
    "error": Severity.HIGH,
}

_IAM_HINTS = ("iam", "aad", "active_directory", "role", "privileg", "rbac", "identity", "mfa")
_DATA_HINTS = ("storage", "blob", "sql", "cosmos", "keyvault", "datalake", "synapse")
_NET_HINTS = ("network", "nsg", "firewall", "appgw", "loadbalancer", "frontdoor", "ddos")
_END_HINTS = ("vm", "virtualmachine", "disk", "patch", "compute")
_APP_HINTS = ("appservice", "function", "aks", "containerregistry", "webapp")
_LOG_HINTS = ("monitor", "sentinel", "log_analytics", "defender", "activitylog")
_RES_HINTS = ("backup", "recovery", "siterecovery")

_INTERNET_HINTS = ("public", "internet", "publicly", "open to the world", "0.0.0.0/0", "::/0", "anywhere")


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


def _parse_defender_record(rec: dict) -> Finding | None:
    props = rec.get("properties") or {}
    status_code = ((props.get("status") or {}).get("code") or "").lower()
    if status_code != "unhealthy":
        return None
    title = props.get("displayName") or rec.get("name") or "Azure Defender finding"
    desc = props.get("description") or (props.get("status") or {}).get("cause") or ""
    sev = _severity_from(props.get("severity"))
    resource_id = (props.get("resourceDetails") or {}).get("id") or rec.get("id") or "unknown-resource"
    asset = f"azure:{resource_id}"
    exposure = "internet" if _looks_internet_exposed(title, desc, resource_id) else "internal"
    return Finding(
        source="azure_defender",
        asset=asset,
        title=str(title)[:240],
        severity=sev,
        domain=_domain_for(f"{title} {resource_id}"),
        exposure=exposure,
        evidence=str(desc)[:500] or None,
        raw={"assessment_id": rec.get("name"), "subscription": _extract_subscription(resource_id)},
    )


def _extract_subscription(resource_id: str) -> str | None:
    m = re.search(r"/subscriptions/([0-9a-f-]+)/", resource_id or "", flags=re.IGNORECASE)
    return m.group(1) if m else None


def _parse_scoutsuite_az(data: dict) -> list[Finding]:
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
                asset = f"azure:{svc_name}:{item}"
                exposure = "internet" if _looks_internet_exposed(title, item) else "internal"
                out.append(Finding(
                    source="scoutsuite_azure",
                    asset=asset,
                    title=str(title)[:240],
                    severity=sev,
                    domain=_domain_for(f"{svc_name} {title}"),
                    exposure=exposure,
                    evidence=(rule.get("rationale") or "")[:500] or None,
                    raw={"rule": rule_id, "service": svc_name},
                ))
    return out


def parse_azure_cspm(path: str | Path) -> list[Finding]:
    """Parse Azure Defender or ScoutSuite Azure JSON → list[Finding]."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    # ScoutSuite output files are JS-wrapped (`scoutsuite_results = {...};`)
    text = text.strip()
    if text.startswith("scoutsuite_results"):
        text = text.split("=", 1)[1].rstrip(";\n ")
    data = json.loads(text)

    # ScoutSuite (has "services" key at top level)
    if isinstance(data, dict) and "services" in data and isinstance(data["services"], dict):
        return _parse_scoutsuite_az(data)

    # Defender for Cloud - array, or wrapper with "value"
    if isinstance(data, dict):
        for key in ("value", "Findings", "findings", "results"):
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
        f = _parse_defender_record(rec)
        if f is not None:
            out.append(f)
    return out
