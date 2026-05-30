"""AWS Cloud Security Posture Management (CSPM) ingest.

Supported input formats (auto-detected from JSON structure):

1) Prowler v3 / v4 JSON output
   - Array of finding objects with keys like:
     CheckID, CheckTitle, ServiceName, Status (PASS|FAIL),
     Severity (informational|low|medium|high|critical),
     ResourceId, ResourceArn, Region, AccountId, Description, Risk
   - Failed checks (Status == FAIL) are emitted as Findings.

2) AWS Security Hub ASFF (Findings export)
   - Array of objects with keys like:
     SchemaVersion, Id, Title, Description, Severity.Label, Resources[],
     Workflow.Status, RecordState.
   - Only ACTIVE / WARNING records are emitted.

Each finding rolls up to Domain.CLOUD (or IDENTITY for IAM checks). Internet-
facing exposure is inferred from service / check hints (e.g. public S3,
0.0.0.0/0 SG, public RDS).
"""
from __future__ import annotations

import json
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
}

_IAM_HINTS = ("iam", "identity", "sts", "sso", "secretsmanager", "kms_key_policy")
_DATA_HINTS = ("s3", "rds", "dynamodb", "redshift", "efs", "ebs", "glacier", "backup")
_NET_HINTS = ("ec2", "vpc", "elbv2", "elb", "cloudfront", "apigateway", "route53", "wafv2", "shield")
_APP_HINTS = ("lambda", "ecs", "eks", "apigateway", "appsync", "amplify")
_LOG_HINTS = ("cloudtrail", "cloudwatch", "guardduty", "config", "securityhub")
_RES_HINTS = ("backup", "drs", "elasticache")

_INTERNET_HINTS = (
    "public", "0.0.0.0/0", "::/0", "open to the world", "internet",
    "publicly accessible", "publicly_accessible", "world readable", "world-readable",
)


def _severity_from(value: Any) -> Severity:
    if value is None:
        return Severity.LOW
    return _SEV_MAP.get(str(value).strip().lower(), Severity.LOW)


def _domain_for_service(service: str, title: str) -> Domain:
    s = (service or "").lower()
    t = (title or "").lower()
    blob = f"{s} {t}"
    if any(h in blob for h in _IAM_HINTS):
        return Domain.IDENTITY
    if any(h in blob for h in _LOG_HINTS):
        return Domain.DETECT_RESPOND
    if any(h in blob for h in _DATA_HINTS):
        return Domain.ASSET_DATA
    if any(h in blob for h in _APP_HINTS):
        return Domain.APPSEC
    if any(h in blob for h in _NET_HINTS):
        return Domain.NETWORK
    if any(h in blob for h in _RES_HINTS):
        return Domain.RESILIENCE
    return Domain.CLOUD


def _looks_internet_exposed(*texts: str) -> bool:
    blob = " ".join((t or "").lower() for t in texts)
    return any(h in blob for h in _INTERNET_HINTS)


def _parse_prowler_record(rec: dict) -> Finding | None:
    status = (rec.get("Status") or rec.get("status") or "").strip().upper()
    if status not in ("FAIL", "FAILED", "WARNING"):
        return None
    sev = _severity_from(rec.get("Severity") or rec.get("severity"))
    service = rec.get("ServiceName") or rec.get("service_name") or rec.get("service") or ""
    title = rec.get("CheckTitle") or rec.get("check_title") or rec.get("CheckID") or "AWS CSPM finding"
    desc = rec.get("StatusExtended") or rec.get("Description") or rec.get("Risk") or ""
    resource = (
        rec.get("ResourceArn") or rec.get("resource_arn")
        or rec.get("ResourceId") or rec.get("resource_id")
        or rec.get("Resource") or "unknown-resource"
    )
    region = rec.get("Region") or rec.get("region") or ""
    asset = f"aws:{region}:{resource}" if region else f"aws:{resource}"
    exposure = "internet" if _looks_internet_exposed(title, desc, str(resource)) else "internal"
    return Finding(
        source="prowler",
        asset=asset,
        title=title[:240],
        severity=sev,
        domain=_domain_for_service(service, title),
        exposure=exposure,
        evidence=(desc or "")[:500] or None,
        raw={"check_id": rec.get("CheckID") or rec.get("check_id"), "service": service,
             "account": rec.get("AccountId") or rec.get("account_id")},
    )


def _parse_asff_record(rec: dict) -> Finding | None:
    state = (rec.get("RecordState") or "ACTIVE").upper()
    if state != "ACTIVE":
        return None
    workflow = ((rec.get("Workflow") or {}).get("Status") or "").upper()
    if workflow in ("SUPPRESSED", "RESOLVED"):
        return None
    sev_label = (rec.get("Severity") or {}).get("Label") or (rec.get("Severity") or {}).get("Original")
    sev = _severity_from(sev_label)
    title = rec.get("Title") or "AWS Security Hub finding"
    desc = rec.get("Description") or ""
    resources = rec.get("Resources") or []
    resource_id = (resources[0].get("Id") if resources else None) or "unknown-resource"
    region = (resources[0].get("Region") if resources else None) or rec.get("Region") or ""
    service_label = (resources[0].get("Type") if resources else None) or ""
    asset = f"aws:{region}:{resource_id}" if region else f"aws:{resource_id}"
    exposure = "internet" if _looks_internet_exposed(title, desc, resource_id, service_label) else "internal"
    return Finding(
        source="security_hub",
        asset=asset,
        title=title[:240],
        severity=sev,
        domain=_domain_for_service(service_label, title),
        exposure=exposure,
        evidence=desc[:500] or None,
        raw={"finding_id": rec.get("Id"), "product": (rec.get("ProductFields") or {}).get("aws/securityhub/ProductName"),
             "compliance": (rec.get("Compliance") or {}).get("Status")},
    )


def _detect_and_parse(records: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        # ASFF distinguishes itself by SchemaVersion + Resources[]
        if "SchemaVersion" in rec or ("Resources" in rec and "Severity" in rec and "Title" in rec):
            f = _parse_asff_record(rec)
        else:
            f = _parse_prowler_record(rec)
        if f is not None:
            out.append(f)
    return out


def parse_aws_cspm(path: str | Path) -> list[Finding]:
    """Parse a Prowler or AWS Security Hub ASFF JSON file → list[Finding]."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    if isinstance(data, dict):
        # Common wrappers
        for key in ("Findings", "findings", "results"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        return []
    return _detect_and_parse(data)
