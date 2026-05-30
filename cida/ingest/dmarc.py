"""DMARC/SPF/DKIM/MTA-STS posture parser.

Expects JSON output from a checker (e.g. `checkdmarc`, `hardenize`):
{
  "domain": "example.com",
  "spf": {"present": true, "policy": "v=spf1 -all"},
  "dmarc": {"present": true, "policy": "reject", "pct": 100},
  "dkim": {"present": true},
  "mta_sts": {"present": false}
}
"""
from __future__ import annotations

import json
from pathlib import Path

from cida.models import Domain, Finding, Severity


def parse_dmarc_check(json_path: str | Path) -> list[Finding]:
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        data = [data]
    findings: list[Finding] = []
    for entry in data:
        domain_name = entry.get("domain", "unknown")
        # DMARC missing or weak
        dmarc = entry.get("dmarc", {}) or {}
        if not dmarc.get("present"):
            findings.append(Finding(
                source="dmarc_check", asset=domain_name,
                title="DMARC record missing", severity=Severity.HIGH,
                domain=Domain.DETECT_RESPOND, cwe_id="CWE-290", exposure="internet",
                evidence="No DMARC record found for domain"))
        elif (dmarc.get("policy") or "none") == "none":
            findings.append(Finding(
                source="dmarc_check", asset=domain_name,
                title="DMARC policy = none (monitoring only)", severity=Severity.MEDIUM,
                domain=Domain.DETECT_RESPOND, exposure="internet",
                evidence="DMARC present but not enforcing - BEC risk elevated"))
        # SPF
        spf = entry.get("spf", {}) or {}
        if not spf.get("present"):
            findings.append(Finding(
                source="dmarc_check", asset=domain_name,
                title="SPF record missing", severity=Severity.MEDIUM,
                domain=Domain.DETECT_RESPOND, exposure="internet"))
        # DKIM
        dkim = entry.get("dkim", {}) or {}
        if not dkim.get("present"):
            findings.append(Finding(
                source="dmarc_check", asset=domain_name,
                title="DKIM signing not detected", severity=Severity.MEDIUM,
                domain=Domain.DETECT_RESPOND, exposure="internet"))
        # MTA-STS
        mta = entry.get("mta_sts", {}) or {}
        if not mta.get("present"):
            findings.append(Finding(
                source="dmarc_check", asset=domain_name,
                title="MTA-STS not deployed", severity=Severity.LOW,
                domain=Domain.DETECT_RESPOND, exposure="internet"))
    return findings
