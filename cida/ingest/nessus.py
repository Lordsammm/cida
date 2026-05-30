"""Nessus CSV and XML (.nessus) parser → normalized Finding objects.

Nessus CSV columns (typical): Plugin ID, CVE, CVSS v3.0 Base Score, Risk,
Host, Protocol, Port, Name, Synopsis, Description, Solution, See Also, ...

Nessus XML: NessusClientData_v2 root → Report → ReportHost → ReportItem
  severity attr: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd

from cida.models import Domain, Finding, Severity

_RISK_TO_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "none": Severity.INFO,
}


def _domain_for(name: str) -> Domain:
    n = (name or "").lower()
    if any(k in n for k in ["web", "http", "tls", "ssl", "cert", "cors", "xss", "sql"]):
        return Domain.APPSEC
    if any(k in n for k in ["smb", "rdp", "dns", "ntp", "snmp", "ftp"]):
        return Domain.NETWORK
    if any(k in n for k in ["windows", "linux", "kernel", "patch", "smbv1", "office"]):
        return Domain.ENDPOINT
    if any(k in n for k in ["s3", "azure", "gcp", "iam", "bucket", "cloud"]):
        return Domain.CLOUD
    return Domain.NETWORK


def parse_nessus_csv(csv_path: str | Path) -> list[Finding]:
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    df.columns = [c.strip() for c in df.columns]

    findings: list[Finding] = []
    for _, row in df.iterrows():
        risk = (row.get("Risk") or "").strip().lower()
        sev = _RISK_TO_SEVERITY.get(risk, Severity.INFO)
        if sev == Severity.INFO:
            continue  # skip informational
        cvss_raw = row.get("CVSS v3.0 Base Score") or row.get("CVSS Base Score") or ""
        try:
            cvss = float(cvss_raw) if cvss_raw else None
        except ValueError:
            cvss = None
        cve = (row.get("CVE") or "").strip()
        cve = cve.split(",")[0].strip() if cve else None
        name = row.get("Name") or "Unnamed"
        host = row.get("Host") or row.get("IP Address") or "unknown"
        port = row.get("Port") or ""
        asset = f"{host}:{port}" if port else host
        findings.append(Finding(
            source="nessus",
            asset=asset,
            title=name,
            severity=sev,
            domain=_domain_for(name),
            cve_id=cve or None,
            cvss_v3=cvss,
            cvss_severity=sev,
            exposure="unknown",
            evidence=(row.get("Synopsis") or "").strip()[:500] or None,
        ))
    return findings


_XML_SEV = {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM,
            "3": Severity.HIGH, "4": Severity.CRITICAL}


def parse_nessus_xml(xml_path: str | Path) -> list[Finding]:
    """Parse a .nessus (XML) file produced by Nessus / Tenable."""
    tree = ET.parse(str(xml_path))
    root = tree.getroot()
    findings: list[Finding] = []
    for report in root.iter("Report"):
        for host in report.iter("ReportHost"):
            host_name = host.get("name", "unknown")
            for item in host.iter("ReportItem"):
                sev_int = item.get("severity", "0")
                sev = _XML_SEV.get(sev_int, Severity.INFO)
                if sev == Severity.INFO:
                    continue
                plugin_name = item.get("pluginName") or "Unnamed"
                port = item.get("port", "")
                asset = f"{host_name}:{port}" if port and port != "0" else host_name
                cve_el = item.find("cve")
                cve = (cve_el.text or "").strip() if cve_el is not None else None
                cvss_el = item.find("cvss3_base_score")
                if cvss_el is None:
                    cvss_el = item.find("cvss_base_score")
                cvss: float | None = None
                if cvss_el is not None and cvss_el.text:
                    try:
                        cvss = float(cvss_el.text)
                    except ValueError:
                        pass
                synopsis_el = item.find("synopsis")
                evidence = (synopsis_el.text or "").strip()[:500] if synopsis_el is not None else None
                findings.append(Finding(
                    source="nessus",
                    asset=asset,
                    title=plugin_name,
                    severity=sev,
                    domain=_domain_for(plugin_name),
                    cve_id=cve or None,
                    cvss_v3=cvss,
                    cvss_severity=sev,
                    exposure="unknown",
                    evidence=evidence or None,
                ))
    return findings


def parse_nessus(path: str | Path) -> list[Finding]:
    """Dispatch to CSV or XML parser based on file extension."""
    p = Path(path)
    if p.suffix.lower() in (".xml", ".nessus"):
        return parse_nessus_xml(p)
    return parse_nessus_csv(p)
