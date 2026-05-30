"""CIDA Project Drop Zone - auto-discovers all assessment artefacts in a folder.

Usage
-----
Create a folder anywhere under ``cida/clients/`` - name it however you like -
and drop everything inside.  Subdirectory structure is fully supported;
all files are discovered recursively.  Only ``org_profile.yaml`` and a
questionnaire file are required.

    cida/clients/
        XYZ Bank/
            org_profile.yaml          ← required
            questionnaire.csv         ← required (or .xlsx)
            scan_results.json         ← any name, any format
            april_assessment.xml      ← any name
            screenshots/              ← PNG, JPEG, SVG, …  →  Evidence Appendix
            cloud_exports/            ← AWS/Azure/GCP CSPM, any name
            ...

Run
~~~
    cida score-project "cida/clients/XYZ Bank"

Or programmatically:

    from ingest.project import load_project
    org, responses, findings, evidence = load_project(Path("cida/clients/XYZ Bank"))
"""
from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from models import Finding, OrgProfile, QuestionnaireResponses
from ingest.sniffer import (
    SniffResult, sniff, format_unknown_diagnostic,
    _IMAGE_EXTS, _SKIP_EXTS,
)


# Files CIDA should always ignore
_ALWAYS_SKIP = {
    "readme.md", "readme.txt", ".gitignore", ".ds_store", "desktop.ini",
    "thumbs.db", ".env", ".env.local",
}

# Known questionnaire / org-profile filenames (handled separately)
_PROFILE_NAMES = {"org_profile.yaml", "org_profile.yml", "org.yaml", "org.yml"}
_QUESTIONNAIRE_NAMES = {"questionnaire.csv", "questionnaire.xlsx",
                        "responses.csv", "responses.xlsx"}


@dataclass
class EvidenceImage:
    filename: str
    path: Path
    size_bytes: int
    captured_at: datetime
    caption: str  # derived from filename (title-cased, no extension)


def _find_file(root: Path, *candidates: str) -> Path | None:
    all_files = {p.name.lower(): p for p in root.rglob("*") if p.is_file()}
    for c in candidates:
        match = all_files.get(c.lower())
        if match:
            return match
    return None


def _load_org_profile(path: Path) -> OrgProfile:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return OrgProfile.model_validate(data)


def _load_questionnaire(path: Path, org_id: str) -> QuestionnaireResponses:
    from ingest.questionnaire import parse_questionnaire_csv
    if path.suffix.lower() == ".csv":
        return parse_questionnaire_csv(path, org_id=org_id)
    if path.suffix.lower() in (".xlsx", ".xls"):
        try:
            import openpyxl
            wb = openpyxl.load_workbook(path, data_only=True)
            ws = wb.active
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".csv",
                                             delete=False, encoding="utf-8", newline="") as tmp:
                writer = csv.writer(tmp)
                for row in ws.iter_rows(values_only=True):
                    writer.writerow(["" if v is None else v for v in row])
                tmp_path = Path(tmp.name)
            try:
                return parse_questionnaire_csv(tmp_path, org_id=org_id)
            finally:
                tmp_path.unlink(missing_ok=True)
        except ImportError:
            print("[warn] openpyxl not installed -- cannot read XLSX questionnaire. "
                  "Run: pip install openpyxl")
    return QuestionnaireResponses(
        org_id=org_id, submitted_at=datetime.now(timezone.utc), responses=[]
    )


def _make_evidence_image(path: Path) -> EvidenceImage:
    try:
        stat = path.stat()
        size = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    except Exception:
        size = 0
        mtime = datetime.now(timezone.utc)
    caption = path.stem.replace("_", " ").replace("-", " ").title()
    return EvidenceImage(filename=path.name, path=path,
                         size_bytes=size, captured_at=mtime, caption=caption)


def _discover_all_files(root: Path) -> list[Path]:
    """Return all files recursively, skipping known non-assets."""
    out = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name in _ALWAYS_SKIP:
            continue
        # Skip any file inside an output/ subdirectory (CIDA's own output)
        if "output" in (part.lower() for part in p.relative_to(root).parts[:-1]):
            continue
        out.append(p)
    return out


def _load_findings_from_paths(
    paths: list[Path],
    org_email_domains: list[str],
) -> tuple[list[Finding], list[EvidenceImage], list[dict]]:
    """Route each file through the sniffer, parse findings, collect evidence images.

    Returns (findings, evidence_images, unclassified_diagnostic_dicts).
    """
    from ingest.sniffer import sniff, format_unknown_diagnostic

    findings: list[Finding] = []
    images: list[EvidenceImage] = []
    unclassified: list[dict] = []

    for p in paths:
        name = p.name.lower()
        if name in _PROFILE_NAMES or name in _QUESTIONNAIRE_NAMES:
            continue

        result: SniffResult = sniff(p)
        cat = result.category

        if cat == "skip":
            continue

        if cat == "evidence_image":
            images.append(_make_evidence_image(p))
            continue

        if cat == "unknown":
            diag_str = format_unknown_diagnostic(p, result)
            print(diag_str)
            unclassified.append({
                "filename": p.name,
                "path": str(p),
                "top_keys": result.top_keys,
                "sample_values": result.sample_values,
                "scores": result.scores,
            })
            continue

        try:
            if cat == "cspm_aws":
                from ingest.cspm_aws import parse_aws_cspm
                findings.extend(parse_aws_cspm(p))

            elif cat == "cspm_azure":
                from ingest.cspm_azure import parse_azure_cspm
                findings.extend(parse_azure_cspm(p))

            elif cat == "cspm_gcp":
                from ingest.cspm_gcp import parse_gcp_cspm
                findings.extend(parse_gcp_cspm(p))

            elif cat in ("vuln_scan", "network_scan"):
                # Route XML/CSV/nessus to nessus parser; JSON to generic vuln handler
                if p.suffix.lower() in (".xml", ".nessus", ".csv"):
                    from ingest.nessus import parse_nessus
                    findings.extend(parse_nessus(p))
                else:
                    findings.extend(_parse_generic_vuln_json(p))

            elif cat == "web_app_scan":
                findings.extend(_parse_web_app_scan(p))

            elif cat == "attack_surface":
                from ingest.attack_surface import parse_attack_surface
                findings.extend(parse_attack_surface(p))

            elif cat == "darkweb":
                from ingest.darkweb import parse_darkweb
                findings.extend(parse_darkweb(p, org_email_domains=org_email_domains))

            elif cat == "dmarc":
                from ingest.dmarc import parse_dmarc
                findings.extend(parse_dmarc(p))

            elif cat == "vapt_pdf":
                from ingest.vapt_pdf import parse_vapt_pdf
                findings.extend(parse_vapt_pdf(p))

            elif cat == "generic_findings":
                from ingest.findings import _load_json_findings
                findings.extend(_load_json_findings(p))

            elif cat == "questionnaire":
                # Questionnaire files are handled separately - skip here
                pass

        except Exception as e:
            print(f"[warn] Could not parse {p.name} (category={cat}): {e}")

    return findings, images, unclassified


def _parse_generic_vuln_json(path: Path) -> list[Finding]:
    """Best-effort normalizer for JSON vulnerability scanner outputs."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []

    # Common wrapper keys
    items = raw
    if isinstance(raw, dict):
        for key in ("vulnerabilities", "findings", "issues", "results", "alerts"):
            if key in raw and isinstance(raw[key], list):
                items = raw[key]
                break

    if not isinstance(items, list):
        return findings

    from models import Severity
    _SEV_MAP = {
        "critical": Severity.critical, "high": Severity.high,
        "medium": Severity.medium, "low": Severity.low,
        "info": Severity.info, "informational": Severity.info,
        "3": Severity.critical, "2": Severity.high,
        "1": Severity.medium, "0": Severity.low,
    }

    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            Finding.model_validate(item)
            findings.append(Finding.model_validate(item))
            continue
        except Exception:
            pass

        # Try to normalise common scanner fields
        title = (item.get("title") or item.get("name") or item.get("plugin_name")
                 or item.get("vulnerability_name") or item.get("check_name", "Unknown Finding"))
        raw_sev = str(item.get("severity") or item.get("risk") or item.get("risk_factor", "")).lower()
        severity = _SEV_MAP.get(raw_sev, Severity.info)
        description = (item.get("description") or item.get("desc") or item.get("synopsis", ""))
        recommendation = (item.get("recommendation") or item.get("solution")
                          or item.get("remediation") or item.get("fix", ""))
        affected = []
        for ak in ("host", "ip", "hostname", "asset", "url", "affected_host"):
            v = item.get(ak)
            if v:
                affected.append(str(v))
        cve = item.get("cve") or item.get("cve_id") or ""

        try:
            from models import Finding, Severity
            findings.append(Finding(
                title=str(title),
                severity=severity,
                description=str(description),
                recommendation=str(recommendation),
                affected_assets=affected,
                cve_id=str(cve) if cve else None,
                source="vuln_scan",
            ))
        except Exception:
            pass

    return findings


def _parse_web_app_scan(path: Path) -> list[Finding]:
    """Best-effort normalizer for web application scanner outputs (ZAP, Burp, Nikto, …)."""
    findings: list[Finding] = []
    ext = path.suffix.lower()

    if ext in (".xml", ".html", ".htm"):
        import xml.etree.ElementTree as ET
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError:
            return findings

        # OWASP ZAP: <OWASPZAPReport> → <site> → <alerts> → <alertitem>
        for alert in root.iter("alertitem"):
            title = _xml_text(alert, "alert") or _xml_text(alert, "name") or "Web App Finding"
            raw_risk = _xml_text(alert, "riskcode") or _xml_text(alert, "risk") or "1"
            severity = _risk_to_severity(raw_risk)
            desc = _xml_text(alert, "desc") or _xml_text(alert, "description") or ""
            soln = _xml_text(alert, "solution") or ""
            cweid = _xml_text(alert, "cweid") or ""
            affected = [_xml_text(inst, "uri") or "" for inst in alert.findall(".//instance")]
            affected = [a for a in affected if a]
            try:
                findings.append(Finding(
                    title=title, severity=severity, description=desc,
                    recommendation=soln, affected_assets=affected,
                    cwe_id=f"CWE-{cweid}" if cweid else None,
                    source="web_app_scan",
                ))
            except Exception:
                pass

        # Burp Suite: <issues> → <issue>
        for issue in root.iter("issue"):
            title = _xml_text(issue, "name") or "Burp Finding"
            raw_sev = _xml_text(issue, "severity") or "Information"
            severity = _named_severity(raw_sev)
            desc = _xml_text(issue, "issueBackground") or _xml_text(issue, "issueDetail") or ""
            soln = _xml_text(issue, "remediationBackground") or ""
            url = _xml_text(issue, "host") or ""
            path_val = _xml_text(issue, "path") or ""
            affected = [f"{url}{path_val}"] if url else []
            try:
                findings.append(Finding(
                    title=title, severity=severity, description=desc,
                    recommendation=soln, affected_assets=affected,
                    source="web_app_scan",
                ))
            except Exception:
                pass

    elif ext == ".json":
        findings.extend(_parse_generic_vuln_json(path))

    return findings


def _xml_text(el, tag: str) -> str | None:
    child = el.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return None


def _risk_to_severity(raw: str):
    from models import Severity
    m = {"0": Severity.info, "1": Severity.low, "2": Severity.medium,
         "3": Severity.high, "4": Severity.critical}
    return m.get(str(raw).strip(), Severity.info)


def _named_severity(raw: str):
    from models import Severity
    m = {"critical": Severity.critical, "high": Severity.high,
         "medium": Severity.medium, "low": Severity.low,
         "information": Severity.info, "informational": Severity.info, "info": Severity.info}
    return m.get(raw.lower().strip(), Severity.info)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_project(
    project_dir: str | Path,
    offline: bool = False,
) -> tuple[OrgProfile, QuestionnaireResponses, list[Finding], list[EvidenceImage], list[dict]]:
    """Load an entire CIDA project from a client assets directory.

    Returns ``(org_profile, questionnaire_responses, findings, evidence_images, unclassified_files)``.

    Raises ``FileNotFoundError`` if ``org_profile.yaml`` or questionnaire is missing.
    """
    root = Path(project_dir).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Project directory not found: {root}")

    # --- Org profile ---
    org_path = _find_file(root, "org_profile.yaml", "org_profile.yml", "org.yaml", "org.yml")
    if org_path is None:
        raise FileNotFoundError(
            f"org_profile.yaml not found in {root}. "
            "Create one using examples/sample_org_profile.yaml as a template."
        )
    org = _load_org_profile(org_path)
    print(f"[project] Org profile     : {org.name} ({org.sector} / {org.country})")

    # --- Questionnaire ---
    q_path = _find_file(root, "questionnaire.csv", "questionnaire.xlsx",
                        "responses.csv", "responses.xlsx")
    if q_path is None:
        raise FileNotFoundError(
            f"questionnaire.csv not found in {root}. "
            "Export the completed questionnaire from the SaaS platform and drop it here."
        )
    responses = _load_questionnaire(q_path, org_id=org.org_id)
    print(f"[project] Questionnaire   : {len(responses.responses)} responses from {q_path.name}")

    # --- Discover and classify all remaining files ---
    all_files = _discover_all_files(root)
    asset_files = [p for p in all_files
                   if p.name.lower() not in _PROFILE_NAMES
                   and p.name.lower() not in _QUESTIONNAIRE_NAMES]

    if asset_files:
        print(f"[project] Asset files     : {len(asset_files)} files to classify")
    else:
        print("[project] Asset files     : none -- scoring from questionnaire only")

    raw_findings, evidence_images, unclassified = _load_findings_from_paths(
        asset_files, org_email_domains=org.email_domains
    )

    print(f"[project] Raw findings    : {len(raw_findings)} loaded")
    if evidence_images:
        print(f"[project] Evidence images : {len(evidence_images)} images")
    if unclassified:
        print(f"[project] Unclassified    : {len(unclassified)} files (see diagnostics above)")

    # --- Enrich ---
    if raw_findings:
        from enrich.cve import enrich_findings
        raw_findings = enrich_findings(raw_findings, offline=offline)
        print(f"[project] Enriched        : {len(raw_findings)} findings (CVE/EPSS/KEV/CWE)")

    return org, responses, raw_findings, evidence_images, unclassified


def project_manifest(project_dir: str | Path) -> dict:
    """Return a manifest dict describing what files were found - for SaaS integration."""
    root = Path(project_dir).expanduser().resolve()
    result: dict = {
        "project_dir": str(root),
        "org_profile": None,
        "questionnaire": None,
        "asset_files": [],
        "evidence_images": [],
        "unclassified_files": [],
        "missing_required": [],
    }

    org_path = _find_file(root, "org_profile.yaml", "org_profile.yml", "org.yaml", "org.yml")
    q_path = _find_file(root, "questionnaire.csv", "questionnaire.xlsx",
                        "responses.csv", "responses.xlsx")
    result["org_profile"] = str(org_path) if org_path else None
    result["questionnaire"] = str(q_path) if q_path else None
    if not org_path:
        result["missing_required"].append("org_profile.yaml")
    if not q_path:
        result["missing_required"].append("questionnaire.csv")

    all_files = _discover_all_files(root)
    for p in all_files:
        if p.name.lower() in _PROFILE_NAMES or p.name.lower() in _QUESTIONNAIRE_NAMES:
            continue
        sniff_result = sniff(p)
        entry = {"filename": p.name, "path": str(p), "category": sniff_result.category}
        if sniff_result.category == "evidence_image":
            result["evidence_images"].append(entry)
        elif sniff_result.category == "unknown":
            entry["top_keys"] = sniff_result.top_keys
            entry["scores"] = sniff_result.scores
            result["unclassified_files"].append(entry)
        elif sniff_result.category not in ("skip",):
            result["asset_files"].append(entry)

    return result
