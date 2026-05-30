"""Generic findings loader - content-based routing via sniffer, with filename fallback.

The sniffer classifies files by probing their internal structure (field names,
XML root elements, CSV headers) rather than by filename.  Filename-based
heuristics are only used as a final fallback for unrecognised extensions.
"""
from __future__ import annotations

import json
from pathlib import Path

from models import Finding


def load_findings_from_dir(
    directory: str | Path,
    org_email_domains: list[str] | None = None,
) -> list[Finding]:
    """Load all findings from files in *directory* using content-based detection.

    Files are classified by the sniffer (data shape, not filename).  Unknown
    files are reported to stdout with diagnostic info and skipped.
    """
    from ingest.sniffer import sniff, format_unknown_diagnostic
    from ingest.project import (
        _parse_generic_vuln_json, _parse_web_app_scan,
        _PROFILE_NAMES, _QUESTIONNAIRE_NAMES,
    )

    directory = Path(directory)
    if not directory.exists():
        return []
    org_email_domains = org_email_domains or []
    out: list[Finding] = []

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name in _PROFILE_NAMES or name in _QUESTIONNAIRE_NAMES:
            continue

        result = sniff(path)
        cat = result.category

        if cat in ("skip", "evidence_image", "vapt_pdf", "questionnaire"):
            # vapt_pdf requires the caller to invoke the PDF parser explicitly
            continue

        if cat == "unknown":
            print(format_unknown_diagnostic(path, result))
            continue

        try:
            if cat == "cspm_aws":
                from ingest.cspm_aws import parse_aws_cspm
                out.extend(parse_aws_cspm(path))

            elif cat == "cspm_azure":
                from ingest.cspm_azure import parse_azure_cspm
                out.extend(parse_azure_cspm(path))

            elif cat == "cspm_gcp":
                from ingest.cspm_gcp import parse_gcp_cspm
                out.extend(parse_gcp_cspm(path))

            elif cat in ("vuln_scan", "network_scan"):
                if path.suffix.lower() in (".xml", ".nessus", ".csv"):
                    from ingest.nessus import parse_nessus
                    out.extend(parse_nessus(path))
                else:
                    out.extend(_parse_generic_vuln_json(path))

            elif cat == "web_app_scan":
                out.extend(_parse_web_app_scan(path))

            elif cat == "attack_surface":
                from ingest.attack_surface import parse_attack_surface
                out.extend(parse_attack_surface(path))

            elif cat == "darkweb":
                from ingest.darkweb import parse_darkweb
                out.extend(parse_darkweb(path, org_email_domains=org_email_domains))

            elif cat == "dmarc":
                from ingest.dmarc import parse_dmarc
                out.extend(parse_dmarc(path))

            elif cat == "generic_findings":
                out.extend(_load_json_findings(path))

        except Exception as exc:
            print(f"[warn] Failed to parse {path.name} (category={cat}): {exc}")

    return out


_JSON_LIST_KEYS = {"findings", "vulnerabilities", "issues", "results", "alerts",
                   "checks", "data", "items"}


def _load_json_findings(path: Path) -> list[Finding]:
    """Load a pre-normalised CIDA Finding[] JSON (bare list or wrapped dict)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        for k in _JSON_LIST_KEYS:
            if k in data and isinstance(data[k], list):
                data = data[k]
                break
    if not isinstance(data, list):
        return []
    out: list[Finding] = []
    for d in data:
        try:
            out.append(Finding.model_validate(d))
        except Exception:
            pass
    return out
