from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape
import zipfile

from ingest.cida_docx import ingest_cida_docx, parse_cida_docx


def _write_minimal_docx(path: Path, paragraphs: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        f"<w:p><w:r><w:t>{escape(p)}</w:t></w:r></w:p>" for p in paragraphs
    )
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body>"
        "</w:document>"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", document_xml)


def _sample_paragraphs() -> list[str]:
    return [
        "DEVELOPED FOR",
        "Acme Insurance Plc",
        "Industry: Insurance",
        "Date of Assessment: 2026-01-10 Revenue: $12M",
        "Email Security",
        "DMARC",
        "PASSED",
        "SPF",
        "PASSED",
        "Compromised Email Addresses - CRITICAL",
        "analyst@acme.com",
        "soc@acme.com",
        "In the course of OSINT analysis, two addresses were observed.",
        "Recommendation: rotate credentials",
        "Web Application Security",
        "Admin portal exposed - HIGH",
        "Impacted Assets",
        "https://portal.acme.com/login",
        "Recommendation: restrict access",
        "Vulnerabilities",
        "Missing Strict-Transport-Security Header",
        "The Strict-Transport-Security response header is missing, "
        "allowing potential SSL stripping or downgrade attacks against users LOW RISK",
        "Non-compliance with NDPR - HIGH",
    ]


def test_parse_cida_docx_extracts_core_fields(tmp_path: Path) -> None:
    docx_path = tmp_path / "sample.docx"
    _write_minimal_docx(docx_path, _sample_paragraphs())

    parsed = parse_cida_docx(docx_path)

    assert parsed.org_name == "Acme Insurance Plc"
    assert parsed.industry == "Insurance"
    assert parsed.assessment_date == "2026-01-10"
    assert parsed.revenue_raw == "$12M"
    assert parsed.declared["dmarc"] == "PASSED"
    assert parsed.declared["spf"] == "PASSED"
    assert parsed.declared["ndpr"] == "NON_COMPLIANT"
    assert parsed.compromised_emails == ["analyst@acme.com", "soc@acme.com"]

    titles = [f.title for f in parsed.findings]
    assert "Compromised email addresses found on dark-web breach dumps" in titles
    assert "Admin portal exposed" in titles
    assert "Missing Strict-Transport-Security Header" in titles


def test_ingest_cida_docx_builds_pipeline_inputs(tmp_path: Path) -> None:
    docx_path = tmp_path / "sample.docx"
    _write_minimal_docx(docx_path, _sample_paragraphs())

    org, questionnaire, findings, parsed = ingest_cida_docx(docx_path, country="NG")

    assert org.name == "Acme Insurance Plc"
    assert org.sector.value == "insurance"
    assert org.country == "NG"
    assert parsed.compromised_emails == ["analyst@acme.com", "soc@acme.com"]
    assert len(questionnaire.responses) > 0
    assert len(findings) >= 3

    by_source = {f.source for f in findings}
    assert "darkweb_credentials" in by_source
    assert "cida_docx" in by_source

    resp_by_id = {r.control_id: r for r in questionnaire.responses}
    assert resp_by_id["IAM-001"].raw_answer == "no"
    assert resp_by_id["IAM-002"].raw_answer == "no"
    assert resp_by_id["GOV-001"].raw_answer == "no"