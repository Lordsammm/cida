"""End-to-end smoke test for the CIDA pipeline."""
from __future__ import annotations

from pathlib import Path

import pytest

from actuarial.model import run_actuarial_model
from ingest.findings import load_findings_from_dir
from ingest.questionnaire import parse_questionnaire_csv
from models import OrgProfile
from report.renderer import build_report, render_json, render_html, render_policyholder_html
from scoring.engine import score_organization

import yaml

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_smoke_end_to_end(tmp_path: Path) -> None:
    org = OrgProfile.model_validate(
        yaml.safe_load((EXAMPLES / "sample_org_profile.yaml").read_text(encoding="utf-8"))
    )
    responses = parse_questionnaire_csv(EXAMPLES / "sample_questionnaire.csv", org_id=org.org_id)
    assert len(responses.responses) >= 30, f"Expected ≥30 parsed responses, got {len(responses.responses)}"

    findings = load_findings_from_dir(EXAMPLES / "sample_findings")
    assert len(findings) >= 5

    scoring = score_organization(responses, findings)
    assert 0.0 <= scoring.overall_score <= 100.0
    assert 1 <= scoring.tier.tier <= 5
    assert len(scoring.domain_scores) == 10

    actuarial = run_actuarial_model(org, responses, seed=42)
    assert actuarial.aggregate_expected_loss_usd > 0
    assert actuarial.aggregate_var_95_usd >= actuarial.aggregate_expected_loss_usd
    assert len(actuarial.per_driver) == 10

    report = build_report(org, responses, scoring, actuarial)
    assert report.tier.tier == scoring.tier.tier
    assert report.aggregate_expected_loss_usd > 0

    json_path = render_json(report, tmp_path / "report.json")
    assert json_path.exists() and json_path.stat().st_size > 0

    html = render_html(report)
    assert "<html" in html.lower() and report.org.name in html

    print(f"\n  Overall score: {scoring.overall_score}  (Tier {scoring.tier.tier} – {scoring.tier.label})")
    print(f"  Aggregate EL: ${actuarial.aggregate_expected_loss_usd:,.0f}")
    print(f"  VaR95:        ${actuarial.aggregate_var_95_usd:,.0f}")
    print(f"  Premium:      ${report.premium.technical_premium_usd:,.0f}")


def test_policyholder_report_renders(tmp_path: Path) -> None:
    """Policyholder Report renders without error and contains key sections."""
    org = OrgProfile.model_validate(
        yaml.safe_load((EXAMPLES / "sample_org_profile.yaml").read_text(encoding="utf-8"))
    )
    responses = parse_questionnaire_csv(EXAMPLES / "sample_questionnaire.csv", org_id=org.org_id)
    findings = load_findings_from_dir(EXAMPLES / "sample_findings")
    scoring = score_organization(responses, findings)
    actuarial = run_actuarial_model(org, responses, seed=42)
    report = build_report(org, responses, scoring, actuarial, findings=findings)

    html = render_policyholder_html(report, findings=findings)

    assert "<html" in html.lower()
    assert org.name in html
    # Key Policyholder Report sections must be present
    assert "Risk Summary" in html
    assert "Email Security" in html
    assert "Vulnerabilities" in html
    assert "Cyber Insurance" in html
