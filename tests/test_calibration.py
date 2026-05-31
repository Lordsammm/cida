"""Tests for enrich/calibration.py score calibration against dark web evidence."""
from datetime import datetime, timezone

import pytest

from catalog.loader import load_catalog
from enrich.calibration import CalibrationResult, CalibrationFlag, calibrate_score
from models import (
    ControlResponse, Domain, Finding, OrgProfile, QuestionnaireResponses,
    Sector, Severity,
)
from scoring.engine import score_organization


def _make_org(email_domains=None):
    return OrgProfile(
        org_id="CAL-TEST", name="Test Org", sector=Sector.BANKING, country="NG",
        employees=200, annual_revenue_usd=20_000_000, data_sensitivity="high",
        email_domains=email_domains or ["testorg.com"],
    )


def _responses(iam_score: float = 85.0) -> QuestionnaireResponses:
    catalog = load_catalog()
    responses = []
    for c in catalog.controls:
        score = iam_score if c.domain.value == "identity" else 60.0
        responses.append(ControlResponse(control_id=c.control_id, raw_answer="yes", score=score))
    return QuestionnaireResponses(
        org_id="CAL-TEST", submitted_at=datetime.now(tz=timezone.utc), responses=responses,
    )


def _scoring(resp):
    return score_organization(resp, [])


def test_no_flags_when_no_credential_findings():
    org = _make_org()
    resp = _responses(iam_score=85.0)
    scoring = _scoring(resp)
    result = calibrate_score(scoring, [], org)
    assert isinstance(result, CalibrationResult)
    assert result.score_ci_adjustment == 0.0
    assert len(result.flags) == 0


def test_identity_inconsistency_flag():
    org = _make_org()
    resp = _responses(iam_score=85.0)
    scoring = _scoring(resp)
    findings = [
        Finding(source="darkweb_spycloud", asset="user@testorg.com",
                title="Credential found in breach", severity=Severity.HIGH,
                domain=Domain.IDENTITY, exposure="unknown"),
    ]
    result = calibrate_score(scoring, findings, org)
    types = [f.flag_type for f in result.flags]
    assert "IDENTITY_INCONSISTENCY" in types
    assert result.score_ci_adjustment > 0


def test_plaintext_credential_flag():
    org = _make_org()
    resp = _responses(iam_score=50.0)
    scoring = _scoring(resp)
    findings = [
        Finding(source="darkweb_spycloud", asset="admin@testorg.com",
                title="Plaintext password exposed", severity=Severity.CRITICAL,
                domain=Domain.IDENTITY, exposure="unknown"),
    ]
    result = calibrate_score(scoring, findings, org)
    types = [f.flag_type for f in result.flags]
    assert "ACTIVE_PLAINTEXT_EXPOSURE" in types


def test_stealer_log_flag_for_matching_domain():
    org = _make_org(email_domains=["testorg.com"])
    resp = _responses(iam_score=70.0)
    scoring = _scoring(resp)
    findings = [
        Finding(source="darkweb_stealer_redline", asset="testorg.com",
                title="Stealer log dump", severity=Severity.CRITICAL,
                domain=Domain.ENDPOINT, exposure="unknown"),
    ]
    result = calibrate_score(scoring, findings, org)
    types = [f.flag_type for f in result.flags]
    assert "ACTIVE_STEALER_EXPOSURE" in types


def test_ci_widens_with_inconsistency():
    org = _make_org()
    resp = _responses(iam_score=85.0)
    scoring = _scoring(resp)
    original_range = scoring.overall_score_ci_high - scoring.overall_score_ci_low
    findings = [
        Finding(source="darkweb_hibp", asset="staff@testorg.com",
                title="Account in breach", severity=Severity.HIGH,
                domain=Domain.IDENTITY, exposure="unknown"),
    ]
    result = calibrate_score(scoring, findings, org)
    adjusted_range = result.adjusted_ci_high - result.adjusted_ci_low
    assert adjusted_range >= original_range


def test_ci_values_within_bounds():
    org = _make_org()
    resp = _responses(iam_score=85.0)
    scoring = _scoring(resp)
    findings = [
        Finding(source="darkweb_hibp", asset="staff@testorg.com",
                title="Credential breach", severity=Severity.CRITICAL,
                domain=Domain.IDENTITY, exposure="unknown"),
        Finding(source="darkweb_stealer_raccoon", asset="testorg.com",
                title="Stealer log", severity=Severity.CRITICAL,
                domain=Domain.ENDPOINT, exposure="unknown"),
    ]
    result = calibrate_score(scoring, findings, org)
    assert result.adjusted_ci_low >= 0.0
    assert result.adjusted_ci_high <= 100.0


def test_to_dict_serialisable():
    import json
    org = _make_org()
    resp = _responses(iam_score=85.0)
    scoring = _scoring(resp)
    findings = [
        Finding(source="darkweb_spycloud", asset="admin@testorg.com",
                title="Credential breach", severity=Severity.HIGH,
                domain=Domain.IDENTITY, exposure="unknown"),
    ]
    result = calibrate_score(scoring, findings, org)
    d = result.to_dict()
    json.dumps(d)  # must not raise
    assert "flags" in d
    assert "score_ci_adjustment" in d
