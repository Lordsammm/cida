"""Tests for ml/anomaly.py questionnaire anomaly detection."""
from datetime import datetime, timezone

import pytest

from catalog.loader import load_catalog
from ml.anomaly import AnomalyFlag, detect_anomalies, _MIN_CONTROLS_ANSWERED
from models import (
    ControlResponse, Domain, Finding, OrgProfile, QuestionnaireResponses,
    Sector, Severity,
)
from scoring.engine import score_organization


def _responses(score: float = 60.0, count: int | None = None) -> QuestionnaireResponses:
    catalog = load_catalog()
    controls = catalog.controls[:count] if count else catalog.controls
    return QuestionnaireResponses(
        org_id="ANOM-TEST", submitted_at=datetime.now(tz=timezone.utc),
        responses=[ControlResponse(control_id=c.control_id, raw_answer="yes", score=score)
                   for c in controls],
    )


def _scoring(responses, findings=None):
    return score_organization(responses, findings or [])


def test_no_flags_for_typical_org():
    resp = _responses(score=60.0)
    scoring = _scoring(resp)
    flags = detect_anomalies(resp, [], scoring)
    assert isinstance(flags, list)
    # A typical average-scoring org should produce few or no flags
    critical_flags = [f for f in flags if f.severity == "high"]
    assert len(critical_flags) == 0


def test_perfect_attestation_flagged():
    resp = _responses(score=100.0)
    scoring = _scoring(resp)
    flags = detect_anomalies(resp, [], scoring)
    types = [f.flag_type for f in flags]
    assert "PERFECT_ATTESTATION" in types


def test_identity_inconsistency_flagged():
    # High identity score but critical identity findings
    resp = _responses(score=90.0)
    scoring = _scoring(resp)
    findings = [
        Finding(source="nessus", asset="auth-server", title="Privileged auth bypass",
                severity=Severity.CRITICAL, domain=Domain.IDENTITY, exposure="internet"),
    ]
    flags = detect_anomalies(resp, findings, scoring)
    types = [f.flag_type for f in flags]
    assert "IDENTITY_INCONSISTENCY" in types


def test_incomplete_questionnaire_flagged():
    resp = _responses(count=10)  # only 10 of 41 answered
    scoring = _scoring(resp)
    flags = detect_anomalies(resp, [], scoring)
    types = [f.flag_type for f in flags]
    assert "INCOMPLETE_QUESTIONNAIRE" in types


def test_flag_has_required_fields():
    resp = _responses(score=100.0)
    scoring = _scoring(resp)
    flags = detect_anomalies(resp, [], scoring)
    for flag in flags:
        assert isinstance(flag, AnomalyFlag)
        assert flag.flag_type
        assert flag.description
        assert flag.severity in ("high", "medium", "low")
        assert flag.recommendation


def test_sector_outlier_flagged_for_banking():
    resp = _responses(score=100.0)
    scoring = _scoring(resp)
    flags = detect_anomalies(resp, [], scoring, sector="banking")
    types = [f.flag_type for f in flags]
    assert "SECTOR_OUTLIER" in types


def test_flags_are_serialisable():
    import json
    resp = _responses(score=100.0)
    scoring = _scoring(resp)
    flags = detect_anomalies(resp, [], scoring)
    for flag in flags:
        json.dumps(flag.to_dict())  # must not raise
