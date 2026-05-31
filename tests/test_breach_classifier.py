"""Tests for ml/breach_classifier.py."""
import math
from datetime import datetime, timezone

import pytest

from actuarial.model import run_actuarial_model
from catalog.loader import load_catalog
from ml.breach_classifier import BreachProbabilities, compute_breach_probabilities, _poisson_p12m
from models import ControlResponse, LossDriver, OrgProfile, QuestionnaireResponses, Sector


def _make_org_and_responses(sector=Sector.BANKING, country="NG"):
    org = OrgProfile(
        org_id="BP-TEST", name="Test Org", sector=sector, country=country,
        employees=300, annual_revenue_usd=30_000_000, data_sensitivity="high",
    )
    catalog = load_catalog()
    responses = QuestionnaireResponses(
        org_id="BP-TEST", submitted_at=datetime.now(tz=timezone.utc),
        responses=[ControlResponse(control_id=c.control_id, raw_answer="yes", score=60.0)
                   for c in catalog.controls],
    )
    return org, responses


def test_poisson_p12m_zero_rate():
    assert _poisson_p12m(0.0) == 0.0


def test_poisson_p12m_unit_rate():
    p = _poisson_p12m(1.0)
    assert abs(p - (1 - math.exp(-1))) < 1e-9


def test_poisson_p12m_approaches_one_for_high_rate():
    p = _poisson_p12m(100.0)
    assert p > 0.99   # 1 - exp(-100) is effectively 1.0


def test_compute_breach_probabilities_returns_correct_type():
    org, responses = _make_org_and_responses()
    actuarial = run_actuarial_model(org, responses, seed=42)
    from scoring.engine import score_organization
    scoring = score_organization(responses, [])
    result = compute_breach_probabilities(actuarial, scoring, sector=Sector.BANKING)
    assert isinstance(result, BreachProbabilities)


def test_all_probabilities_in_range():
    org, responses = _make_org_and_responses()
    actuarial = run_actuarial_model(org, responses, seed=42)
    from scoring.engine import score_organization
    scoring = score_organization(responses, [])
    bp = compute_breach_probabilities(actuarial, scoring, sector=Sector.BANKING)
    for field_val in [bp.overall_p12m, bp.ransomware_p12m, bp.phishing_bec_p12m,
                      bp.data_breach_p12m, bp.funds_fraud_p12m, bp.peer_baseline_p12m]:
        assert 0.0 <= field_val <= 1.0


def test_overall_p_is_highest():
    org, responses = _make_org_and_responses()
    actuarial = run_actuarial_model(org, responses, seed=42)
    from scoring.engine import score_organization
    scoring = score_organization(responses, [])
    bp = compute_breach_probabilities(actuarial, scoring, sector=Sector.BANKING)
    assert bp.overall_p12m >= bp.ransomware_p12m
    assert bp.overall_p12m >= bp.data_breach_p12m


def test_to_dict_serialisable():
    org, responses = _make_org_and_responses()
    actuarial = run_actuarial_model(org, responses, seed=42)
    from scoring.engine import score_organization
    scoring = score_organization(responses, [])
    bp = compute_breach_probabilities(actuarial, scoring, sector=Sector.BANKING)
    d = bp.to_dict()
    import json
    json.dumps(d)  # must not raise
    assert "overall_p12m" in d
    assert "calibration_source" in d


def test_above_peer_baseline_flag():
    org, responses = _make_org_and_responses()
    actuarial = run_actuarial_model(org, responses, seed=42)
    from scoring.engine import score_organization
    scoring = score_organization(responses, [])
    bp = compute_breach_probabilities(actuarial, scoring, sector=Sector.BANKING)
    assert isinstance(bp.above_peer_baseline, bool)
    assert bp.above_peer_baseline == (bp.overall_p12m > bp.peer_baseline_p12m)
