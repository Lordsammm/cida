"""Unit tests for scoring engine."""
from datetime import datetime, timezone

import pytest

from cida.catalog.loader import load_catalog
from cida.models import ControlResponse, QuestionnaireResponses
from cida.scoring.engine import score_organization, _tier_for, TIER_BANDS


def _make_responses(score_per_control: float) -> QuestionnaireResponses:
    catalog = load_catalog()
    return QuestionnaireResponses(
        org_id="TEST",
        submitted_at=datetime.now(tz=timezone.utc),
        responses=[
            ControlResponse(control_id=c.control_id, raw_answer="yes", score=score_per_control)
            for c in catalog.controls
        ],
    )


def test_perfect_score_is_tier_1():
    r = _make_responses(100.0)
    res = score_organization(r, findings=[])
    assert res.overall_score >= 95
    assert res.tier.tier == 1


def test_zero_score_is_tier_5():
    r = _make_responses(0.0)
    res = score_organization(r, findings=[])
    # Geometric mean uses score=1.0 floor → very low but not 0
    assert res.overall_score <= 5
    assert res.tier.tier == 5


def test_mid_score_lands_tier_3():
    r = _make_responses(60.0)
    res = score_organization(r, findings=[])
    assert 50 <= res.overall_score <= 70
    assert res.tier.tier in (2, 3)


def test_tier_thresholds():
    assert _tier_for(90).tier == 1
    assert _tier_for(85).tier == 1
    assert _tier_for(84.9).tier == 2
    assert _tier_for(70).tier == 2
    assert _tier_for(60).tier == 3
    assert _tier_for(45).tier == 4
    assert _tier_for(20).tier == 5


def test_domain_count_constant():
    r = _make_responses(50.0)
    res = score_organization(r, findings=[])
    assert len(res.domain_scores) == 10
    for d in res.domain_scores:
        assert 0 <= d.score <= 100
