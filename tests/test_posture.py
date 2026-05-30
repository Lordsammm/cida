"""Unit tests for posture & remediation."""
from datetime import datetime, timezone

from catalog.loader import load_catalog
from config.loader import context_for
from models import ControlResponse, QuestionnaireResponses, Sector
from posture.compliance import build_remediation_roadmap, compute_posture


def _responses(score):
    catalog = load_catalog()
    return QuestionnaireResponses(
        org_id="T", submitted_at=datetime.now(tz=timezone.utc),
        responses=[ControlResponse(control_id=c.control_id, raw_answer="yes", score=score)
                   for c in catalog.controls],
    )


def test_perfect_score_full_coverage():
    posture = compute_posture(_responses(100.0), Sector.INSURANCE, context_for("NG"))
    assert posture
    for p in posture:
        assert p.coverage_pct == 100.0


def test_failing_org_has_gaps():
    posture = compute_posture(_responses(30.0), Sector.INSURANCE, context_for("NG"))
    assert posture
    for p in posture:
        assert p.coverage_pct < 100.0


def test_remediation_rank_monotonic():
    items = build_remediation_roadmap(_responses(40.0), {})
    assert items
    ranks = [r.priority_rank for r in items]
    assert ranks == sorted(ranks)
