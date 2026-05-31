"""Tests for ml/peer_store.py peer benchmarking."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from catalog.loader import load_catalog
from ml.peer_store import PeerStore, PeerComparison, _ACCUMULATED_PATH, _normal_cdf
from models import ControlResponse, OrgProfile, QuestionnaireResponses, Sector
from scoring.engine import score_organization


def _responses(score: float = 60.0) -> QuestionnaireResponses:
    catalog = load_catalog()
    return QuestionnaireResponses(
        org_id="PEER-TEST", submitted_at=datetime.now(tz=timezone.utc),
        responses=[ControlResponse(control_id=c.control_id, raw_answer="yes", score=score)
                   for c in catalog.controls],
    )


def _scoring(score: float = 60.0):
    resp = _responses(score)
    return score_organization(resp, [])


def test_normal_cdf_midpoint():
    assert abs(_normal_cdf(0.0) - 0.5) < 0.01


def test_normal_cdf_extreme_high():
    assert _normal_cdf(6.0) > 0.99


def test_normal_cdf_extreme_low():
    assert _normal_cdf(-6.0) < 0.01


def test_get_percentiles_returns_comparison():
    store = PeerStore()
    scoring = _scoring(60.0)
    result = store.get_percentiles("banking", "NG", scoring)
    assert isinstance(result, PeerComparison)
    assert 0.0 <= result.overall_score_percentile <= 100.0
    assert result.sector == "banking"
    assert result.region == "west_africa"


def test_percentile_above_50_for_high_scorer():
    store = PeerStore()
    scoring = _scoring(90.0)  # well above typical mean of 52
    result = store.get_percentiles("banking", "NG", scoring)
    assert result.overall_score_percentile > 50.0


def test_percentile_below_50_for_low_scorer():
    store = PeerStore()
    scoring = _scoring(30.0)  # below typical mean
    result = store.get_percentiles("banking", "NG", scoring)
    assert result.overall_score_percentile < 50.0


def test_domain_percentiles_present():
    store = PeerStore()
    scoring = _scoring(60.0)
    result = store.get_percentiles("banking", "NG", scoring)
    assert len(result.domain_percentiles) > 0
    for pct in result.domain_percentiles.values():
        assert 0.0 <= pct <= 100.0


def test_unknown_country_uses_fallback():
    store = PeerStore()
    scoring = _scoring(60.0)
    result = store.get_percentiles("other", "XX", scoring)
    assert isinstance(result, PeerComparison)
    assert result.overall_score_percentile >= 0.0


def test_to_dict_serialisable():
    import json
    store = PeerStore()
    scoring = _scoring(60.0)
    result = store.get_percentiles("banking", "NG", scoring)
    d = result.to_dict()
    json.dumps(d)  # must not raise
    assert "overall_score_percentile" in d
    assert "data_source" in d


def test_record_creates_accumulated_file(tmp_path, monkeypatch):
    """Recording should update or create the accumulated JSON file."""
    acc_path = tmp_path / "peer_accumulated.json"
    monkeypatch.setattr("ml.peer_store._ACCUMULATED_PATH", acc_path)
    store = PeerStore()
    scoring = _scoring(65.0)
    store.record("banking", "NG", scoring)
    assert acc_path.exists()
    data = json.loads(acc_path.read_text())
    assert "banking:west_africa" in data
    assert data["banking:west_africa"]["n_orgs"] == 1
