"""Tests for per-assessment public-intelligence wiring.

These tests use canned snapshots returned by stub `IntelSource`s so they
run fully offline and deterministically - no live HTTP.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from actuarial.model import run_actuarial_model
from enrich.intel import gather_company_intel, derive_intel_impact
from enrich.intel.base import IntelSource
from ingest.questionnaire import parse_questionnaire_csv
from models import CompanyIntelSnapshot, OrgProfile
from scoring.engine import score_organization
from scoring.risk_summary import build_risk_summary

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _org() -> OrgProfile:
    return OrgProfile.model_validate(
        yaml.safe_load((EXAMPLES / "sample_org_profile.yaml").read_text(encoding="utf-8"))
    )


class _StubSource(IntelSource):
    """Test IntelSource that returns a canned snapshot."""

    def __init__(self, name: str, snap: CompanyIntelSnapshot):
        self.name = name
        self._snap = snap

    def fetch(self, org_name: str, country: str | None = None) -> CompanyIntelSnapshot:
        return self._snap


def _make_snap(source: str, *, headlines: list[dict] | None = None) -> CompanyIntelSnapshot:
    return CompanyIntelSnapshot(
        org_name="Sample Insurance Nigeria Plc",
        source=source,
        fetched_at=datetime.now(tz=timezone.utc),
        recent_news=headlines or [],
    )


def test_offline_short_circuit_returns_empty_snapshot():
    snap = gather_company_intel(_org(), offline=True)
    assert snap.recent_news == []
    assert snap.breach_mentions == []
    assert snap.regulatory_actions == []


def test_gather_merges_and_classifies_headlines():
    proshare = _StubSource("proshare", _make_snap("proshare", headlines=[
        {"title": "Sample Insurance hit by ransomware attack", "url": "https://p/1"},
        {"title": "Sample Insurance fined by NDPC over data breach", "url": "https://p/2"},
        {"title": "Sample Insurance appoints new CISO", "url": "https://p/3"},
    ]))
    bd = _StubSource("businessday_intelligence", _make_snap("businessday_intelligence", headlines=[
        {"title": "Sample Insurance Q3 results beat estimates", "url": "https://b/1"},
        {"title": "Sample Insurance hit by ransomware attack", "url": "https://p/1"},  # dup
        {"title": "Wire fraud at Sample Insurance branch", "url": "https://b/2"},
    ]))

    merged = gather_company_intel(_org(), sources=[proshare, bd])

    assert len(merged.recent_news) == 5  # dup removed
    assert any("breach" in (a["tags"] or []) for a in merged.recent_news)
    assert len(merged.breach_mentions) >= 2  # ransomware + ndpc breach (+ wire fraud counted as fraud)
    assert len(merged.regulatory_actions) >= 1
    assert len(merged.executive_changes) >= 1


def test_derive_intel_impact_lifts_privacy_and_regulatory():
    snap = CompanyIntelSnapshot(
        org_name="Test Co",
        source="merged",
        fetched_at=datetime.now(tz=timezone.utc),
        breach_mentions=[{"title": "ransomware", "tags": ["breach"]}],
        regulatory_actions=[{"title": "fined", "tags": ["regulatory"]}],
    )
    impact = derive_intel_impact(snap)
    assert impact.driver_multipliers.get("privacy_liability", 1.0) > 1.0
    assert impact.driver_multipliers.get("regulatory_penalties", 1.0) > 1.0
    assert any("breach mention" in s for s in impact.signals)


def test_actuarial_intel_lifts_privacy_liability_lambda():
    org = _org()
    responses = parse_questionnaire_csv(EXAMPLES / "sample_questionnaire.csv", org_id=org.org_id)

    baseline = run_actuarial_model(org, responses, seed=42)
    intel = CompanyIntelSnapshot(
        org_name=org.name,
        source="merged",
        fetched_at=datetime.now(tz=timezone.utc),
        breach_mentions=[{"title": "ransomware A"}, {"title": "data breach B"}],
        regulatory_actions=[{"title": "fined by regulator"}],
    )
    lifted = run_actuarial_model(org, responses, seed=42, intel=intel)

    baseline_priv = next(d for d in baseline.per_driver if d.driver.value == "privacy_liability")
    lifted_priv = next(d for d in lifted.per_driver if d.driver.value == "privacy_liability")
    assert lifted_priv.annual_frequency_mean > baseline_priv.annual_frequency_mean

    baseline_reg = next(d for d in baseline.per_driver if d.driver.value == "regulatory_penalties")
    lifted_reg = next(d for d in lifted.per_driver if d.driver.value == "regulatory_penalties")
    assert lifted_reg.annual_frequency_mean > baseline_reg.annual_frequency_mean

    assert lifted.inputs_used.get("intel_signals")  # non-empty list
    assert lifted.inputs_used["intel_driver_multipliers"].get("privacy_liability", 1.0) > 1.0


def test_risk_summary_surfaces_intel_signals():
    org = _org()
    responses = parse_questionnaire_csv(EXAMPLES / "sample_questionnaire.csv", org_id=org.org_id)
    scoring = score_organization(responses, [])
    intel = CompanyIntelSnapshot(
        org_name=org.name,
        source="merged",
        fetched_at=datetime.now(tz=timezone.utc),
        breach_mentions=[{"title": "ransomware A", "url": "u/1", "tags": ["breach"]}],
        regulatory_actions=[{"title": "fined", "url": "u/2", "tags": ["regulatory"]}],
    )
    actuarial = run_actuarial_model(org, responses, seed=42, intel=intel)
    rs = build_risk_summary(org, scoring, actuarial, [], intel=intel)

    names = {p.name for p in rs.posture_signals}
    assert "Recent Adverse Media" in names
    assert "Regulator Action" in names
    adverse = next(p for p in rs.posture_signals if p.name == "Recent Adverse Media")
    assert adverse.status == "AT_RISK"
    assert adverse.count >= 1

    assert rs.public_intel
    assert rs.public_intel["counts"]["breach_mentions"] >= 1
    assert rs.intel_fetched_at is not None
