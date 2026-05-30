"""Unit tests for actuarial pipeline."""
import math
from datetime import datetime, timezone

import pytest

from cida.actuarial.model import run_actuarial_model, _control_modifier_for
from cida.actuarial.posterior_update import (
    ClaimObservation,
    gamma_posterior,
    lognormal_posterior,
)
from cida.catalog.loader import load_catalog
from cida.models import ControlResponse, LossDriver, OrgProfile, QuestionnaireResponses, Sector


def _org():
    return OrgProfile(
        org_id="T", name="T Co", sector=Sector.INSURANCE, country="NG",
        employees=500, annual_revenue_usd=50_000_000, data_sensitivity="high",
    )


def _responses(score):
    catalog = load_catalog()
    return QuestionnaireResponses(
        org_id="T", submitted_at=datetime.now(tz=timezone.utc),
        responses=[ControlResponse(control_id=c.control_id, raw_answer="yes", score=score)
                   for c in catalog.controls],
    )


def test_var_ge_el():
    result = run_actuarial_model(_org(), _responses(70.0), seed=42)
    assert result.aggregate_var_95_usd >= result.aggregate_expected_loss_usd
    assert result.aggregate_tvar_99_usd >= result.aggregate_var_95_usd * 0.5  # tail


def test_seven_drivers():
    result = run_actuarial_model(_org(), _responses(70.0), seed=42)
    assert len(result.per_driver) == 10
    drivers = {d.driver for d in result.per_driver}
    assert drivers == set(LossDriver)


def test_higher_score_lower_loss():
    """A better-scored org should have lower EL than a worse-scored org."""
    good = run_actuarial_model(_org(), _responses(95.0), seed=42)
    bad = run_actuarial_model(_org(), _responses(20.0), seed=42)
    assert bad.aggregate_expected_loss_usd > good.aggregate_expected_loss_usd


def test_control_modifier_cap():
    """Modifier must never exceed configured cap."""
    catalog = load_catalog()
    bad_responses = _responses(0.0)
    for driver in LossDriver:
        mod = _control_modifier_for(driver, bad_responses, catalog.controls, cap=4.0)
        assert 0 <= mod <= 4.0


def test_gamma_posterior_simple():
    a_post, b_post = gamma_posterior(
        alpha_prior=0.5, beta_prior=1.0,
        observations=[
            ClaimObservation(driver=LossDriver.SOCIAL_ENGINEERING, exposure_years=1, event_count=2, severities_usd=[50000, 80000]),
            ClaimObservation(driver=LossDriver.SOCIAL_ENGINEERING, exposure_years=1, event_count=0, severities_usd=[]),
        ],
        driver=LossDriver.SOCIAL_ENGINEERING,
    )
    assert a_post == 2.5
    assert b_post == 3.0


def test_lognormal_posterior_pulls_toward_data():
    mu_post, sigma_post, n_post = lognormal_posterior(
        mu_prior=10.0, sigma_prior=1.0, n_prior=5.0,
        observations=[
            ClaimObservation(driver=LossDriver.SOCIAL_ENGINEERING, exposure_years=1, event_count=3,
                             severities_usd=[math.exp(12), math.exp(12), math.exp(12)]),
        ],
        driver=LossDriver.SOCIAL_ENGINEERING,
    )
    # mu_post should move toward 12 (observed) from 10 (prior)
    assert 10.5 < mu_post < 12
    assert n_post == 8
