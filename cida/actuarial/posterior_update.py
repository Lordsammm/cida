"""Bayesian posterior update for actuarial priors.

When real claims data accumulates, update Gamma(α, β) frequency priors via
conjugate posterior:
    α_post = α_prior + Σ events_observed
    β_post = β_prior + Σ exposure_years

Severity Lognormal(μ, σ) updates via conjugate Normal-Inverse-Gamma on the
log-losses (with known σ approximated by a precision-weighted update).

This module is the entry point for the proprietary data flywheel - each
assessment whose actual claim outcomes become known feeds back here.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from cida.config.loader import CONFIG_DIR
from cida.models import LossDriver


@dataclass
class ClaimObservation:
    """One observed claim (or zero-claim exposure period)."""
    driver: LossDriver
    exposure_years: float          # how long the org was exposed (typically 1.0)
    event_count: int               # how many events occurred in that exposure
    severities_usd: list[float]    # one entry per event; empty if event_count=0
    country: str | None = None     # ISO-2 (for stratified updates)
    sector: str | None = None


def gamma_posterior(
    alpha_prior: float,
    beta_prior: float,
    observations: Iterable[ClaimObservation],
    driver: LossDriver,
) -> tuple[float, float]:
    """Return (alpha_post, beta_post) after conjugate update."""
    total_events = 0
    total_exposure = 0.0
    for obs in observations:
        if obs.driver != driver:
            continue
        total_events += obs.event_count
        total_exposure += obs.exposure_years
    return alpha_prior + total_events, beta_prior + total_exposure


def lognormal_posterior(
    mu_prior: float,
    sigma_prior: float,
    n_prior: float,
    observations: Iterable[ClaimObservation],
    driver: LossDriver,
) -> tuple[float, float, float]:
    """Precision-weighted update for Lognormal(μ, σ) on log-severity.

    Treats μ as the parameter of interest (σ held at prior unless overwhelmingly
    contradicted). Returns (mu_post, sigma_post, n_post). n_prior is the
    pseudo-count weight of the prior (effective sample size).
    """
    log_losses: list[float] = []
    for obs in observations:
        if obs.driver != driver:
            continue
        for sev in obs.severities_usd:
            if sev > 0:
                log_losses.append(math.log(sev))
    if not log_losses:
        return mu_prior, sigma_prior, n_prior
    n_obs = len(log_losses)
    mean_obs = sum(log_losses) / n_obs
    var_obs = sum((x - mean_obs) ** 2 for x in log_losses) / max(n_obs - 1, 1)

    # Precision-weighted mean for μ
    n_post = n_prior + n_obs
    mu_post = (mu_prior * n_prior + mean_obs * n_obs) / n_post

    # Conservative σ update: weighted average of prior variance and observed variance
    sigma_post = math.sqrt((sigma_prior ** 2 * n_prior + var_obs * n_obs) / n_post)
    return mu_post, sigma_post, n_post


def update_priors_file(observations: list[ClaimObservation], out_path: Path | None = None) -> dict:
    """Apply observations to global priors and write back a new priors YAML.

    Strict: only writes if `out_path` is provided. Returns the updated prior dict
    so the caller can validate / version it before persisting.
    """
    priors_path = CONFIG_DIR / "priors" / "global.yaml"
    priors = yaml.safe_load(priors_path.read_text(encoding="utf-8"))

    for driver in LossDriver:
        # Frequency
        fp = priors["frequency_priors"].get(driver.value, {"alpha": 0.1, "beta": 1.0})
        a_post, b_post = gamma_posterior(fp["alpha"], fp["beta"], observations, driver)
        priors["frequency_priors"][driver.value] = {"alpha": a_post, "beta": b_post}

        # Severity (use n_prior=5 effective pseudo-events as default weight)
        sp = priors["severity_priors"].get(driver.value, {"mu": 10.0, "sigma": 1.3})
        mu_post, sigma_post, _ = lognormal_posterior(sp["mu"], sp["sigma"], 5.0, observations, driver)
        priors["severity_priors"][driver.value] = {"mu": mu_post, "sigma": sigma_post}

    priors.setdefault("source_notes", []).append(
        f"Posterior update applied: {len(observations)} observations"
    )

    if out_path is not None:
        out_path.write_text(yaml.safe_dump(priors, sort_keys=False), encoding="utf-8")

    return priors
