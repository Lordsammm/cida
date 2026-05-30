"""Bayesian actuarial model - frequency (Poisson with Gamma prior) ×
severity (Lognormal) × Monte Carlo aggregate loss per driver.

Calibration:
  λ_driver = (alpha_prior / beta_prior)
              × sector_multiplier
              × country_multiplier
              × disclosure_correction
              × Π (control_modifiers)            # control failures uplift frequency
  E[severity]_driver scales with revenue^elasticity, with sector multipliers.

Uncertainty: we draw λ from Gamma posterior (data-free → uses prior directly),
severities from Lognormal, run N simulations, summarize EL, VaR95, TVaR99.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
from scipy import stats

from cida.catalog.loader import load_catalog
from cida.config.loader import load_country, load_priors, load_sector, load_vector_matrix
from cida.enrich.intel import IntelImpact, derive_intel_impact
from cida.models import (
    CompanyIntelSnapshot,
    Control,
    ControlResponse,
    Finding,
    LossDriver,
    LossDriverEstimate,
    OrgProfile,
    QuestionnaireResponses,
    Sector,
    ThreatVector,
    VectorScore,
)
from cida.scoring.vectors import (
    peer_baseline_multiplier_for_driver,
    score_threat_vectors,
    vector_multiplier_for_driver,
)

DEFAULT_BASELINE_REVENUE_USD = 50_000_000.0  # priors calibrated to a ~$50M org
N_SIMULATIONS = 10_000


@dataclass
class ActuarialResult:
    per_driver: list[LossDriverEstimate]
    aggregate_expected_loss_usd: float
    aggregate_var_95_usd: float
    aggregate_tvar_99_usd: float
    # Aggregate (composite across drivers) annual loss percentiles.
    aggregate_loss_p50_usd: float = 0.0
    aggregate_loss_p90_usd: float = 0.0
    aggregate_loss_p99_usd: float = 0.0
    # Average per-driver vector-derived frequency multiplier (org vs neutral).
    avg_control_modifier: float = 1.0
    # Average per-driver multiplier for a peer at baseline vector scores.
    avg_peer_baseline_multiplier: float = 1.0
    # Per-vector underwriting scores (passed through from scoring layer).
    vector_scores: list[VectorScore] = None
    # driver -> [(vector, per_vector_mult, vector_score)]; for explainability
    vector_contributions_per_driver: dict = None
    inputs_used: dict = None  # populated in run_actuarial_model


def _control_modifier_for(
    driver: LossDriver,
    responses: QuestionnaireResponses,
    controls: list[Control],
    cap: float = 4.0,
) -> float:
    """Aggregate per-driver control modifier as a damped geometric combination.

    For each control influencing this driver, the per-control factor is
        f_i = 1 + deficiency_i * (modifier_i - 1)
    where deficiency_i = 1 - score_i/100.

    Pure multiplicative stacking explodes when many controls map to the same
    driver. Instead, we combine in log-space and apply a hard cap:
        total = min(exp(sum(log(f_i))), cap)
    Cap defaults to 4.0× (i.e. worst case = 4× baseline frequency from controls).
    """
    log_sum = 0.0
    import math
    for c in controls:
        if driver not in c.loss_driver_modifiers:
            continue
        r = responses.get(c.control_id)
        score = r.score if r else 30.0
        deficiency = 1.0 - (score / 100.0)
        mod = c.loss_driver_modifiers[driver]
        factor = max(1.0 + deficiency * (mod - 1.0), 0.01)
        log_sum += math.log(factor)
    total = math.exp(log_sum)
    return min(total, cap)


def _severity_size_scale(revenue_usd: float | None, elasticity: float) -> float:
    rev = revenue_usd or DEFAULT_BASELINE_REVENUE_USD
    return max(0.1, (rev / DEFAULT_BASELINE_REVENUE_USD) ** elasticity)


def run_actuarial_model(
    org: OrgProfile,
    responses: QuestionnaireResponses,
    seed: int = 42,
    findings: list[Finding] | None = None,
    vector_scores: list[VectorScore] | None = None,
    intel: CompanyIntelSnapshot | None = None,
) -> ActuarialResult:
    catalog = load_catalog()
    priors = load_priors()
    sector_cfg = load_sector(org.sector.value if hasattr(org.sector, "value") else org.sector)
    try:
        country_cfg = load_country(org.country)
    except FileNotFoundError:
        country_cfg = None

    matrix_cfg = load_vector_matrix()
    if vector_scores is None:
        vector_scores = score_threat_vectors(responses, findings or [], catalog)

    # Per-assessment public intel: lift specific vector scores and apply
    # multiplicative bumps to selected drivers (e.g. recent breach mention ->
    # privacy_liability x1.5). All multipliers cap inside vector_multiplier_for_driver.
    intel_impact = derive_intel_impact(intel)
    if intel_impact.vector_score_uplift:
        adjusted: list[VectorScore] = []
        for vs in vector_scores:
            bump = intel_impact.vector_score_uplift.get(vs.vector.value, 0.0)
            if bump > 0:
                new_score = min(100.0, vs.score_0_100 + bump)
                adjusted.append(vs.model_copy(update={"score_0_100": new_score}))
            else:
                adjusted.append(vs)
        vector_scores = adjusted

    rng = np.random.default_rng(seed)
    aggregate_losses = np.zeros(N_SIMULATIONS)
    per_driver_estimates: list[LossDriverEstimate] = []
    driver_ctrl_mults: list[float] = []
    driver_peer_mults: list[float] = []
    vector_contribs_per_driver: dict[str, list] = {}

    sector_freq = priors.sector_frequency_multipliers.get(
        Sector(org.sector) if not isinstance(org.sector, Sector) else org.sector, {}
    )

    size_scale = _severity_size_scale(org.annual_revenue_usd, priors.size_severity_elasticity)
    # Disclosure correction inflates frequency to account for under-reporting.
    # Cap at 2.0x in the actuarial path so it doesn't compound explosively with
    # sector + country + control multipliers; the full per-country factor
    # remains available for posterior updates in posterior_update.py.
    raw_disclosure = country_cfg.disclosure_correction_factor if country_cfg else 1.0
    disclosure_corr = min(raw_disclosure, 2.0)

    inputs_used = {
        "sector_freq_multipliers": dict(sector_freq),
        "country": country_cfg.iso_a2 if country_cfg else None,
        "disclosure_correction": disclosure_corr,
        "size_scale": size_scale,
        "n_simulations": N_SIMULATIONS,
        "intel_driver_multipliers": dict(intel_impact.driver_multipliers),
        "intel_vector_uplifts": dict(intel_impact.vector_score_uplift),
        "intel_signals": list(intel_impact.signals),
    }

    for driver in LossDriver:
        # --- frequency ---
        fp = priors.frequency_priors.get(driver, {"alpha": 0.1, "beta": 1.0})
        alpha, beta = fp["alpha"], fp["beta"]
        # Apply sector + country + vector-derived multipliers
        sector_mult = sector_freq.get(driver, 1.0)
        country_mult = country_cfg.base_frequency_multipliers.get(driver, 1.0) if country_cfg else 1.0
        # Africa overlay applied to alpha at load time already
        ctrl_mult, vec_contribs = vector_multiplier_for_driver(driver, vector_scores, matrix_cfg)
        peer_mult = peer_baseline_multiplier_for_driver(driver, matrix_cfg)
        # Per-assessment public intel multiplier (capped to keep behaviour bounded).
        intel_mult = min(2.5, intel_impact.driver_multipliers.get(driver.value, 1.0))
        driver_ctrl_mults.append(ctrl_mult)
        driver_peer_mults.append(peer_mult)
        vector_contribs_per_driver[driver.value] = [
            {"vector": v.value, "per_vector_mult": m, "vector_score": s}
            for (v, m, s) in vec_contribs
        ]
        # adjust prior mean: lambda_eff = (alpha/beta) * multipliers
        lambda_mean = (alpha / beta) * sector_mult * country_mult * ctrl_mult * intel_mult
        # apply disclosure correction (true rate higher than observed)
        lambda_mean *= disclosure_corr

        # Draw uncertainty in lambda via Gamma posterior (no data → use prior shape with adjusted mean)
        # Use Gamma(alpha_eff, beta_eff) with mean = lambda_mean and CV approximated.
        # CV of Gamma = 1/sqrt(alpha). Keep alpha_eff = alpha (preserve uncertainty), beta_eff = alpha/lambda_mean.
        if lambda_mean <= 0:
            lambda_mean = 1e-6
        beta_eff = alpha / lambda_mean
        lambda_samples = stats.gamma.rvs(a=alpha, scale=1.0 / beta_eff, size=N_SIMULATIONS, random_state=rng)
        # Annual event count for each simulation
        counts = stats.poisson.rvs(mu=lambda_samples, random_state=rng)

        # --- severity ---
        sp = priors.severity_priors.get(driver, {"mu": 10.0, "sigma": 1.3})
        mu, sigma = sp["mu"], sp["sigma"]
        sev_size_mult = size_scale
        sector_sev_mult = sector_cfg.severity_multipliers.get(driver, 1.0)
        # adjusted mu = log(median * size_scale * sector_mult)
        adj_mu = mu + np.log(max(sev_size_mult * sector_sev_mult, 1e-9))

        # For each simulation, sum severity over count events
        losses = np.zeros(N_SIMULATIONS)
        # Vectorize: sample max(counts) per sim then sum
        max_count = int(counts.max()) if counts.size else 0
        if max_count > 0:
            # draw a [N_SIMULATIONS, max_count] grid; mask by per-row count
            grid = stats.lognorm.rvs(s=sigma, scale=np.exp(adj_mu),
                                     size=(N_SIMULATIONS, max_count), random_state=rng)
            mask = np.arange(max_count)[None, :] < counts[:, None]
            losses = (grid * mask).sum(axis=1)

        aggregate_losses += losses

        # Per-driver stats
        sev_samples = stats.lognorm.rvs(s=sigma, scale=np.exp(adj_mu), size=N_SIMULATIONS, random_state=rng)
        per_driver_estimates.append(LossDriverEstimate(
            driver=driver,
            annual_frequency_mean=float(np.mean(lambda_samples)),
            annual_frequency_ci_low=float(np.quantile(lambda_samples, 0.05)),
            annual_frequency_ci_high=float(np.quantile(lambda_samples, 0.95)),
            severity_mean_usd=float(np.mean(sev_samples)),
            severity_p95_usd=float(np.quantile(sev_samples, 0.95)),
            severity_p99_usd=float(np.quantile(sev_samples, 0.99)),
            expected_annual_loss_usd=float(np.mean(losses)),
            var_95_usd=float(np.quantile(losses, 0.95)),
            tvar_99_usd=float(losses[losses >= np.quantile(losses, 0.99)].mean()
                              if (losses >= np.quantile(losses, 0.99)).any() else np.quantile(losses, 0.99)),
            aggregate_loss_p50_usd=float(np.quantile(losses, 0.50)),
            aggregate_loss_p90_usd=float(np.quantile(losses, 0.90)),
            aggregate_loss_p99_usd=float(np.quantile(losses, 0.99)),
        ))

    avg_ctrl = float(np.mean(driver_ctrl_mults)) if driver_ctrl_mults else 1.0
    avg_peer = float(np.mean(driver_peer_mults)) if driver_peer_mults else 1.0

    return ActuarialResult(
        per_driver=per_driver_estimates,
        aggregate_expected_loss_usd=float(np.mean(aggregate_losses)),
        aggregate_var_95_usd=float(np.quantile(aggregate_losses, 0.95)),
        aggregate_tvar_99_usd=float(aggregate_losses[aggregate_losses >= np.quantile(aggregate_losses, 0.99)].mean()
                                    if (aggregate_losses >= np.quantile(aggregate_losses, 0.99)).any()
                                    else np.quantile(aggregate_losses, 0.99)),
        aggregate_loss_p50_usd=float(np.quantile(aggregate_losses, 0.50)),
        aggregate_loss_p90_usd=float(np.quantile(aggregate_losses, 0.90)),
        aggregate_loss_p99_usd=float(np.quantile(aggregate_losses, 0.99)),
        avg_control_modifier=avg_ctrl,
        avg_peer_baseline_multiplier=avg_peer,
        vector_scores=vector_scores,
        vector_contributions_per_driver=vector_contribs_per_driver,
        inputs_used=inputs_used,
    )
