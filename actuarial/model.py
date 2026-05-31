"""Bayesian actuarial model - frequency (Poisson with Gamma prior) ×
severity (Lognormal) × Monte Carlo aggregate loss per driver.

Calibration:
  λ_driver = (alpha_prior / beta_prior)
              × sector_multiplier
              × country_multiplier
              × vector_control_modifier
              × intel_multiplier
              × disclosure_correction_driver      # per-driver observability-weighted
  E[severity]_driver scales with revenue^elasticity_driver × sector_sev_mult.

Correlation: loss driver frequencies are drawn via a Gaussian copula
  (correlation matrix from config/priors/global.yaml) rather than
  independently, correctly capturing "single event, multiple coverage lines"
  structure. If the matrix is absent, falls back to independent draws.

Disclosure: the Africa under-reporting correction is applied per-driver
  proportional to how unobservable that event type is in African markets,
  replacing the previous hard cap of 2.0× across all drivers.

Severity elasticity: per-driver revenue^elasticity replaces the legacy
  single scalar, reflecting that ransomware and BI scale more steeply with
  organisation size than BEC or FTF.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
from scipy import stats
from scipy.linalg import cholesky, LinAlgError

from catalog.loader import load_catalog
from config.loader import load_country, load_priors, load_sector, load_vector_matrix
from enrich.intel import IntelImpact, derive_intel_impact
from models import (
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
from scoring.vectors import (
    peer_baseline_multiplier_for_driver,
    score_threat_vectors,
    vector_multiplier_for_driver,
)

DEFAULT_BASELINE_REVENUE_USD = 50_000_000.0  # priors calibrated to a ~$50M org
N_SIMULATIONS = 10_000


def _nearest_pd(matrix: np.ndarray) -> np.ndarray:
    """Return the nearest positive-definite matrix via eigenvalue thresholding."""
    eigvals, eigvecs = np.linalg.eigh(matrix)
    eigvals = np.maximum(eigvals, 1e-8)
    pd = eigvecs @ np.diag(eigvals) @ eigvecs.T
    # Re-normalise to a correlation matrix (diagonal = 1).
    d = np.sqrt(np.diag(pd))
    return pd / np.outer(d, d)


def _draw_correlated_lambdas(
    lambda_params: list[tuple[float, float]],
    correlation: np.ndarray,
    rng: np.random.Generator,
    n_sims: int,
) -> np.ndarray:
    """Draw correlated Gamma frequency samples via the Iman-Conover method.

    This achieves a Gaussian copula dependence structure without calling
    scipy.stats.gamma.ppf, which is prohibitively slow for shape parameters
    alpha < 0.1 (e.g. network_sec_liability alpha=0.02, pci_fines alpha=0.03).

    Algorithm:
      1. Draw independent Gamma samples per driver using numpy (always fast).
      2. Draw correlated standard normals via Cholesky of the correlation matrix.
      3. Reorder each driver's Gamma samples to match the rank order of the
         corresponding correlated normal column.

    The result has the correct marginal distribution for each driver and an
    approximate Gaussian copula dependence structure matching the correlation
    matrix. The Iman-Conover method is exact in expectation and standard
    practice in actuarial simulation (Vose, 2008; Wang, 1998).

    Returns: array of shape (n_drivers, n_sims).
    """
    n = len(lambda_params)

    # Step 1: independent Gamma draws per driver — numpy gamma is always fast.
    raw = np.zeros((n_sims, n))
    for i, (alpha, scale) in enumerate(lambda_params):
        raw[:, i] = rng.gamma(shape=alpha, scale=scale, size=n_sims)

    # Step 2: correlated standard normals via Cholesky decomposition.
    try:
        L = cholesky(correlation, lower=True)
    except LinAlgError:
        L = cholesky(_nearest_pd(correlation), lower=True)
    Z_corr = rng.standard_normal((n_sims, n)) @ L.T  # (n_sims, n_drivers)

    # Step 3: rank-based reordering (Iman-Conover).
    # For each driver i, sort the raw Gamma samples then place them in the
    # order dictated by the rank of the i-th correlated normal column.
    normal_ranks = np.argsort(np.argsort(Z_corr, axis=0), axis=0)  # (n_sims, n)
    result = np.zeros((n_sims, n))
    for i in range(n):
        sorted_raw = np.sort(raw[:, i])           # ascending sorted Gammas
        result[:, i] = sorted_raw[normal_ranks[:, i]]  # reorder by corr-normal rank

    return result.T  # (n_drivers, n_sims)


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


def _driver_disclosure(
    raw_factor: float,
    driver: LossDriver,
    observability_map: dict,
) -> float:
    """Return the effective disclosure correction for one driver.

    Replaces the previous hard cap of 2.0×. Instead, the correction scales
    with how unobservable the event type is in African markets:

        effective = 1 + (raw_factor - 1) × (1 - observability)

    observability ∈ [0, 1]:
      1.0 → event always surfaces (regulatory penalties, third-party litigation)
          → correction = 1.0 (no adjustment needed)
      0.0 → event is completely hidden (suppressed fraud, silent breaches)
          → correction = raw_factor (full adjustment)
    """
    obs = observability_map.get(driver, 0.5)
    return 1.0 + (raw_factor - 1.0) * (1.0 - obs)


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
    per_driver_estimates: list[LossDriverEstimate] = []
    driver_ctrl_mults: list[float] = []
    driver_peer_mults: list[float] = []
    vector_contribs_per_driver: dict[str, list] = {}

    sector_freq = priors.sector_frequency_multipliers.get(
        Sector(org.sector) if not isinstance(org.sector, Sector) else org.sector, {}
    )

    raw_disclosure = country_cfg.disclosure_correction_factor if country_cfg else 1.0
    observability_map = priors.disclosure_observability  # dict[LossDriver, float]

    inputs_used = {
        "sector_freq_multipliers": dict(sector_freq),
        "country": country_cfg.iso_a2 if country_cfg else None,
        "raw_disclosure_factor": raw_disclosure,
        "n_simulations": N_SIMULATIONS,
        "copula_active": priors.driver_correlation is not None,
        "intel_driver_multipliers": dict(intel_impact.driver_multipliers),
        "intel_vector_uplifts": dict(intel_impact.vector_score_uplift),
        "intel_signals": list(intel_impact.signals),
    }

    # ------------------------------------------------------------------ #
    # Pass 1: compute per-driver lambda_mean and Gamma scale parameters.  #
    # ------------------------------------------------------------------ #
    drivers_list = list(LossDriver)
    lambda_params: list[tuple[float, float]] = []   # (alpha, scale=lambda_mean/alpha)
    driver_metadata: list[dict] = []

    for driver in drivers_list:
        fp = priors.frequency_priors.get(driver, {"alpha": 0.1, "beta": 1.0})
        alpha, beta = fp["alpha"], fp["beta"]

        sector_mult  = sector_freq.get(driver, 1.0)
        country_mult = (country_cfg.base_frequency_multipliers.get(driver, 1.0)
                        if country_cfg else 1.0)
        ctrl_mult, vec_contribs = vector_multiplier_for_driver(driver, vector_scores, matrix_cfg)
        peer_mult    = peer_baseline_multiplier_for_driver(driver, matrix_cfg)
        intel_mult   = min(2.5, intel_impact.driver_multipliers.get(driver.value, 1.0))

        driver_ctrl_mults.append(ctrl_mult)
        driver_peer_mults.append(peer_mult)
        vector_contribs_per_driver[driver.value] = [
            {"vector": v.value, "per_vector_mult": m, "vector_score": s}
            for (v, m, s) in vec_contribs
        ]

        lambda_mean = (alpha / beta) * sector_mult * country_mult * ctrl_mult * intel_mult

        # Per-driver disclosure correction (replaces previous hard 2.0× cap).
        disc_corr = _driver_disclosure(raw_disclosure, driver, observability_map)
        lambda_mean *= disc_corr
        lambda_mean = max(lambda_mean, 1e-6)

        # Gamma(alpha, scale=lambda_mean/alpha): mean=lambda_mean, CV=1/√alpha.
        scale = lambda_mean / alpha
        lambda_params.append((alpha, scale))

        sp = priors.severity_priors.get(driver, {"mu": 10.0, "sigma": 1.3})
        # Per-driver severity elasticity; fall back to global scalar.
        elasticity = (priors.severity_elasticities.get(driver)
                      or priors.size_severity_elasticity)
        size_scale = _severity_size_scale(org.annual_revenue_usd, elasticity)
        sector_sev_mult = sector_cfg.severity_multipliers.get(driver, 1.0)

        driver_metadata.append({
            "alpha": alpha,
            "scale": scale,
            "sp_mu": sp["mu"],
            "sp_sigma": sp["sigma"],
            "size_scale": size_scale,
            "sector_sev_mult": sector_sev_mult,
            "disc_corr": disc_corr,
            "lambda_mean": lambda_mean,
        })

    # ------------------------------------------------------------------ #
    # Pass 2: draw correlated lambda samples via Gaussian copula.         #
    # ------------------------------------------------------------------ #
    if priors.driver_correlation is not None:
        corr_matrix = np.array(priors.driver_correlation, dtype=float)
        lambda_matrix = _draw_correlated_lambdas(lambda_params, corr_matrix, rng, N_SIMULATIONS)
    else:
        # Legacy: independent draws (fallback when matrix is absent).
        lambda_matrix = np.zeros((len(drivers_list), N_SIMULATIONS))
        for i, (alpha, scale) in enumerate(lambda_params):
            lambda_matrix[i] = stats.gamma.rvs(a=alpha, scale=scale,
                                               size=N_SIMULATIONS, random_state=rng)

    # ------------------------------------------------------------------ #
    # Pass 3: compute per-driver losses using the correlated lambda draws.#
    # ------------------------------------------------------------------ #
    aggregate_losses = np.zeros(N_SIMULATIONS)

    for i, driver in enumerate(drivers_list):
        meta = driver_metadata[i]
        lambda_samples = lambda_matrix[i]  # (N_SIMULATIONS,)

        counts = stats.poisson.rvs(mu=lambda_samples, random_state=rng)

        adj_mu = meta["sp_mu"] + np.log(
            max(meta["size_scale"] * meta["sector_sev_mult"], 1e-9)
        )
        sigma = meta["sp_sigma"]

        losses = np.zeros(N_SIMULATIONS)
        max_count = int(counts.max()) if counts.size else 0
        if max_count > 0:
            grid = stats.lognorm.rvs(s=sigma, scale=np.exp(adj_mu),
                                     size=(N_SIMULATIONS, max_count), random_state=rng)
            mask = np.arange(max_count)[None, :] < counts[:, None]
            losses = (grid * mask).sum(axis=1)

        aggregate_losses += losses

        sev_samples = stats.lognorm.rvs(s=sigma, scale=np.exp(adj_mu),
                                        size=N_SIMULATIONS, random_state=rng)
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
                              if (losses >= np.quantile(losses, 0.99)).any()
                              else np.quantile(losses, 0.99)),
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
