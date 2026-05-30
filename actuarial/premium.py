"""Premium calculation: technical premium + sub-limits + retention recommendations.

compute_premium() returns a PremiumRecommendation that is the carrier-ready
underwriting package: expected loss, risk-loaded premium, sublimits, conditions,
exclusions, regulatory flags, and the Maximum Probable Loss at the 99th percentile.
"""
from __future__ import annotations

from actuarial.model import ActuarialResult
from config.loader import fx_rate_for_currency
from models import LossDriver, PremiumRecommendation, Sector


# Sector base rates (USD per $1M revenue, indicative - refine with portfolio data)
SECTOR_BASE_RATE_PER_REV_M = {
    Sector.BANKING: 8_500,
    Sector.INSURANCE: 5_500,
    Sector.FINTECH: 9_500,
    Sector.HEALTHCARE: 7_500,
    Sector.PENSION: 4_500,
    Sector.EDUCATION: 3_500,
    Sector.TELECOM: 6_500,
    Sector.MANUFACTURING: 4_000,
    Sector.OTHER: 5_000,
}


def compute_premium(
    actuarial: ActuarialResult,
    sector: Sector,
    annual_revenue_usd: float | None,
    overall_score: float,
    posture_flags: list[str] | None = None,
    local_currency: str | None = None,
) -> PremiumRecommendation:
    """Produce a carrier-ready underwriting package.

    Args:
        actuarial: Output of run_actuarial_model().
        sector: Organisation sector enum value.
        annual_revenue_usd: Reported annual revenue (USD); defaults to $50M baseline.
        overall_score: CIDA overall risk score 0–100 (100 = worst).
        posture_flags: Optional list of compliance framework IDs with low posture
            coverage (e.g. ["ndpr_ndpa", "pci_dss_v4"]).  Used to populate
            regulatory_risk_flags and add conditions.
        local_currency: ISO-4217 currency code of the org's home country (e.g. "NGN").
            When provided, local-currency equivalents are computed using the
            indicative rate from cida/config/fx_rates.yaml and included in the output.
    """
    EL = actuarial.aggregate_expected_loss_usd
    VAR95 = actuarial.aggregate_var_95_usd
    MPL99 = actuarial.aggregate_tvar_99_usd  # Maximum Probable Loss at 99th pctile

    # Risk loading (load for variance) - proportional to (VaR - EL)
    risk_loading = max(0.0, (VAR95 - EL)) * 0.20

    # Expense load (acquisition + admin) = 25% of (EL + risk_loading)
    expense_load = (EL + risk_loading) * 0.25

    # Profit margin = 10%
    profit_margin = (EL + risk_loading + expense_load) * 0.10

    technical_premium = EL + risk_loading + expense_load + profit_margin

    # Sector base rate for comparison
    base_rate_per_m = SECTOR_BASE_RATE_PER_REV_M.get(sector, 5_000)
    revenue_m = (annual_revenue_usd or 50_000_000.0) / 1_000_000.0
    base_rate = base_rate_per_m * revenue_m
    multiplier = technical_premium / base_rate if base_rate > 0 else 1.0

    # Suggested aggregate limit: 2x EL up to a multiple of revenue, capped
    suggested_aggregate_limit = min(
        max(EL * 2.0, 500_000),
        (annual_revenue_usd or 50_000_000) * 0.10,
    )

    # Retention scales with severity median; higher-risk orgs get higher retention
    retention_base = max(actuarial.per_driver[0].severity_mean_usd * 0.10, 5_000)
    score_factor = max(0.5, (100 - overall_score) / 50.0)
    suggested_retention = round(retention_base * score_factor, -2)

    # Per-driver sub-limits (% of aggregate, proportional to each driver's EL)
    total_driver_el = sum(d.expected_annual_loss_usd for d in actuarial.per_driver) or 1.0
    sub_limits = {
        d.driver.value: round(
            suggested_aggregate_limit * (d.expected_annual_loss_usd / total_driver_el), -3
        )
        for d in actuarial.per_driver
    }

    # --- Exclusions (coverage restrictions) ---
    exclusions: list[str] = []
    if overall_score < 40:
        exclusions.append(
            "Ransomware extortion payments excluded pending MFA and EDR deployment; "
            "only system restoration costs covered."
        )
    if overall_score < 50:
        exclusions.append(
            "Social engineering / BEC sublimit capped at 20% of aggregate limit until "
            "security awareness training programme is evidenced."
        )
    if overall_score < 30:
        exclusions.append(
            "Business Interruption cover deferred for 72 hours (extended waiting period) "
            "due to critical unpatched vulnerabilities."
        )

    # --- Conditions (time-bound remediation requirements) ---
    conditions: list[str] = []
    if overall_score < 60:
        conditions.append(
            "Condition: Insured must provide evidence of MFA enforcement on all "
            "internet-facing systems within 90 days of policy inception."
        )
    if overall_score < 50:
        conditions.append(
            "Condition: Penetration test results and remediation plan to be submitted "
            "to underwriter within 120 days of policy inception."
        )
    if overall_score < 40:
        conditions.append(
            "Condition: EDR/XDR solution must be deployed on ≥90% of endpoints and "
            "evidenced within 60 days; failure to comply triggers a 25% premium surcharge."
        )
    if overall_score < 35:
        conditions.append(
            "Condition: Incident Response retainer with a named DFIR provider must be "
            "in place within 30 days of policy inception."
        )

    # --- Regulatory risk flags from compliance posture ---
    reg_flags: list[str] = []
    _REGULATORY_FLAG_LABELS: dict[str, str] = {
        "ndpr_ndpa":      "NDPR/NDPA 2023 - Nigeria data protection non-compliance detected",
        "gdpr":           "EU GDPR - data protection posture below threshold for EU data flows",
        "hipaa_security": "HIPAA Security Rule - insufficient safeguards for healthcare PHI",
        "pci_dss_v4":     "PCI-DSS v4 - card data environment controls deficient",
        "popia":          "POPIA (South Africa) - data protection posture gap identified",
    }
    for flag in (posture_flags or []):
        label = _REGULATORY_FLAG_LABELS.get(flag)
        if label:
            reg_flags.append(label)
        else:
            reg_flags.append(f"Compliance gap detected: {flag}")

    # If regulatory_penalties driver has significant EL, flag it regardless
    reg_driver = next(
        (d for d in actuarial.per_driver if d.driver.value == "regulatory_penalties"), None
    )
    if reg_driver and reg_driver.expected_annual_loss_usd > 0 and not reg_flags:
        reg_flags.append(
            "Regulatory_penalties driver has material expected loss - confirm compliance "
            "framework posture with compliance team."
        )

    # --- Local currency conversion -------------------------------------------
    # All actuarial calculations are in USD (the universal reinsurance base).
    # If the org's local currency is known, compute local-currency equivalents
    # for the carrier to write a policy in the insured's home currency.
    fx_rate: float | None = None
    if local_currency:
        fx_rate = fx_rate_for_currency(local_currency)

    def _to_local(usd: float) -> float | None:
        return round(usd * fx_rate, 2) if fx_rate else None

    return PremiumRecommendation(
        technical_premium_usd=round(technical_premium, 2),
        base_rate_usd=round(base_rate, 2),
        multiplier=round(multiplier, 3),
        risk_loading=round(risk_loading, 2),
        expense_load=round(expense_load, 2),
        profit_margin=round(profit_margin, 2),
        suggested_aggregate_limit_usd=round(suggested_aggregate_limit, -3),
        suggested_retention_usd=float(suggested_retention),
        maximum_probable_loss_usd=round(MPL99, 2),
        sub_limits=sub_limits,
        # Local currency fields
        local_currency_code=local_currency.upper() if local_currency else None,
        fx_rate_to_usd=round(fx_rate, 4) if fx_rate else None,
        technical_premium_local=_to_local(technical_premium),
        suggested_aggregate_limit_local=_to_local(round(suggested_aggregate_limit, -3)),
        suggested_retention_local=_to_local(float(suggested_retention)),
        maximum_probable_loss_local=_to_local(round(MPL99, 2)),
        # Policy terms
        exclusions_recommended=exclusions,
        conditions_recommended=conditions,
        regulatory_risk_flags=reg_flags,
    )
