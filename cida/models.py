"""Single source of truth for all CIDA data shapes.

Enums, org profile, questionnaire responses, findings, scoring outputs,
actuarial estimates, premium recommendation, and config models.
All pipeline modules import from here.
"""
from __future__ import annotations

from datetime import datetime, date
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, ConfigDict, field_validator


# ---------- Enums ----------

class Domain(str, Enum):
    GOVERNANCE = "governance"
    IDENTITY = "identity"
    ASSET_DATA = "asset_data"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPSEC = "appsec"
    CLOUD = "cloud"
    THIRD_PARTY = "third_party"
    DETECT_RESPOND = "detect_respond"
    RESILIENCE = "resilience"


class LossDriver(str, Enum):
    """Insurance coverage lines (what the carrier actually pays out for).

    Aligned with industry standard cyber-insurance policy schedules
    (Coalition, Beazley, AIG CyberEdge, Munich Re cyber wording).
    Threat actors (DDoS, insider, third-party, mobile-money) are NOT loss
    drivers - they are ThreatVectors that *lift* the frequency of one or
    more coverage lines below.
    """
    # ---- First-party ----
    CYBER_EXTORTION       = "cyber_extortion"        # ransom + negotiator
    BUSINESS_INTERRUPTION = "business_interruption"  # revenue loss from downtime (any cause)
    DATA_RECOVERY         = "data_recovery"          # forensics + rebuild + IR
    FUNDS_TRANSFER_FRAUD  = "funds_transfer_fraud"   # system-based wire/ACH fraud
    SOCIAL_ENGINEERING    = "social_engineering"     # BEC / invoice / impersonation
    COMPUTER_FRAUD        = "computer_fraud"         # theft via direct system compromise (USSD, switch, API)
    # ---- Third-party ----
    PRIVACY_LIABILITY     = "privacy_liability"      # notification + civil claims for data breach
    NETWORK_SEC_LIABILITY = "network_sec_liability"  # passing malware, taking down 3rd parties
    REGULATORY_PENALTIES  = "regulatory_penalties"   # NDPR / POPIA / GDPR / CBN fines
    PCI_FINES             = "pci_fines"              # card-brand penalties


# Legacy → new alias map. Applied at YAML load time so existing sector /
# country / catalog files continue to validate. New configs should use the
# canonical values above directly.
LEGACY_LOSS_DRIVER_ALIASES: dict[str, str] = {
    "bec":                "social_engineering",
    "ransomware":         "cyber_extortion",       # extortion component; BI/recovery seeded separately
    "data_breach":        "privacy_liability",
    "ddos":               "business_interruption", # DDoS is a *cause* of BI
    "insider":            "privacy_liability",     # most common claim type is data theft
    "third_party":        "privacy_liability",     # supply-chain breach -> privacy
    "mobile_money_fraud": "computer_fraud",
}


class ThreatVector(str, Enum):
    """Technical areas an attacker can exploit. Each vector is scored 0-100
    (high = worse) from a blend of findings + control responses, then
    multiplied through `vector_matrix.yaml` to lift loss-driver frequencies.
    """
    EXTERNAL_NETWORK_EXPOSURE   = "external_network_exposure"
    UNPATCHED_VULNERABILITIES   = "unpatched_vulnerabilities"
    WEB_APPLICATION_WEAKNESSES  = "web_application_weaknesses"
    EMAIL_HYGIENE               = "email_hygiene"
    IDENTITY_AND_ACCESS         = "identity_and_access"
    ENDPOINT_SECURITY           = "endpoint_security"
    CLOUD_MISCONFIGURATION      = "cloud_misconfiguration"
    DATA_PROTECTION             = "data_protection"
    THIRD_PARTY_SUPPLY_CHAIN    = "third_party_supply_chain"
    DETECTION_AND_RESPONSE      = "detection_and_response"
    CREDENTIAL_SECRETS_EXPOSURE = "credential_secrets_exposure"
    DDOS_RESILIENCE             = "ddos_resilience"
    INSIDER_RISK                = "insider_risk"
    MOBILE_AGENT_NETWORK        = "mobile_agent_network"


class Confidence(str, Enum):
    HIGH = "high"      # scored mostly from hard telemetry (CVE scans, CSPM, dark web)
    MEDIUM = "medium"  # mixed: telemetry + self-attestation
    LOW = "low"        # questionnaire / self-attestation only


class Sector(str, Enum):
    BANKING = "banking"
    INSURANCE = "insurance"
    FINTECH = "fintech"
    PENSION = "pension"
    EDUCATION = "education"
    HEALTHCARE = "healthcare"
    TELECOM = "telecom"
    MANUFACTURING = "manufacturing"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------- Control catalog ----------

class FrameworkCrosswalk(BaseModel):
    nist_csf_2_0: list[str] = Field(default_factory=list)
    nist_sp_800_53_r5: list[str] = Field(default_factory=list)
    iso_27001_2022: list[str] = Field(default_factory=list)
    cis_v8: list[str] = Field(default_factory=list)
    soc2_tsc: list[str] = Field(default_factory=list)
    pci_dss_v4: list[str] = Field(default_factory=list)
    hipaa_security: list[str] = Field(default_factory=list)
    gdpr: list[str] = Field(default_factory=list)
    ndpr_ndpa: list[str] = Field(default_factory=list)
    ccpa: list[str] = Field(default_factory=list)
    popia: list[str] = Field(default_factory=list)
    malabo: list[str] = Field(default_factory=list)
    fsca_js1_2023: list[str] = Field(default_factory=list)


class Control(BaseModel):
    """One question / control in the master catalog."""
    control_id: str
    domain: Domain
    question_text: str
    response_type: Literal["yes_no", "scale_1_5", "multi_select", "evidence"] = "yes_no"
    options: list[str] | None = None
    weight: float = 1.0  # weight within domain
    # which loss drivers this control influences, and by what frequency multiplier
    # when the control is FAILED (score 0). value = multiplier on lambda.
    # e.g. {"bec": 2.0} means missing this control doubles BEC frequency.
    loss_driver_modifiers: dict[LossDriver, float] = Field(default_factory=dict)
    # OPTIONAL: which threat vectors this control contributes evidence to.
    # When non-empty, the control's score also flows into vector scoring.
    threat_vectors: list[ThreatVector] = Field(default_factory=list)
    sectors: list[Sector] | None = None  # None = applies to all sectors
    crosswalk: FrameworkCrosswalk = Field(default_factory=FrameworkCrosswalk)
    guidance: str | None = None


class ControlCatalog(BaseModel):
    version: str
    controls: list[Control]

    def by_domain(self, domain: Domain) -> list[Control]:
        return [c for c in self.controls if c.domain == domain]

    def by_id(self, cid: str) -> Control | None:
        return next((c for c in self.controls if c.control_id == cid), None)


# ---------- Org profile ----------

class OrgProfile(BaseModel):
    org_id: str
    name: str
    sector: Sector
    country: str  # ISO-3166 alpha-2
    employees: int
    annual_revenue_usd: float | None = None
    annual_revenue_local: float | None = None
    local_currency: str | None = None
    data_sensitivity: Literal["low", "medium", "high", "very_high"] = "medium"
    regulated_data_types: list[str] = Field(default_factory=list)  # PCI, PHI, PII, ...
    public_facing_assets: int = 0
    websites: list[str] = Field(default_factory=list)
    email_domains: list[str] = Field(default_factory=list)


# ---------- Responses ----------

class ControlResponse(BaseModel):
    control_id: str
    raw_answer: str | int | bool | list[str]
    score: float  # normalized 0-100 (computed at ingest time)
    evidence_ref: str | None = None
    notes: str | None = None


class QuestionnaireResponses(BaseModel):
    org_id: str
    submitted_at: datetime
    responses: list[ControlResponse]

    def get(self, cid: str) -> ControlResponse | None:
        return next((r for r in self.responses if r.control_id == cid), None)


# ---------- Technical findings ----------

class Finding(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    source: str  # "nessus", "burp", "prowler", "shodan", "vapt_pdf", ...
    asset: str = ""  # primary asset - IP, domain, URL, cloud_resource_arn, etc.
    title: str
    severity: Severity
    domain: Domain = Domain.NETWORK  # which CIDA domain this finding rolls up into
    description: str = ""           # vulnerability description (client-facing)
    recommendation: str = ""        # remediation recommendation (client-facing)
    affected_assets: list[str] = Field(default_factory=list)  # all affected assets
    cve_id: str | None = None
    cwe_id: str | None = None          # primary CWE (backward-compat single value)
    cwe_ids: list[str] = Field(default_factory=list)  # all CWEs from NVD (may be >1)
    owasp_category: str | None = None  # e.g. "A03:2021 Injection"
    cvss_v3: float | None = None
    cvss_severity: Severity | None = None
    epss_score: float | None = None
    kev_listed: bool = False
    exposure: Literal["internet", "internal", "unknown"] = "unknown"
    asset_criticality: Literal["low", "medium", "high", "crown_jewel"] = "medium"
    evidence: str | None = None
    raw: dict = Field(default_factory=dict)


# ---------- External intel ----------

class CompanyIntelSnapshot(BaseModel):
    org_name: str
    source: str  # "proshare", "businessday", "hibp", ...
    fetched_at: datetime
    financials: dict = Field(default_factory=dict)
    recent_news: list[dict] = Field(default_factory=list)
    breach_mentions: list[dict] = Field(default_factory=list)
    executive_changes: list[dict] = Field(default_factory=list)
    regulatory_actions: list[dict] = Field(default_factory=list)


# ---------- Scoring outputs ----------

class DomainScore(BaseModel):
    domain: Domain
    score: float  # 0-100
    n_controls: int
    n_passed: int  # score >= 70
    weight: float
    technical_penalty: float = 0.0  # 0-100 penalty from findings in this domain
    top_gaps: list[str] = Field(default_factory=list)  # control_ids of biggest gaps


class TierAssignment(BaseModel):
    tier: int  # 1-5
    label: str
    description: str


class LossDriverEstimate(BaseModel):
    driver: LossDriver
    annual_frequency_mean: float
    annual_frequency_ci_low: float   # 5th percentile
    annual_frequency_ci_high: float  # 95th percentile
    severity_mean_usd: float
    severity_p95_usd: float
    severity_p99_usd: float
    expected_annual_loss_usd: float
    var_95_usd: float
    tvar_99_usd: float
    # Percentiles of the annual aggregate loss distribution for this driver
    # (median / 1-in-10-yr / 1-in-100-yr loss). 0.0 if no losses simulated.
    aggregate_loss_p50_usd: float = 0.0
    aggregate_loss_p90_usd: float = 0.0
    aggregate_loss_p99_usd: float = 0.0


class PremiumRecommendation(BaseModel):
    # ── USD figures (actuarial base - all calculations done in USD) ──────────
    technical_premium_usd: float
    base_rate_usd: float
    multiplier: float
    risk_loading: float
    expense_load: float
    profit_margin: float
    suggested_aggregate_limit_usd: float
    suggested_retention_usd: float
    maximum_probable_loss_usd: float = 0.0   # P99 aggregate loss (1-in-100-yr)
    sub_limits: dict[str, float] = Field(default_factory=dict)
    # ── Local currency figures (for carrier policy writing + client display) ─
    # None when the country's FX rate is unavailable.
    local_currency_code: str | None = None       # ISO-4217 code, e.g. "NGN"
    fx_rate_to_usd: float | None = None          # 1 USD = this many local units
    technical_premium_local: float | None = None
    suggested_aggregate_limit_local: float | None = None
    suggested_retention_local: float | None = None
    maximum_probable_loss_local: float | None = None
    # ── Policy terms ─────────────────────────────────────────────────────────
    exclusions_recommended: list[str] = Field(default_factory=list)
    conditions_recommended: list[str] = Field(default_factory=list)  # time-bound remediation conditions
    regulatory_risk_flags: list[str] = Field(default_factory=list)   # compliance gaps that drive regulatory_penalties driver


class FrameworkPosture(BaseModel):
    framework: str
    coverage_pct: float
    controls_aligned: int
    controls_total: int
    top_gaps: list[str] = Field(default_factory=list)


class RemediationItem(BaseModel):
    control_id: str
    title: str
    domain: Domain
    score_uplift_potential: float  # estimated points added to overall score
    annual_loss_reduction_usd: float
    effort: Literal["low", "medium", "high"]
    priority_rank: int
    framework_citations: list[str] = Field(default_factory=list)


class PostureSignal(BaseModel):
    """A single binary/scored posture indicator (DMARC, SPF, Malware, Data Leaks, ...).

    `status`: one of SECURE, AT_RISK, NOT_AVAILABLE, NOT_ENABLED.
    `count`: optional count (e.g., number of leaked credentials).
    `detail`: optional human-readable detail string.
    """
    name: str
    status: Literal["SECURE", "AT_RISK", "NOT_AVAILABLE", "NOT_ENABLED"]
    count: int = 0
    detail: str = ""


class VectorScore(BaseModel):
    """Per-threat-vector underwriting score with provenance.

    `score_0_100`: 0 = best (no exposure), 100 = worst (saturated exposure).
    `confidence`: HIGH (hard telemetry), MEDIUM (mixed), LOW (questionnaire only).
    `n_findings`: number of technical findings backing the score.
    `n_controls`: number of control responses contributing.
    `contributing_drivers`: which loss drivers this vector lifts at the
        org's current score (derived from the vector x driver matrix).
    """
    vector: ThreatVector
    score_0_100: float
    confidence: Confidence
    n_findings: int = 0
    n_controls: int = 0
    top_evidence: list[str] = Field(default_factory=list)        # finding titles / control IDs
    contributing_drivers: list[LossDriver] = Field(default_factory=list)


class LikelihoodDriver(BaseModel):
    """A single contributor to the org's likelihood multiplier vs peer.

    Surfaced in the report's "Drivers of Likelihood" section.
    """
    vector: ThreatVector
    contribution_pts: float      # signed; positive = lifts risk above peer
    confidence: Confidence
    drivers_affected: list[LossDriver]
    rationale: str


class IncidentProbabilityItem(BaseModel):
    """One dynamic incident type shown on the 'How Much Would a Cyber Incident Cost?' page."""
    key: str            # machine identifier, e.g. "ransomware"
    label: str          # display name, e.g. "Ransomware Risk"
    probability_pct: float  # 0-100 annual probability


class RiskSummary(BaseModel):
    """Underwriter-facing risk summary (Coalition-style layout).

    `risk_score` is on a 0-100 scale where **high = more risk** (inverse of
    the CIDA `overall_score`). It is primarily driven by control gaps,
    severity-weighted findings, and exposure.
    """
    risk_score: float                       # 0-100, 100 = high risk
    risk_band: Literal["LOW", "MODERATE", "ELEVATED", "HIGH", "SEVERE"]
    # Dynamic incident type list - derived from findings, sector, and driver EL.
    # Replaces the old dict[str, float] to include display labels.
    incident_probabilities: list[IncidentProbabilityItem] = Field(default_factory=list)
    # Likelihood of any cyber incident vs sector peer baseline.
    # multiplier < 1.0 → less likely than peer ; > 1.0 → more likely.
    likelihood_multiplier_vs_peer: float
    peer_baseline_annual_frequency: float   # incidents/yr for the median peer
    org_total_annual_frequency: float       # sum of mean λ across drivers
    # Aggregate annual loss percentiles across ALL drivers (composite).
    composite_loss_p50_usd: float
    composite_loss_p90_usd: float
    composite_loss_p99_usd: float
    # Attack-surface inventory derived from findings + org profile.
    attack_surface: dict[str, int] = Field(default_factory=dict)
    # Counts of unique findings by normalized severity.
    finding_counts: dict[str, int] = Field(default_factory=dict)
    # Posture indicators (DMARC, SPF, Data Leaks, Malware, ...).
    posture_signals: list[PostureSignal] = Field(default_factory=list)
    # Top non-critical findings grouped by title with asset counts.
    grouped_findings: list[dict] = Field(default_factory=list)
    # Per-threat-vector scores (14 vectors, 0-100 with confidence).
    vector_scores: list[VectorScore] = Field(default_factory=list)
    # Ranked "Drivers of Likelihood" - vectors most lifting the multiplier.
    top_likelihood_drivers: list[LikelihoodDriver] = Field(default_factory=list)
    # Per-assessment public intelligence (Proshare + BusinessDay) - counts &
    # the top headline items surfaced in the report.
    public_intel: dict = Field(default_factory=dict)
    intel_fetched_at: datetime | None = None


class CIDAReport(BaseModel):
    org: OrgProfile
    generated_at: datetime
    overall_score: float
    overall_score_ci_low: float
    overall_score_ci_high: float
    tier: TierAssignment
    domain_scores: list[DomainScore]
    loss_estimates: list[LossDriverEstimate]
    aggregate_expected_loss_usd: float
    aggregate_var_95_usd: float
    aggregate_tvar_99_usd: float
    risk_summary: RiskSummary | None = None
    premium: PremiumRecommendation
    posture: list[FrameworkPosture]
    remediation: list[RemediationItem]
    findings_summary: dict  # counts by severity, top CVEs/KEVs, etc.
    intel_summary: dict = Field(default_factory=dict)
    # YOA client report fields
    compromised_emails: list[str] = Field(default_factory=list)
    dns_records: dict[str, list[str]] = Field(default_factory=dict)  # A / MX / NS records
    assessment_limitations: list[str] = Field(default_factory=list)  # scope limitation notes
    evidence_images: list[dict] = Field(default_factory=list)         # {filename, caption, path, size_bytes}
    unclassified_files: list[dict] = Field(default_factory=list)      # files the sniffer could not classify
    disclaimer: str = (
        "CIDA Risk Assessment - Underwriting Decision Support. "
        "Final pricing and binding authority remain with the issuing carrier."
    )


# ---------- Config models ----------

class RegulatorDirective(BaseModel):
    id: str
    name: str
    enacted: str | None = None
    effective: str | None = None
    cyber_relevant_sections: list[dict] = Field(default_factory=list)

    @field_validator("enacted", "effective", mode="before")
    @classmethod
    def _coerce_date_to_str(cls, v):
        if isinstance(v, (date, datetime)):
            return v.isoformat()
        return v


class Regulator(BaseModel):
    id: str
    name: str
    type: Literal["insurance", "data_protection", "financial", "sector"]
    scope: Literal["national", "supranational"] = "national"
    country: str | None = None
    member_countries: list[str] = Field(default_factory=list)
    website: str | None = None
    directives: list[RegulatorDirective] = Field(default_factory=list)


class CountryRegulators(BaseModel):
    insurance: str | None = None
    data_protection: str | None = None
    central_bank: str | None = None
    capital_markets: str | None = None
    telecoms: str | None = None
    sector: dict[str, str] = Field(default_factory=dict)


class ITUGCI(BaseModel):
    edition: int
    year: int
    score: float
    tier: str


class Country(BaseModel):
    iso_a2: str
    iso_a3: str
    name: str
    region: str
    sub_region: str = "Sub-Saharan Africa"
    currency: str
    official_languages: list[str] = Field(default_factory=list)
    ccTLDs: list[str] = Field(default_factory=list)
    itu_gci: ITUGCI | None = None
    disclosure_correction_factor: float = 3.0
    mobile_money_penetration: Literal["low", "medium", "high", "very_high"] = "medium"
    base_frequency_multipliers: dict[LossDriver, float] = Field(default_factory=dict)
    regulators: CountryRegulators = Field(default_factory=CountryRegulators)
    cert: str | None = None
    intel_sources: list[str] = Field(default_factory=list)


class SectorOverlay(BaseModel):
    name: Sector
    description: str
    base_frequency_multipliers: dict[LossDriver, float] = Field(default_factory=dict)
    severity_multipliers: dict[LossDriver, float] = Field(default_factory=dict)
    required_frameworks: list[str] = Field(default_factory=list)
    additional_controls: list[str] = Field(default_factory=list)


class Priors(BaseModel):
    # Per loss driver: prior parameters
    # Frequency: Poisson rate, modeled via Gamma(alpha, beta) conjugate prior.
    #   E[lambda] = alpha / beta
    # Severity: Lognormal(mu, sigma)
    frequency_priors: dict[LossDriver, dict[str, float]]  # {driver: {alpha, beta}}
    severity_priors: dict[LossDriver, dict[str, float]]   # {driver: {mu, sigma}}
    sector_frequency_multipliers: dict[Sector, dict[LossDriver, float]] = Field(default_factory=dict)
    size_severity_elasticity: float = 0.45  # severity scales with revenue^elasticity
    source_notes: list[str] = Field(default_factory=list)
