"""Anomaly detection on questionnaire responses.

Flags internally inconsistent or statistically unusual response patterns
that suggest questionnaire gaming, incomplete assessment, or genuine
outlier risk profiles. Results are surfaced to the underwriter only
(not shown in the Policyholder Report).

v1 is rule-based — no training data required. The rules cover the
highest-value detection cases identified in live underwriting practice.
An isolation-forest layer can be added once enough assessments accumulate.
"""
from __future__ import annotations

from dataclasses import dataclass

from models import Domain, Finding, Severity


# Domain → typical corresponding ThreatVector name fragments
# Used to detect domain-vector score divergence.
_DOMAIN_VECTOR_MAP = {
    Domain.IDENTITY:       "identity_and_access",
    Domain.ENDPOINT:       "endpoint_security",
    Domain.DETECT_RESPOND: "detection_and_response",
    Domain.RESILIENCE:     "ddos_resilience",   # closest proxy for resilience
    Domain.NETWORK:        "external_network_exposure",
    Domain.APPSEC:         "web_application_weaknesses",
    Domain.CLOUD:          "cloud_misconfiguration",
    Domain.THIRD_PARTY:    "third_party_supply_chain",
    Domain.GOVERNANCE:     None,
    Domain.ASSET_DATA:     None,
}

# Sectors where a very high score is statistically unusual enough to require review
_HIGH_RISK_SECTORS = {"banking", "fintech"}

# Minimum controls that should be answered for a complete assessment
_MIN_CONTROLS_ANSWERED = 25

# Total controls in the catalog
_TOTAL_CONTROLS = 41


@dataclass
class AnomalyFlag:
    flag_type: str
    description: str
    affected_domain: str | None
    severity: str          # "high", "medium", "low"
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "flag_type": self.flag_type,
            "description": self.description,
            "affected_domain": self.affected_domain,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


def _control_count(responses) -> int:
    return len(responses.responses)


def _all_perfect(responses) -> bool:
    return all(r.score >= 99.9 for r in responses.responses)


def _domain_score(scoring, domain: Domain) -> float | None:
    for ds in scoring.domain_scores:
        if ds.domain == domain:
            return ds.score
    return None


def _vector_score(scoring, vector_name_fragment: str) -> float | None:
    if not scoring.domain_scores:
        return None
    # VectorScores are on the ActuarialResult, not ScoringResult.
    # ScoringResult only has domain_scores — we use those as a proxy.
    return None


def _critical_in_domain(findings: list[Finding], domain: Domain) -> int:
    return sum(
        1 for f in findings
        if f.domain == domain and f.severity == Severity.CRITICAL
    )


def _backup_findings(findings: list[Finding]) -> list[Finding]:
    keywords = ("backup", "recovery", "snapshot", "restore", "bcp", "bcdr")
    return [
        f for f in findings
        if any(k in (f.title or "").lower() or k in (f.description or "").lower()
               for k in keywords)
    ]


def detect_anomalies(
    responses,
    findings: list[Finding],
    scoring,
    sector: str = "other",
) -> list[AnomalyFlag]:
    """Detect questionnaire anomalies and internal inconsistencies.

    Args:
        responses:  QuestionnaireResponses.
        findings:   All Finding objects from the assessment.
        scoring:    ScoringResult.
        sector:     Org sector string.

    Returns:
        List of AnomalyFlag dicts for the underwriting scorecard.
    """
    flags: list[AnomalyFlag] = []
    n_answered = _control_count(responses)

    # Rule 1: Perfect attestation — all controls score 100
    if _all_perfect(responses) and n_answered >= _MIN_CONTROLS_ANSWERED:
        flags.append(AnomalyFlag(
            flag_type="PERFECT_ATTESTATION",
            description=(
                f"All {n_answered} questionnaire controls score 100/100. "
                "A perfect score is statistically rare for any organisation "
                "and may indicate the questionnaire was completed aspirationally "
                "rather than reflecting current operational reality."
            ),
            affected_domain=None,
            severity="high",
            recommendation=(
                "Request objective evidence for the top 5 highest-weight controls "
                "(MFA deployment logs, EDR coverage report, backup test records, "
                "patch compliance dashboard, incident response playbook). "
                "Apply a minimum 10-point score CI widening."
            ),
        ))

    # Rule 2: Identity inconsistency — high IAM score + critical identity findings
    iam_score = _domain_score(scoring, Domain.IDENTITY)
    crit_iam = _critical_in_domain(findings, Domain.IDENTITY)
    if iam_score is not None and iam_score > 80 and crit_iam > 0:
        flags.append(AnomalyFlag(
            flag_type="IDENTITY_INCONSISTENCY",
            description=(
                f"Identity domain score is {iam_score:.0f}/100 (strong) but "
                f"{crit_iam} CRITICAL finding(s) in the Identity domain from "
                "technical assessment. Technical evidence contradicts "
                "questionnaire attestation."
            ),
            affected_domain="identity",
            severity="high",
            recommendation=(
                "Reconcile specific findings with the self-reported MFA and PAM "
                "controls. Likely the questionnaire response covers planned "
                "controls, not deployed ones. Score the Identity domain at the "
                "technical finding level, not the questionnaire level."
            ),
        ))

    # Rule 3: Resilience inconsistency — high resilience score + backup findings
    res_score = _domain_score(scoring, Domain.RESILIENCE)
    backup_finds = _backup_findings(findings)
    if res_score is not None and res_score > 80 and backup_finds:
        flags.append(AnomalyFlag(
            flag_type="RESILIENCE_INCONSISTENCY",
            description=(
                f"Resilience domain score is {res_score:.0f}/100 (strong) but "
                f"{len(backup_finds)} backup/recovery finding(s) detected in "
                "technical assessment. Questionnaire and technical evidence diverge "
                "on backup and recovery maturity."
            ),
            affected_domain="resilience",
            severity="medium",
            recommendation=(
                "Request last successful backup restoration test report and "
                "offsite / immutable backup architecture diagram. If backup "
                "testing cannot be evidenced within the last 12 months, apply "
                "ransomware waiting period of 72 hours."
            ),
        ))

    # Rule 4: Incomplete assessment
    if n_answered < _MIN_CONTROLS_ANSWERED:
        flags.append(AnomalyFlag(
            flag_type="INCOMPLETE_QUESTIONNAIRE",
            description=(
                f"Only {n_answered} of {_TOTAL_CONTROLS} controls were answered "
                f"({100 * n_answered // _TOTAL_CONTROLS}% completion). "
                "Score confidence interval is significantly wider on unanswered domains."
            ),
            affected_domain=None,
            severity="medium",
            recommendation=(
                "Request completion of the remaining controls before binding, "
                "or apply a 15-point minimum CI widening to reflect incomplete "
                "information. Flag unanswered domains specifically."
            ),
        ))

    # Rule 5: Domain-vector divergence (using domain scores as proxy)
    # If a domain scores well (> 70) but has many technical findings in that domain
    for domain, vec_fragment in _DOMAIN_VECTOR_MAP.items():
        if vec_fragment is None:
            continue
        d_score = _domain_score(scoring, domain)
        if d_score is None or d_score <= 70:
            continue
        domain_finds = [
            f for f in findings if f.domain == domain
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if len(domain_finds) >= 3:
            flags.append(AnomalyFlag(
                flag_type="DOMAIN_VECTOR_DIVERGENCE",
                description=(
                    f"{domain.value.replace('_', ' ').title()} domain questionnaire "
                    f"score is {d_score:.0f}/100 but {len(domain_finds)} "
                    "CRITICAL/HIGH technical findings exist in this domain. "
                    "Self-attestation may not reflect technical posture."
                ),
                affected_domain=domain.value,
                severity="medium",
                recommendation=(
                    f"Review specific findings in the {domain.value} domain against "
                    "questionnaire responses. Apply technical finding penalty "
                    "directly to domain score and re-compute tier."
                ),
            ))

    # Rule 6: Sector outlier — very high score in a high-risk sector
    sector_str = sector.value if hasattr(sector, "value") else str(sector)
    if sector_str in _HIGH_RISK_SECTORS and scoring.overall_score > 90:
        flags.append(AnomalyFlag(
            flag_type="SECTOR_OUTLIER",
            description=(
                f"Overall score of {scoring.overall_score:.0f}/100 is exceptionally "
                f"high for a {sector_str} organisation in Africa. "
                "Very few African financial sector organisations achieve this "
                "maturity level; score warrants enhanced evidence review."
            ),
            affected_domain=None,
            severity="low",
            recommendation=(
                "Request third-party penetration test report (within 12 months), "
                "ISO 27001 or equivalent certification, and most recent incident "
                "log. Adjust premium loading if strong evidence confirms maturity."
            ),
        ))

    return flags
