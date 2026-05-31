"""Score calibration against dark web and credential exposure evidence.

Checks whether technical findings (dark web, credential leaks, stealer logs)
are consistent with questionnaire-derived domain scores. When an org claims
strong identity controls but has active credential exposure, the inconsistency
widens the score confidence interval and raises underwriter alerts.

This detects questionnaire optimism — a documented pattern where organisations
over-report security maturity (Beazley 2024: 75% of executives believe they are
better prepared than their actual posture shows).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from models import Domain, Finding, OrgProfile, Severity


@dataclass
class CalibrationFlag:
    flag_type: str
    description: str
    severity: str          # "high", "medium", "low"
    recommendation: str


@dataclass
class CalibrationResult:
    score_ci_adjustment: float          # additive points added to CI half-width
    flags: list[CalibrationFlag]
    adjusted_ci_low: float
    adjusted_ci_high: float

    def to_dict(self) -> dict:
        return {
            "score_ci_adjustment": round(self.score_ci_adjustment, 1),
            "adjusted_ci_low": round(self.adjusted_ci_low, 1),
            "adjusted_ci_high": round(self.adjusted_ci_high, 1),
            "flags": [
                {
                    "flag_type": f.flag_type,
                    "description": f.description,
                    "severity": f.severity,
                    "recommendation": f.recommendation,
                }
                for f in self.flags
            ],
        }


def _is_credential_finding(f: Finding) -> bool:
    src = (f.source or "").lower()
    return any(k in src for k in ("darkweb", "dark_web", "credential", "stealer",
                                   "spycloud", "dehashed", "hibp", "flare",
                                   "hudson", "breach"))


def _is_plaintext_credential(f: Finding) -> bool:
    return _is_credential_finding(f) and f.severity in (
        Severity.CRITICAL, Severity.HIGH
    )


def _is_stealer_log(f: Finding) -> bool:
    src = (f.source or "").lower()
    return any(k in src for k in ("stealer", "redline", "raccoon", "vidar", "lumma",
                                   "hudson", "russian_market", "genesis"))


def _identity_domain_score(scoring) -> float | None:
    for ds in scoring.domain_scores:
        if ds.domain == Domain.IDENTITY:
            return ds.score
    return None


def _resilience_domain_score(scoring) -> float | None:
    for ds in scoring.domain_scores:
        if ds.domain == Domain.RESILIENCE:
            return ds.score
    return None


def _critical_findings_in_domain(findings: list[Finding], domain: Domain) -> int:
    return sum(
        1 for f in findings
        if f.domain == domain and f.severity == Severity.CRITICAL
    )


def calibrate_score(
    scoring,
    findings: list[Finding],
    org: OrgProfile,
) -> CalibrationResult:
    """Check consistency between questionnaire scores and technical evidence.

    Args:
        scoring:   ScoringResult from score_organization().
        findings:  All Finding objects from the assessment.
        org:       OrgProfile (used for email domain matching).

    Returns:
        CalibrationResult with CI adjustment and inconsistency flags.
    """
    flags: list[CalibrationFlag] = []
    ci_adjustment = 0.0

    cred_findings = [f for f in findings if _is_credential_finding(f)]
    plaintext_cred = [f for f in findings if _is_plaintext_credential(f)]
    stealer_logs = [f for f in findings if _is_stealer_log(f)]

    iam_score = _identity_domain_score(scoring)

    # Check 1: Credential evidence contradicts high IAM score
    if cred_findings and iam_score is not None and iam_score > 75:
        ci_adjustment += 8.0
        flags.append(CalibrationFlag(
            flag_type="IDENTITY_INCONSISTENCY",
            description=(
                f"IAM domain score is {iam_score:.0f}/100 (strong) but "
                f"{len(cred_findings)} credential exposure finding(s) detected "
                "in dark web / breach data. Questionnaire may over-state "
                "identity control maturity."
            ),
            severity="high",
            recommendation=(
                "Request evidence of MFA deployment logs, credential rotation "
                "records, and privileged account audit before binding. Consider "
                "excluding specific credentials found in breach data from coverage "
                "until rotation is confirmed."
            ),
        ))

    # Check 2: Plaintext credentials + low confidence on identity vector
    if plaintext_cred:
        from models import Confidence
        identity_vec_low = any(
            vs.confidence in (Confidence.LOW, Confidence.MEDIUM)
            for vs in (scoring.domain_scores or [])
            if hasattr(vs, "confidence")
        )
        ci_adjustment += 5.0
        flags.append(CalibrationFlag(
            flag_type="ACTIVE_PLAINTEXT_EXPOSURE",
            description=(
                f"{len(plaintext_cred)} plaintext credential finding(s) detected "
                "(CRITICAL or HIGH severity). These represent active, exploitable "
                "account access, not historical hashed leaks."
            ),
            severity="high",
            recommendation=(
                "Mandatory immediate credential rotation for all affected accounts "
                "before coverage commences. Widen exclusion for BEC/FTF events "
                "involving accounts listed in findings."
            ),
        ))

    # Check 3: Active stealer log dump linked to org domain
    org_domains = set(d.lower() for d in (org.email_domains or []))
    org_domains.update(d.lower() for d in (org.websites or []))
    stealer_hits = [
        f for f in stealer_logs
        if any(d in (f.asset or "").lower() for d in org_domains)
    ] if org_domains else stealer_logs

    if stealer_hits:
        ci_adjustment += 6.0
        flags.append(CalibrationFlag(
            flag_type="ACTIVE_STEALER_EXPOSURE",
            description=(
                f"{len(stealer_hits)} active stealer log finding(s) directly "
                "reference the organisation's email domain or websites. Stealer "
                "logs indicate malware-infected employee devices with live "
                "credential dumps — the highest-risk credential exposure type."
            ),
            severity="high",
            recommendation=(
                "Require endpoint incident response investigation before binding. "
                "Apply waiting period or exclusion for ransomware events until "
                "EDR deployment is confirmed on affected endpoints."
            ),
        ))

    # Compute adjusted CI
    raw_low = scoring.overall_score_ci_low
    raw_high = scoring.overall_score_ci_high
    half_adj = ci_adjustment / 2.0
    adjusted_low = max(0.0, raw_low - half_adj)
    adjusted_high = min(100.0, raw_high + half_adj)

    return CalibrationResult(
        score_ci_adjustment=ci_adjustment,
        flags=flags,
        adjusted_ci_low=adjusted_low,
        adjusted_ci_high=adjusted_high,
    )
