"""Core scoring engine.

Pipeline:
1. Per-control score (from questionnaire response, 0-100).
2. Per-domain rollup: weighted mean of control scores − technical-findings penalty.
3. Overall score: weighted GEOMETRIC mean of domain scores (penalizes any one weak domain).
4. Tier assignment 1-5.

All weights and tier thresholds are config-driven.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np

from catalog.loader import load_catalog
from models import (
    Control,
    ControlCatalog,
    Domain,
    DomainScore,
    Finding,
    QuestionnaireResponses,
    Severity,
    TierAssignment,
)


# Domain weights - sum to 1.0
DOMAIN_WEIGHTS: dict[Domain, float] = {
    Domain.GOVERNANCE: 0.10,
    Domain.IDENTITY: 0.14,
    Domain.ASSET_DATA: 0.10,
    Domain.NETWORK: 0.10,
    Domain.ENDPOINT: 0.12,
    Domain.APPSEC: 0.09,
    Domain.CLOUD: 0.08,
    Domain.THIRD_PARTY: 0.07,
    Domain.DETECT_RESPOND: 0.12,
    Domain.RESILIENCE: 0.08,
}

# Penalty per technical finding by severity (points off the domain score).
SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 8.0,
    Severity.HIGH: 3.5,
    Severity.MEDIUM: 1.0,
    Severity.LOW: 0.25,
    Severity.INFO: 0.0,
}

# KEV-listed CVE adds a flat extra penalty (in points).
KEV_BONUS_PENALTY = 6.0

MAX_DOMAIN_TECH_PENALTY = 35.0  # cap so one noisy scanner can't zero a domain


TIER_BANDS = [
    (85, TierAssignment(tier=1, label="Excellent", description="Mature program; preferred risk")),
    (70, TierAssignment(tier=2, label="Good", description="Strong program with minor gaps; standard terms")),
    (55, TierAssignment(tier=3, label="Adequate", description="Acceptable risk with required remediations")),
    (40, TierAssignment(tier=4, label="Below Standard", description="Material gaps; restricted terms or sub-limits required")),
    (0,  TierAssignment(tier=5, label="High Risk", description="Significant deficiencies; declination or conditional cover")),
]


@dataclass
class ScoringResult:
    overall_score: float
    overall_score_ci_low: float
    overall_score_ci_high: float
    tier: TierAssignment
    domain_scores: list[DomainScore]
    control_scores: dict[str, float]   # control_id -> 0-100
    findings_summary: dict


def _tier_for(score: float) -> TierAssignment:
    for threshold, tier in TIER_BANDS:
        if score >= threshold:
            return tier
    return TIER_BANDS[-1][1]


def _domain_tech_penalty(domain: Domain, findings: Iterable[Finding]) -> float:
    penalty = 0.0
    for f in findings:
        if f.domain != domain:
            continue
        penalty += SEVERITY_PENALTY.get(f.severity, 0.0)
        if f.kev_listed:
            penalty += KEV_BONUS_PENALTY
        if f.epss_score is not None and f.epss_score > 0.5:
            penalty += 2.0
        if f.exposure == "internet":
            penalty *= 1.0  # already weighted via severity; placeholder
    return min(penalty, MAX_DOMAIN_TECH_PENALTY)


def _control_response_score(responses: QuestionnaireResponses, cid: str) -> float | None:
    r = responses.get(cid)
    return r.score if r else None


def score_organization(
    responses: QuestionnaireResponses,
    findings: list[Finding],
    catalog: ControlCatalog | None = None,
) -> ScoringResult:
    catalog = catalog or load_catalog()

    # 1) per-control scores (only those answered)
    control_scores: dict[str, float] = {}
    for control in catalog.controls:
        s = _control_response_score(responses, control.control_id)
        if s is not None:
            control_scores[control.control_id] = s

    # 2) per-domain rollup
    domain_scores: list[DomainScore] = []
    for domain in Domain:
        controls_in = catalog.by_domain(domain)
        scored = [(c, control_scores[c.control_id]) for c in controls_in if c.control_id in control_scores]
        if not scored:
            # Unanswered domain → assume neutral 50 (uncertain), with high CI later
            ds = DomainScore(domain=domain, score=50.0, n_controls=0, n_passed=0,
                             weight=DOMAIN_WEIGHTS.get(domain, 0.0),
                             technical_penalty=_domain_tech_penalty(domain, findings),
                             top_gaps=[])
            ds.score = max(0.0, ds.score - ds.technical_penalty)
            domain_scores.append(ds)
            continue
        weights = np.array([c.weight for c, _ in scored])
        scores = np.array([s for _, s in scored])
        weighted_mean = float(np.sum(weights * scores) / np.sum(weights))
        tech_pen = _domain_tech_penalty(domain, findings)
        final = max(0.0, weighted_mean - tech_pen)
        # Top gaps: lowest-scoring controls in this domain
        gaps_sorted = sorted(scored, key=lambda cs: cs[1])
        top_gap_ids = [c.control_id for c, s in gaps_sorted if s < 70.0][:3]
        ds = DomainScore(
            domain=domain,
            score=round(final, 1),
            n_controls=len(scored),
            n_passed=sum(1 for _, s in scored if s >= 70),
            weight=DOMAIN_WEIGHTS.get(domain, 0.0),
            technical_penalty=round(tech_pen, 1),
            top_gaps=top_gap_ids,
        )
        domain_scores.append(ds)

    # 3) Overall: weighted GEOMETRIC mean (penalizes weak domains harder than arithmetic mean)
    # Use log-space to avoid 0s. Add small epsilon to allow log(0) edge case.
    weights = np.array([ds.weight for ds in domain_scores])
    scores = np.array([max(ds.score, 1.0) for ds in domain_scores])
    weights = weights / weights.sum()
    log_score = float(np.sum(weights * np.log(scores)))
    overall = float(np.exp(log_score))

    # Uncertainty interval - driven by (a) unanswered controls and (b) finding noise.
    # Simple heuristic: ±sqrt(unanswered_fraction)*15 points.
    answered = len(control_scores)
    total = len(catalog.controls)
    unanswered_frac = max(0.0, 1.0 - answered / total)
    ci_half = 3.0 + 15.0 * np.sqrt(unanswered_frac)
    ci_low = max(0.0, overall - ci_half)
    ci_high = min(100.0, overall + ci_half)

    # Findings summary
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    kev_count = 0
    cve_set: set[str] = set()
    for f in findings:
        sev_counts[f.severity.value if hasattr(f.severity, "value") else f.severity] = sev_counts.get(
            f.severity.value if hasattr(f.severity, "value") else f.severity, 0
        ) + 1
        if f.kev_listed:
            kev_count += 1
        if f.cve_id:
            cve_set.add(f.cve_id)
    findings_summary = {
        "total": len(findings),
        "by_severity": sev_counts,
        "kev_count": kev_count,
        "unique_cves": len(cve_set),
    }

    return ScoringResult(
        overall_score=round(overall, 1),
        overall_score_ci_low=round(ci_low, 1),
        overall_score_ci_high=round(ci_high, 1),
        tier=_tier_for(overall),
        domain_scores=domain_scores,
        control_scores=control_scores,
        findings_summary=findings_summary,
    )
