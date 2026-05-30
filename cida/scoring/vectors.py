"""Threat-vector scoring (14 vectors x 0-100 score x confidence).

Maps technical findings + questionnaire responses + control catalog onto the
14 ThreatVector enum members. Each vector emits a `VectorScore` with:

    score_0_100  - 0 (best) ... 100 (worst saturated exposure)
    confidence   - HIGH (hard telemetry only), MEDIUM (mixed), LOW (self-attest only)
    n_findings   - count of findings backing the score
    n_controls   - count of control responses contributing
    top_evidence - short list of titles / control IDs for the report

Vectors with no telemetry and no relevant control responses receive
score=50 (neutral) with confidence=LOW so downstream math doesn't divide by
zero, but they are flagged in the report.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from cida.catalog.loader import load_catalog
from cida.config.loader import load_vector_matrix
from cida.models import (
    Confidence,
    ControlCatalog,
    Domain,
    Finding,
    LossDriver,
    QuestionnaireResponses,
    Severity,
    ThreatVector,
    VectorScore,
)


# ---------------------------------------------------------------------------
# Finding-source routing -----------------------------------------------------
# ---------------------------------------------------------------------------
# Each finding's `source` field is matched (case-insensitive substring) to
# the vector(s) it provides evidence for.

_SOURCE_TO_VECTORS: dict[str, list[ThreatVector]] = {
    "shodan":              [ThreatVector.EXTERNAL_NETWORK_EXPOSURE],
    "censys":              [ThreatVector.EXTERNAL_NETWORK_EXPOSURE],
    "amass":               [ThreatVector.EXTERNAL_NETWORK_EXPOSURE],
    "attack_surface":      [ThreatVector.EXTERNAL_NETWORK_EXPOSURE],
    "nessus":              [ThreatVector.UNPATCHED_VULNERABILITIES],
    "qualys":              [ThreatVector.UNPATCHED_VULNERABILITIES],
    "tenable":             [ThreatVector.UNPATCHED_VULNERABILITIES],
    "openvas":             [ThreatVector.UNPATCHED_VULNERABILITIES],
    "burp":                [ThreatVector.WEB_APPLICATION_WEAKNESSES],
    "zap":                 [ThreatVector.WEB_APPLICATION_WEAKNESSES],
    "vapt_pdf":            [ThreatVector.WEB_APPLICATION_WEAKNESSES, ThreatVector.UNPATCHED_VULNERABILITIES],
    "appsec":              [ThreatVector.WEB_APPLICATION_WEAKNESSES],
    "dmarc":               [ThreatVector.EMAIL_HYGIENE],
    "spf":                 [ThreatVector.EMAIL_HYGIENE],
    "dkim":                [ThreatVector.EMAIL_HYGIENE],
    "dns":                 [ThreatVector.EMAIL_HYGIENE, ThreatVector.DDOS_RESILIENCE],
    "prowler":             [ThreatVector.CLOUD_MISCONFIGURATION],
    "securityhub":         [ThreatVector.CLOUD_MISCONFIGURATION],
    "asff":                [ThreatVector.CLOUD_MISCONFIGURATION],
    "scoutsuite":          [ThreatVector.CLOUD_MISCONFIGURATION],
    "defender":            [ThreatVector.CLOUD_MISCONFIGURATION],
    "scc":                 [ThreatVector.CLOUD_MISCONFIGURATION],
    "cspm":                [ThreatVector.CLOUD_MISCONFIGURATION],
    "darkweb_credentials": [ThreatVector.CREDENTIAL_SECRETS_EXPOSURE],
    "darkweb_stealer":     [ThreatVector.CREDENTIAL_SECRETS_EXPOSURE],
    "leaked_secrets":      [ThreatVector.CREDENTIAL_SECRETS_EXPOSURE],
}


def _vectors_for_finding(f: Finding) -> list[ThreatVector]:
    src = (f.source or "").lower()
    for key, vecs in _SOURCE_TO_VECTORS.items():
        if key in src:
            return vecs
    # Fallback via domain
    if f.domain == Domain.APPSEC:
        return [ThreatVector.WEB_APPLICATION_WEAKNESSES]
    if f.domain == Domain.CLOUD:
        return [ThreatVector.CLOUD_MISCONFIGURATION]
    if f.domain == Domain.NETWORK:
        return [ThreatVector.EXTERNAL_NETWORK_EXPOSURE]
    if f.domain == Domain.ENDPOINT:
        return [ThreatVector.ENDPOINT_SECURITY]
    if f.domain == Domain.IDENTITY:
        return [ThreatVector.IDENTITY_AND_ACCESS]
    if f.domain == Domain.ASSET_DATA:
        return [ThreatVector.DATA_PROTECTION]
    return []


# Confidence tier per vector based on telemetry availability.
_VECTOR_CONFIDENCE: dict[ThreatVector, Confidence] = {
    ThreatVector.EXTERNAL_NETWORK_EXPOSURE:   Confidence.HIGH,
    ThreatVector.UNPATCHED_VULNERABILITIES:   Confidence.HIGH,
    ThreatVector.WEB_APPLICATION_WEAKNESSES:  Confidence.HIGH,
    ThreatVector.EMAIL_HYGIENE:               Confidence.HIGH,
    ThreatVector.IDENTITY_AND_ACCESS:         Confidence.MEDIUM,
    ThreatVector.ENDPOINT_SECURITY:           Confidence.MEDIUM,
    ThreatVector.CLOUD_MISCONFIGURATION:      Confidence.HIGH,
    ThreatVector.DATA_PROTECTION:             Confidence.MEDIUM,
    ThreatVector.THIRD_PARTY_SUPPLY_CHAIN:    Confidence.MEDIUM,
    ThreatVector.DETECTION_AND_RESPONSE:      Confidence.LOW,
    ThreatVector.CREDENTIAL_SECRETS_EXPOSURE: Confidence.HIGH,
    ThreatVector.DDOS_RESILIENCE:             Confidence.LOW,
    ThreatVector.INSIDER_RISK:                Confidence.LOW,
    ThreatVector.MOBILE_AGENT_NETWORK:        Confidence.LOW,
}

# Severity → finding-points (worse exposure)
_FINDING_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH:     12.0,
    Severity.MEDIUM:    4.0,
    Severity.LOW:       1.0,
    Severity.INFO:      0.0,
}

# Vectors that have NO finding sources today → questionnaire-only. We still
# compute a score from control responses (or fall back to 50).
_QUESTIONNAIRE_ONLY: set[ThreatVector] = {
    ThreatVector.THIRD_PARTY_SUPPLY_CHAIN,
    ThreatVector.DETECTION_AND_RESPONSE,
    ThreatVector.DDOS_RESILIENCE,
    ThreatVector.INSIDER_RISK,
    ThreatVector.MOBILE_AGENT_NETWORK,
}


def _controls_for_vector(catalog: ControlCatalog, vector: ThreatVector):
    """Returns controls whose `threat_vectors` list includes this vector,
    OR - if no controls are explicitly tagged - falls back to the domain
    -> vector map below so the legacy 41-control catalog still drives the
    scoring engine.
    """
    explicit = [c for c in catalog.controls if vector in (c.threat_vectors or [])]
    if explicit:
        return explicit
    fallback_domains = _DOMAIN_FALLBACK.get(vector, [])
    if not fallback_domains:
        return []
    return [c for c in catalog.controls if c.domain in fallback_domains]


# Domain -> ThreatVector fallback used when controls are not explicitly tagged.
_DOMAIN_FALLBACK: dict[ThreatVector, list[Domain]] = {
    ThreatVector.EXTERNAL_NETWORK_EXPOSURE:   [Domain.NETWORK],
    ThreatVector.UNPATCHED_VULNERABILITIES:   [Domain.NETWORK, Domain.ENDPOINT],
    ThreatVector.WEB_APPLICATION_WEAKNESSES:  [Domain.APPSEC],
    ThreatVector.EMAIL_HYGIENE:               [Domain.IDENTITY, Domain.DETECT_RESPOND],
    ThreatVector.IDENTITY_AND_ACCESS:         [Domain.IDENTITY],
    ThreatVector.ENDPOINT_SECURITY:           [Domain.ENDPOINT],
    ThreatVector.CLOUD_MISCONFIGURATION:      [Domain.CLOUD],
    ThreatVector.DATA_PROTECTION:             [Domain.ASSET_DATA],
    ThreatVector.THIRD_PARTY_SUPPLY_CHAIN:    [Domain.THIRD_PARTY],
    ThreatVector.DETECTION_AND_RESPONSE:      [Domain.DETECT_RESPOND],
    ThreatVector.CREDENTIAL_SECRETS_EXPOSURE: [Domain.IDENTITY],
    ThreatVector.DDOS_RESILIENCE:             [Domain.RESILIENCE, Domain.NETWORK],
    ThreatVector.INSIDER_RISK:                [Domain.GOVERNANCE, Domain.IDENTITY],
    ThreatVector.MOBILE_AGENT_NETWORK:        [Domain.IDENTITY, Domain.APPSEC],
}


def _control_deficit_score(
    catalog: ControlCatalog,
    responses: QuestionnaireResponses,
    vector: ThreatVector,
) -> tuple[float | None, int, list[str]]:
    """Returns (deficit_0_100, n_controls, top_gap_control_ids) where
    deficit = 100 − weighted_mean(control_score). None if no controls match
    OR none are answered for this vector.
    """
    rel = _controls_for_vector(catalog, vector)
    if not rel:
        return None, 0, []
    weighted_sum = 0.0
    weight_total = 0.0
    n = 0
    by_score: list[tuple[float, str]] = []
    for c in rel:
        r = responses.get(c.control_id)
        if r is None:
            continue
        weighted_sum += r.score * c.weight
        weight_total += c.weight
        n += 1
        by_score.append((r.score, c.control_id))
    if n == 0 or weight_total == 0:
        return None, 0, []
    avg = weighted_sum / weight_total
    deficit = max(0.0, 100.0 - avg)
    by_score.sort(key=lambda x: x[0])
    top_gaps = [cid for s, cid in by_score if s < 70.0][:3]
    return deficit, n, top_gaps


def _findings_to_vector_scores(
    findings: Iterable[Finding],
) -> dict[ThreatVector, tuple[float, int, list[str]]]:
    """Returns vector → (raw_finding_pts, n_findings, top_titles)."""
    bucket: dict[ThreatVector, list[Finding]] = defaultdict(list)
    for f in findings:
        for v in _vectors_for_finding(f):
            bucket[v].append(f)
    out: dict[ThreatVector, tuple[float, int, list[str]]] = {}
    for v, fs in bucket.items():
        pts = 0.0
        for f in fs:
            pts += _FINDING_POINTS.get(f.severity, 0.0)
            if f.kev_listed:
                pts += 15.0
            if f.epss_score is not None and f.epss_score > 0.5:
                pts += 4.0
            if f.exposure == "internet":
                pts += 2.0
        # Top evidence: by severity then KEV
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        ordered = sorted(fs, key=lambda f: (severity_order.index(f.severity), 0 if f.kev_listed else 1))
        titles = [f.title for f in ordered[:3]]
        out[v] = (pts, len(fs), titles)
    return out


def score_threat_vectors(
    responses: QuestionnaireResponses,
    findings: list[Finding],
    catalog: ControlCatalog | None = None,
) -> list[VectorScore]:
    """Compute a `VectorScore` for each of the 14 ThreatVectors."""
    catalog = catalog or load_catalog()
    matrix_cfg = load_vector_matrix()
    matrix = matrix_cfg.get("matrix", {})

    finding_scores = _findings_to_vector_scores(findings)
    out: list[VectorScore] = []

    for vector in ThreatVector:
        finding_pts, n_findings, top_titles = finding_scores.get(vector, (0.0, 0, []))
        ctrl_deficit, n_controls, ctrl_gaps = _control_deficit_score(catalog, responses, vector)

        # Combine finding & control signals.
        # Findings contribute up to 70 points (linearly capped).
        finding_component = min(70.0, finding_pts)
        if ctrl_deficit is not None:
            # Controls bring up to 100. Blend 60/40 (control / finding) when both present.
            if n_findings > 0:
                score = 0.6 * ctrl_deficit + 0.4 * (finding_component * 100.0 / 70.0)
            else:
                score = ctrl_deficit
        else:
            if n_findings > 0:
                # No controls answered → scale finding component up to 0-100
                score = finding_component * 100.0 / 70.0
            else:
                # No evidence at all → neutral 50, confidence LOW
                score = 50.0

        score = round(max(0.0, min(100.0, score)), 1)

        # Confidence: downgrade if we had no telemetry for a normally-HIGH vector.
        base_conf = _VECTOR_CONFIDENCE[vector]
        if vector not in _QUESTIONNAIRE_ONLY:
            if n_findings == 0 and ctrl_deficit is None:
                conf = Confidence.LOW
            elif n_findings == 0 and base_conf == Confidence.HIGH:
                conf = Confidence.MEDIUM
            else:
                conf = base_conf
        else:
            conf = base_conf

        # Which drivers does this vector lift right now? (matrix cell > 1.0)
        row = matrix.get(vector.value, {}) or {}
        contrib_drivers: list[LossDriver] = []
        for d_key, mult in row.items():
            if isinstance(mult, (int, float)) and mult > 1.05:
                try:
                    contrib_drivers.append(LossDriver(d_key))
                except ValueError:
                    pass
        # Cap contributing list to top-4 by multiplier
        contrib_drivers.sort(
            key=lambda d: row.get(d.value, 1.0),
            reverse=True,
        )
        contrib_drivers = contrib_drivers[:4]

        evidence = top_titles + ctrl_gaps

        out.append(
            VectorScore(
                vector=vector,
                score_0_100=score,
                confidence=conf,
                n_findings=n_findings,
                n_controls=n_controls,
                top_evidence=evidence[:5],
                contributing_drivers=contrib_drivers,
            )
        )

    return out


def vector_multiplier_for_driver(
    driver: LossDriver,
    vector_scores: list[VectorScore],
    matrix_cfg: dict | None = None,
) -> tuple[float, list[tuple[ThreatVector, float, float]]]:
    """Compute the combined frequency multiplier for one loss driver from
    all 14 vectors and return per-vector contributions for explainability.

    Returns:
        combined_mult: product of (1 + score/100 * (matrix_val - 1)) capped.
        contributions: list of (vector, per_vector_mult, score_0_100).
    """
    matrix_cfg = matrix_cfg or load_vector_matrix()
    matrix = matrix_cfg.get("matrix", {})
    cap = float(matrix_cfg.get("per_driver_cap", 6.0))

    combined = 1.0
    contribs: list[tuple[ThreatVector, float, float]] = []
    for vs in vector_scores:
        row = matrix.get(vs.vector.value, {}) or {}
        cell = float(row.get(driver.value, 1.0))
        if cell == 1.0:
            contribs.append((vs.vector, 1.0, vs.score_0_100))
            continue
        per_vec = 1.0 + (vs.score_0_100 / 100.0) * (cell - 1.0)
        per_vec = max(1.0, per_vec)  # never reduce below 1.0
        combined *= per_vec
        contribs.append((vs.vector, per_vec, vs.score_0_100))

    combined = min(combined, cap)
    return combined, contribs


def peer_baseline_multiplier_for_driver(
    driver: LossDriver,
    matrix_cfg: dict | None = None,
) -> float:
    """Combined multiplier when every vector sits at the peer baseline score."""
    matrix_cfg = matrix_cfg or load_vector_matrix()
    matrix = matrix_cfg.get("matrix", {})
    cap = float(matrix_cfg.get("per_driver_cap", 6.0))
    baseline = float(matrix_cfg.get("peer_baseline_vector_score", 40.0))

    combined = 1.0
    for vector in ThreatVector:
        row = matrix.get(vector.value, {}) or {}
        cell = float(row.get(driver.value, 1.0))
        if cell == 1.0:
            continue
        per_vec = 1.0 + (baseline / 100.0) * (cell - 1.0)
        combined *= per_vec
    return min(combined, cap)
