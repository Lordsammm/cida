"""Build the underwriter-facing RiskSummary (Coalition-style layout).

risk_score · risk_band · likelihood_vs_peer · incident_probabilities ·
attack_surface · posture_signals · vector_scores · likelihood_drivers · public_intel
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Iterable

from dataclasses import dataclass, field

from cida.actuarial.model import ActuarialResult
from cida.models import (
    CompanyIntelSnapshot,
    Confidence,
    Finding,
    IncidentProbabilityItem,
    LikelihoodDriver,
    LossDriver,
    OrgProfile,
    PostureSignal,
    RiskSummary,
    Severity,
    ThreatVector,
)
from cida.scoring.engine import ScoringResult

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]*\.(?:[a-z0-9\-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
_PORT_RE = re.compile(r":(\d{1,5})\b")
_URL_RE = re.compile(r"https?://[^\s,]+", re.IGNORECASE)


def _band_for(risk_score: float) -> str:
    if risk_score < 20:
        return "LOW"
    if risk_score < 40:
        return "MODERATE"
    if risk_score < 60:
        return "ELEVATED"
    if risk_score < 80:
        return "HIGH"
    return "SEVERE"


def _attack_surface(org: OrgProfile, findings: list[Finding]) -> dict[str, int]:
    sub_domains: set[str] = set()
    ips: set[str] = set()
    apps: set[str] = set()
    services: set[tuple[str, str]] = set()

    # Seed from org profile
    for w in org.websites:
        m = _HOST_RE.search(w)
        if m:
            sub_domains.add(m.group(1).lower())
        if w.strip().startswith(("http://", "https://")):
            apps.add(w.strip().rstrip("/").lower())
    for d in org.email_domains:
        sub_domains.add(d.lower())

    for f in findings:
        a = (f.asset or "").strip()
        if not a:
            continue
        for ip in _IPV4_RE.findall(a):
            ips.add(ip)
        for host in _HOST_RE.findall(a):
            sub_domains.add(host.lower())
        for url in _URL_RE.findall(a):
            apps.add(url.rstrip("/").lower())
        ports = _PORT_RE.findall(a)
        host_key = (_HOST_RE.search(a).group(1).lower() if _HOST_RE.search(a)
                    else (_IPV4_RE.search(a).group(1) if _IPV4_RE.search(a) else a.lower()))
        for p in ports:
            services.add((host_key, p))

    return {
        "sub_domains": len(sub_domains),
        "ip_addresses": len(ips),
        "applications": len(apps),
        "services": len(services),
    }


def _finding_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _posture_signals(findings: list[Finding]) -> list[PostureSignal]:
    """Derive Coalition-style posture indicators from findings.

    Indicators: Data Leaks, Malware, Spam, Blocklisted Domains, DMARC, SPF,
    Torrents, Malicious Events, Honeypot Events. Where we have no telemetry,
    we emit NOT_ENABLED rather than fabricating a SECURE status.
    """
    signals: dict[str, PostureSignal] = {}

    # Data Leaks - from dark-web credentials
    leaks = [f for f in findings if f.source in {"darkweb_credentials", "darkweb_stealer"}
             or "data leak" in (f.title or "").lower()
             or "credential leak" in (f.title or "").lower()]
    n_leaks = len(leaks)
    signals["Data Leaks"] = PostureSignal(
        name="Data Leaks",
        status="AT_RISK" if n_leaks > 0 else "SECURE",
        count=n_leaks,
        detail=f"{n_leaks} leaked credential(s) found on dark-web sources" if n_leaks else "No credential leaks detected",
    )

    # Malware - stealer-tagged findings or malware-titled findings
    malware = [f for f in findings if f.source == "darkweb_stealer"
               or "malware" in (f.title or "").lower()
               or "stealer" in (f.title or "").lower()
               or "trojan" in (f.title or "").lower()]
    signals["Malware"] = PostureSignal(
        name="Malware",
        status="AT_RISK" if malware else "SECURE",
        count=len(malware),
        detail=f"{len(malware)} malware/infostealer indicator(s)" if malware else "No active malware indicators",
    )

    # DMARC
    dmarc_findings = [f for f in findings if "dmarc" in (f.title or "").lower()
                      or "dmarc" in (f.source or "").lower()]
    if dmarc_findings:
        bad = any(f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM) for f in dmarc_findings)
        signals["DMARC"] = PostureSignal(
            name="DMARC",
            status="AT_RISK" if bad else "SECURE",
            count=len(dmarc_findings),
            detail=dmarc_findings[0].title if bad else "DMARC policy enforced",
        )
    else:
        signals["DMARC"] = PostureSignal(name="DMARC", status="NOT_AVAILABLE",
                                          detail="No DMARC record collected")

    # SPF
    spf_findings = [f for f in findings if "spf" in (f.title or "").lower()]
    if spf_findings:
        bad = any(f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM) for f in spf_findings)
        signals["SPF"] = PostureSignal(
            name="SPF",
            status="AT_RISK" if bad else "SECURE",
            count=len(spf_findings),
            detail=spf_findings[0].title if bad else "SPF policy enforced",
        )
    else:
        signals["SPF"] = PostureSignal(name="SPF", status="NOT_AVAILABLE",
                                        detail="No SPF record collected")

    # Indicators we don't yet collect telemetry for
    for name in ("Spam", "Blocklisted Domains", "Torrents", "Malicious Events", "Honeypot Events"):
        signals[name] = PostureSignal(name=name, status="NOT_ENABLED",
                                       detail="Telemetry source not configured")

    return list(signals.values())


def _grouped_findings(findings: list[Finding], top_n: int = 15) -> list[dict]:
    by_title: dict[str, dict] = {}
    for f in findings:
        key = f.title or "(untitled finding)"
        if key not in by_title:
            by_title[key] = {
                "title": key,
                "severity": (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower(),
                "asset_count": 0,
                "domain": f.domain.value if hasattr(f.domain, "value") else str(f.domain),
            }
        by_title[key]["asset_count"] += 1
    # Sort by severity rank then asset_count desc
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items = sorted(by_title.values(),
                   key=lambda d: (sev_rank.get(d["severity"], 5), -d["asset_count"]))
    return items[:top_n]


def _top_likelihood_drivers(actuarial: ActuarialResult, top_n: int = 5) -> list[LikelihoodDriver]:
    """Rank ThreatVectors by their aggregate contribution to org frequency lift.

    contribution_pts = sum across drivers of (per_vector_mult - 1.0) * 100,
    weighted by each driver's prior frequency share so that vectors lifting
    *common* drivers rank higher than vectors lifting only rare drivers.
    """
    vector_scores = actuarial.vector_scores or []
    contribs_map = actuarial.vector_contributions_per_driver or {}
    if not vector_scores:
        return []

    # Frequency weights: mean lambda per driver, normalized to sum=1.
    driver_weights: dict[str, float] = {}
    total = sum(d.annual_frequency_mean for d in actuarial.per_driver) or 1.0
    for d in actuarial.per_driver:
        driver_weights[d.driver.value] = d.annual_frequency_mean / total

    # Confidence lookup
    conf_by_vector = {vs.vector: vs.confidence for vs in vector_scores}
    score_by_vector = {vs.vector: vs.score_0_100 for vs in vector_scores}

    # Accumulate per-vector lift
    per_vector_lift: dict[ThreatVector, float] = {v: 0.0 for v in ThreatVector}
    per_vector_drivers: dict[ThreatVector, list[tuple[str, float]]] = defaultdict(list)
    for driver_value, contribs in contribs_map.items():
        weight = driver_weights.get(driver_value, 0.0)
        for c in contribs:
            vec = ThreatVector(c["vector"])
            lift = max(0.0, (c["per_vector_mult"] - 1.0)) * 100.0 * weight
            per_vector_lift[vec] += lift
            if c["per_vector_mult"] > 1.05:
                per_vector_drivers[vec].append((driver_value, c["per_vector_mult"]))

    ranked = sorted(per_vector_lift.items(), key=lambda kv: kv[1], reverse=True)
    out: list[LikelihoodDriver] = []
    for vec, pts in ranked[:top_n]:
        if pts <= 0.0:
            continue
        affected = per_vector_drivers.get(vec, [])
        affected.sort(key=lambda x: x[1], reverse=True)
        affected_drivers = []
        for dv, _m in affected[:3]:
            try:
                affected_drivers.append(LossDriver(dv))
            except ValueError:
                continue
        score = score_by_vector.get(vec, 0.0)
        conf = conf_by_vector.get(vec, Confidence.LOW)
        rationale = (
            f"Vector score {score:.0f}/100 lifts the frequency of "
            f"{', '.join(d.value for d in affected_drivers) or 'multiple drivers'}."
        )
        out.append(
            LikelihoodDriver(
                vector=vec,
                contribution_pts=round(pts, 2),
                confidence=conf,
                drivers_affected=affected_drivers,
                rationale=rationale,
            )
        )
    return out


def _intel_posture_signals(intel: CompanyIntelSnapshot | None) -> list[PostureSignal]:
    """Translate per-assessment public intel into Coalition-style posture rows."""
    if intel is None:
        return []
    out: list[PostureSignal] = []
    n_breach = len(intel.breach_mentions or [])
    n_reg = len(intel.regulatory_actions or [])
    n_exec = len(intel.executive_changes or [])
    out.append(PostureSignal(
        name="Recent Adverse Media",
        status="AT_RISK" if n_breach > 0 else "SECURE",
        count=n_breach,
        detail=(f"{n_breach} breach/fraud-tagged article(s) in Proshare/BusinessDay search"
                if n_breach else "No recent breach or fraud mentions surfaced in public intel."),
    ))
    out.append(PostureSignal(
        name="Regulator Action",
        status="AT_RISK" if n_reg > 0 else "SECURE",
        count=n_reg,
        detail=(f"{n_reg} regulator-tagged article(s)" if n_reg
                else "No regulatory actions surfaced."),
    ))
    if n_exec >= 2:
        out.append(PostureSignal(
            name="Executive Churn",
            status="AT_RISK",
            count=n_exec,
            detail=f"{n_exec} executive change article(s) in recent public intel.",
        ))
    return out


@dataclass
class _IncidentCandidate:
    key: str
    label: str
    drivers: list[str]
    vector: str
    sectors: list[str] | None = None          # None = all sectors
    evidence_signals: list[str] = field(default_factory=list)  # substrings in finding titles/sources


_INCIDENT_CANDIDATES: list[_IncidentCandidate] = [
    _IncidentCandidate(
        key="ransomware", label="Ransomware Risk",
        drivers=["cyber_extortion"], vector="unpatched_vulnerabilities",
    ),
    _IncidentCandidate(
        key="ddos", label="DDoS Risk",
        drivers=["business_interruption"], vector="ddos_resilience",
        evidence_signals=["udp", "amplification", "ddos"],
    ),
    _IncidentCandidate(
        key="data_breach", label="Data Breach Risk",
        drivers=["privacy_liability", "data_recovery"], vector="credential_secrets_exposure",
    ),
    _IncidentCandidate(
        key="insider_threat", label="Insider Threat Risk",
        drivers=["privacy_liability"], vector="insider_risk",
    ),
    _IncidentCandidate(
        key="phishing", label="Phishing / BEC Risk",
        drivers=["social_engineering", "funds_transfer_fraud"], vector="email_hygiene",
    ),
    _IncidentCandidate(
        key="compliance", label="Compliance Risk",
        drivers=["regulatory_penalties"], vector="data_protection",
    ),
    _IncidentCandidate(
        key="mobile_money", label="Mobile Money Fraud",
        drivers=["computer_fraud", "funds_transfer_fraud"], vector="mobile_agent_network",
        sectors=["banking", "fintech", "pension"],
    ),
    _IncidentCandidate(
        key="supply_chain", label="Supply Chain / Third-Party Risk",
        drivers=["network_sec_liability"], vector="third_party_supply_chain",
        evidence_signals=["third_party", "supplier", "vendor", "api_key", "third-party"],
    ),
    _IncidentCandidate(
        key="cloud_compromise", label="Cloud Misconfiguration Risk",
        drivers=["data_recovery", "privacy_liability"], vector="cloud_misconfiguration",
        evidence_signals=["azure", "aws", "gcp", "blob", "s3", "bucket", "cloud"],
    ),
    _IncidentCandidate(
        key="web_app", label="Web Application Attack Risk",
        drivers=["network_sec_liability", "data_recovery"], vector="web_application_weaknesses",
        evidence_signals=["sql injection", "xss", "brute force", "csrf", "injection",
                          "cross-site", "owasp", "web application"],
    ),
    _IncidentCandidate(
        key="pci", label="Card Fraud / PCI Risk",
        drivers=["pci_fines", "computer_fraud"], vector="web_application_weaknesses",
        sectors=["banking", "fintech", "insurance"],
        evidence_signals=["pci", "card", "payment", "atm", "pos terminal"],
    ),
    _IncidentCandidate(
        key="medical_breach", label="Medical Records Breach",
        drivers=["privacy_liability", "regulatory_penalties"], vector="data_protection",
        sectors=["healthcare"],
        evidence_signals=["ehr", "emr", "patient", "medical", "health record", "phi"],
    ),
]

_MIN_EL_THRESHOLD_USD = 25_000.0   # show incident type if EL exceeds this
_MAX_SHOWN = 8                      # cap to avoid cluttering the report


def _incident_probabilities(
    actuarial: ActuarialResult,
    org: OrgProfile | None = None,
    findings: list[Finding] | None = None,
) -> list[IncidentProbabilityItem]:
    """Dynamically select and score incident types from the 12-candidate pool.

    An incident type is included when ANY of:
      - Blended probability >= 30%
      - Driver expected annual loss > $25k
      - Org sector matches the candidate's sectors list
      - Any finding title/source matches a candidate evidence signal

    Results are sorted by probability descending and capped at 8.
    """
    driver_map: dict[str, float] = {
        d.driver.value: d.annual_frequency_mean for d in actuarial.per_driver
    }
    driver_el_map: dict[str, float] = {
        d.driver.value: d.expected_annual_loss_usd for d in actuarial.per_driver
    }
    vector_map: dict[str, float] = {}
    for vs in (actuarial.vector_scores or []):
        vk = vs.vector.value if hasattr(vs.vector, "value") else str(vs.vector)
        vector_map[vk] = vs.score_0_100

    org_sector = (org.sector.value if org and hasattr(org.sector, "value")
                  else (str(org.sector) if org else "other"))

    # Pre-compute a single string of all finding titles + sources for signal matching
    finding_text = ""
    if findings:
        finding_text = " ".join(
            f"{(f.title or '')} {(f.source or '')}".lower() for f in findings
        )

    def _poisson_prob(lam: float) -> float:
        return 0.0 if lam <= 0 else 1.0 - math.exp(-lam)

    def _blend(driver_keys: list[str], vector_key: str) -> float:
        lam = max((driver_map.get(k, 0.0) for k in driver_keys), default=0.0)
        p_poisson = _poisson_prob(lam)
        vec_score = vector_map.get(vector_key, 0.0) / 100.0
        blended = 0.65 * p_poisson + 0.35 * vec_score
        return round(max(0.05, min(0.95, blended)) * 100, 1)

    results: list[IncidentProbabilityItem] = []

    for candidate in _INCIDENT_CANDIDATES:
        prob = _blend(candidate.drivers, candidate.vector)

        # Max EL across relevant drivers
        max_el = max((driver_el_map.get(k, 0.0) for k in candidate.drivers), default=0.0)

        # Sector match
        sector_match = (
            candidate.sectors is None or org_sector in candidate.sectors
        )

        # Evidence signal match
        signal_match = any(sig in finding_text for sig in candidate.evidence_signals)

        # Evidence signal match boosts probability so the finding-backed type
        # is competitive with actuarial-driven candidates in the top-8 sort.
        if signal_match:
            prob = max(prob, 35.0)

        # Include if any condition is met
        if prob >= 30.0 or max_el >= _MIN_EL_THRESHOLD_USD or (
            candidate.sectors and sector_match
        ) or signal_match:
            results.append(IncidentProbabilityItem(
                key=candidate.key,
                label=candidate.label,
                probability_pct=prob,
            ))

    # Sort by probability descending, cap at MAX_SHOWN
    results.sort(key=lambda x: x.probability_pct, reverse=True)
    return results[:_MAX_SHOWN]


def _public_intel_payload(intel: CompanyIntelSnapshot | None) -> dict:
    """Compact dict surfaced on RiskSummary.public_intel for the PDF template."""
    if intel is None:
        return {}

    def _top(items: list[dict], k: int = 8) -> list[dict]:
        out = []
        for it in (items or [])[:k]:
            if not isinstance(it, dict):
                continue
            out.append({
                "title": it.get("title", "(untitled)"),
                "url": it.get("url", ""),
                "source": it.get("source") or it.get("_source") or "",
                "tags": it.get("tags") or [],
                "published": it.get("published") or it.get("date") or "",
            })
        return out

    return {
        "counts": {
            "headlines": len(intel.recent_news or []),
            "breach_mentions": len(intel.breach_mentions or []),
            "regulatory_actions": len(intel.regulatory_actions or []),
            "executive_changes": len(intel.executive_changes or []),
        },
        "headlines": _top(intel.recent_news, 12),
        "breach_mentions": _top(intel.breach_mentions, 6),
        "regulatory_actions": _top(intel.regulatory_actions, 6),
        "executive_changes": _top(intel.executive_changes, 6),
        "sources": ["proshare", "businessday_intelligence"],
    }


def build_risk_summary(
    org: OrgProfile,
    scoring: ScoringResult,
    actuarial: ActuarialResult,
    findings: list[Finding] | None = None,
    intel: CompanyIntelSnapshot | None = None,
) -> RiskSummary:
    findings = findings or []

    # Risk score = inverse of CIDA overall score, clipped to [0, 100].
    risk_score = round(max(0.0, min(100.0, 100.0 - scoring.overall_score)), 1)

    # Likelihood multiplier vs peer baseline (both derived from vector matrix).
    org_mult = max(actuarial.avg_control_modifier, 0.01)
    peer_mult = max(actuarial.avg_peer_baseline_multiplier, 0.01)
    likelihood_mult = round(org_mult / peer_mult, 2)

    # Org total annual frequency (sum of per-driver means) & peer baseline.
    org_total_freq = sum(d.annual_frequency_mean for d in actuarial.per_driver)
    peer_baseline = round(org_total_freq / max(likelihood_mult, 1e-6), 4) if likelihood_mult > 0 else org_total_freq

    incident_probs = _incident_probabilities(actuarial, org=org, findings=findings)

    return RiskSummary(
        risk_score=risk_score,
        risk_band=_band_for(risk_score),
        incident_probabilities=incident_probs,
        likelihood_multiplier_vs_peer=likelihood_mult,
        peer_baseline_annual_frequency=round(peer_baseline, 4),
        org_total_annual_frequency=round(org_total_freq, 4),
        composite_loss_p50_usd=actuarial.aggregate_loss_p50_usd,
        composite_loss_p90_usd=actuarial.aggregate_loss_p90_usd,
        composite_loss_p99_usd=actuarial.aggregate_loss_p99_usd,
        attack_surface=_attack_surface(org, findings),
        finding_counts=_finding_counts(findings),
        posture_signals=_posture_signals(findings) + _intel_posture_signals(intel),
        grouped_findings=_grouped_findings(findings),
        vector_scores=actuarial.vector_scores or [],
        top_likelihood_drivers=_top_likelihood_drivers(actuarial),
        public_intel=_public_intel_payload(intel),
        intel_fetched_at=(intel.fetched_at if intel else None),
    )
