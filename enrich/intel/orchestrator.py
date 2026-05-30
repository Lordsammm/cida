"""Per-assessment public-intelligence orchestrator.

For each insured we run all available org-specific intel adapters
(Proshare + BusinessDay today; HackerNews / HIBP / sanctions lists in
the future), merge their findings into a single `CompanyIntelSnapshot`,
and hand it to the actuarial + risk-summary layers.

CRITICAL: every adapter MUST return an empty snapshot on failure rather
than raising - a flaky news site cannot block an underwriting run.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from enrich.intel.base import IntelSource
from enrich.intel.businessday import BusinessDayAdapter
from enrich.intel.proshare import ProshareAdapter
from models import CompanyIntelSnapshot, OrgProfile

# Keywords for classifying news headlines into actionable buckets.
_BREACH_KEYWORDS = {
    "breach", "hack", "hacked", "ransomware", "cyber attack", "cyberattack",
    "data leak", "data leaked", "phishing", "credential stuffing", "stealer",
    "extortion", "wiped", "compromised", "intrusion",
}
_FRAUD_KEYWORDS = {
    "fraud", "embezzlement", "stolen", "wire fraud", "bec scam",
    "ussd fraud", "ATM fraud", "card skimming", "scam",
}
_REGULATORY_KEYWORDS = {
    "fine", "fined", "sanction", "penalty", "penalised", "penalized",
    "investigation", "probe", "regulator", "ndpc", "naicom", "popia",
    "info regulator", "cbn directive", "cma kenya", "ssnit",
}
_EXEC_CHANGE_KEYWORDS = {
    "resigns", "resignation", "steps down", "appointed", "new ceo",
    "new cto", "new ciso", "new cfo", "departs", "dismissed", "sacked",
}


def _classify(title: str) -> set[str]:
    t = (title or "").lower()
    tags = set()
    if any(k in t for k in _BREACH_KEYWORDS):
        tags.add("breach")
    if any(k in t for k in _FRAUD_KEYWORDS):
        tags.add("fraud")
    if any(k in t for k in _REGULATORY_KEYWORDS):
        tags.add("regulatory")
    if any(k in t for k in _EXEC_CHANGE_KEYWORDS):
        tags.add("exec_change")
    return tags


def _default_sources() -> list[IntelSource]:
    return [ProshareAdapter(), BusinessDayAdapter()]


def gather_company_intel(
    org: OrgProfile,
    offline: bool = False,
    sources: list[IntelSource] | None = None,
) -> CompanyIntelSnapshot:
    """Run all adapters concurrently-friendly (sequential for simplicity)
    and produce a merged snapshot. Returns an empty snapshot when offline.
    """
    merged = CompanyIntelSnapshot(
        org_name=org.name,
        source="merged",
        fetched_at=datetime.now(tz=timezone.utc),
    )
    if offline:
        return merged

    sources = sources if sources is not None else _default_sources()
    seen_urls: set[str] = set()

    for src in sources:
        try:
            snap = src.fetch(org.name, country=org.country)
        except Exception as e:  # noqa: BLE001 - never let intel crash scoring
            print(f"[warn] intel source {src.name} raised: {e}")
            continue

        # Tag and merge news; classify into actionable buckets.
        for article in snap.recent_news or []:
            url = article.get("url")
            if url and url in seen_urls:
                continue
            seen_urls.add(url)
            tagged = dict(article)
            tagged.setdefault("source", snap.source)
            tagged["tags"] = sorted(_classify(article.get("title", "")))
            merged.recent_news.append(tagged)
            if "breach" in tagged["tags"] or "fraud" in tagged["tags"]:
                merged.breach_mentions.append(tagged)
            if "regulatory" in tagged["tags"]:
                merged.regulatory_actions.append(tagged)
            if "exec_change" in tagged["tags"]:
                merged.executive_changes.append(tagged)

        # Adapter-supplied structured signals win (richer than headline tagging).
        for k, dest in (
            ("breach_mentions", merged.breach_mentions),
            ("regulatory_actions", merged.regulatory_actions),
            ("executive_changes", merged.executive_changes),
        ):
            for item in getattr(snap, k, []) or []:
                url = item.get("url") if isinstance(item, dict) else None
                if url and url in seen_urls:
                    continue
                if url:
                    seen_urls.add(url)
                dest.append({**item, "source": snap.source} if isinstance(item, dict) else item)

        # First non-empty financials wins.
        if not merged.financials and snap.financials:
            merged.financials = snap.financials

    return merged


# ---------------------------------------------------------------------------
# Translating a snapshot into actuarial signals.
# ---------------------------------------------------------------------------

# Driver-level frequency multipliers triggered by intel signals.
# Conservative - these compound on top of vector-derived multipliers.
INTEL_DRIVER_LIFTS = {
    "any_breach_mention":    {"privacy_liability": 1.50, "network_sec_liability": 1.30},
    "many_breach_mentions":  {"privacy_liability": 2.00, "cyber_extortion": 1.30, "data_recovery": 1.25},
    "regulatory_action":     {"regulatory_penalties": 1.60, "privacy_liability": 1.15},
    "many_regulatory":       {"regulatory_penalties": 2.20, "privacy_liability": 1.30},
    "fraud_mention":         {"funds_transfer_fraud": 1.40, "computer_fraud": 1.30, "social_engineering": 1.20},
    "exec_churn":            {},  # surfaces in insider_risk vector instead
}


@dataclass
class IntelImpact:
    """Aggregated, per-driver multipliers + per-vector score adders derived
    from a `CompanyIntelSnapshot`. Consumed by the actuarial model and
    risk-summary builder.
    """
    driver_multipliers: dict[str, float]   # driver_value -> combined mult
    vector_score_uplift: dict[str, float]  # vector_value -> additive points (0..100)
    signals: list[str]                     # human-readable provenance


def derive_intel_impact(snap: CompanyIntelSnapshot | None) -> IntelImpact:
    """Translate a snapshot into multiplicative driver lifts + vector uplift.

    Conservative defaults; everything caps at the existing per-driver
    `per_driver_cap` enforced in the vector-matrix product so combined
    behaviour stays bounded.
    """
    impact = IntelImpact(driver_multipliers={}, vector_score_uplift={}, signals=[])
    if snap is None:
        return impact

    n_breach = len(snap.breach_mentions or [])
    n_reg = len(snap.regulatory_actions or [])
    n_exec = len(snap.executive_changes or [])
    fraud_hits = sum(1 for a in (snap.recent_news or []) if "fraud" in (a.get("tags") or []))

    def _apply(rule_key: str, why: str):
        rule = INTEL_DRIVER_LIFTS.get(rule_key, {})
        if not rule:
            return
        for d, m in rule.items():
            impact.driver_multipliers[d] = impact.driver_multipliers.get(d, 1.0) * m
        impact.signals.append(why)

    if n_breach >= 1:
        _apply("any_breach_mention", f"{n_breach} breach mention(s) in public intel")
    if n_breach >= 3:
        _apply("many_breach_mentions", f"{n_breach} breach mentions (elevated pattern)")
    if n_reg >= 1:
        _apply("regulatory_action", f"{n_reg} regulator action(s) in public intel")
    if n_reg >= 2:
        _apply("many_regulatory", f"{n_reg} regulator actions (pattern)")
    if fraud_hits >= 1:
        _apply("fraud_mention", f"{fraud_hits} fraud mention(s) in public intel")

    # Executive churn → +pts on insider_risk vector (additive, capped at +25)
    if n_exec >= 3:
        impact.vector_score_uplift["insider_risk"] = min(25.0, 5.0 * (n_exec - 2))
        impact.signals.append(f"{n_exec} executive change(s) in 24 mo - insider_risk uplift")
    elif n_exec == 2:
        impact.vector_score_uplift["insider_risk"] = 5.0
        impact.signals.append("2 executive changes - minor insider_risk uplift")

    # Breach mentions also degrade credential_secrets_exposure confidence:
    # we bump its score by +10 to reflect that something already leaked.
    if n_breach >= 1:
        impact.vector_score_uplift["credential_secrets_exposure"] = (
            impact.vector_score_uplift.get("credential_secrets_exposure", 0.0) + 10.0
        )

    return impact
