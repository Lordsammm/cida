"""Per-framework compliance posture + remediation roadmap.

Posture: % of controls in the catalog mapped to a given framework that are
"aligned" (score >= 70).

Remediation: rank failing controls by (uplift × loss reduction estimate / effort).
"""
from __future__ import annotations

from cida.catalog.loader import load_catalog
from cida.config.loader import CountryContext, load_sector
from cida.models import (
    Control,
    Domain,
    FrameworkPosture,
    QuestionnaireResponses,
    RemediationItem,
    Sector,
)


ALIGNED_THRESHOLD = 70.0

# All frameworks we crosswalk to
FRAMEWORKS = [
    "nist_csf_2_0",
    "nist_sp_800_53_r5",
    "iso_27001_2022",
    "cis_v8",
    "soc2_tsc",
    "pci_dss_v4",
    "hipaa_security",
    "gdpr",
    "ndpr_ndpa",
    "ccpa",
    "popia",
    "malabo",
    "fsca_js1_2023",
]


def _control_aligns(c: Control, framework: str) -> bool:
    cw = getattr(c.crosswalk, framework, [])
    return bool(cw)


def compute_posture(
    responses: QuestionnaireResponses,
    sector: Sector,
    country_ctx: CountryContext | None,
) -> list[FrameworkPosture]:
    catalog = load_catalog()
    control_scores = {r.control_id: r.score for r in responses.responses}

    # Sector-required + country-applicable frameworks
    sector_cfg = load_sector(sector.value if hasattr(sector, "value") else sector)
    required = set(sector_cfg.required_frameworks)
    if country_ctx and country_ctx.country.iso_a2 == "ZA":
        required.add("fsca-js1-2023")

    # Always evaluate the common stack
    framework_set = set(FRAMEWORKS) | {f.replace("-", "_").replace(".", "_") for f in required}

    out: list[FrameworkPosture] = []
    for fw in sorted(framework_set):
        controls_in_fw = [c for c in catalog.controls if _control_aligns(c, fw)]
        if not controls_in_fw:
            continue
        aligned = 0
        gaps: list[str] = []
        for c in controls_in_fw:
            s = control_scores.get(c.control_id, 0.0)
            if s >= ALIGNED_THRESHOLD:
                aligned += 1
            else:
                gaps.append(c.control_id)
        coverage = 100.0 * aligned / len(controls_in_fw)
        out.append(FrameworkPosture(
            framework=fw,
            coverage_pct=round(coverage, 1),
            controls_aligned=aligned,
            controls_total=len(controls_in_fw),
            top_gaps=gaps[:5],
        ))
    return out


def build_remediation_roadmap(
    responses: QuestionnaireResponses,
    actuarial_per_driver: dict,
    max_items: int = 10,
) -> list[RemediationItem]:
    """Rank failing controls by (uplift × loss-reduction / effort)."""
    catalog = load_catalog()
    control_scores = {r.control_id: r.score for r in responses.responses}

    candidates: list[tuple[Control, float, float]] = []  # (control, uplift, loss_reduction)
    for c in catalog.controls:
        score = control_scores.get(c.control_id, 0.0)
        if score >= ALIGNED_THRESHOLD:
            continue
        # Uplift potential: how many points would we add if this control reached 100?
        uplift = (100 - score) * c.weight * 0.5  # 0.5 normalization heuristic
        # Loss reduction: sum of (driver_EL × (modifier-1)/modifier) for each driver this control influences
        loss_red = 0.0
        for driver, mod in c.loss_driver_modifiers.items():
            driver_el = actuarial_per_driver.get(driver.value if hasattr(driver, "value") else driver, 0.0)
            if mod > 1.0:
                loss_red += driver_el * (mod - 1.0) / mod
        candidates.append((c, uplift, loss_red))

    # Score each: higher uplift × higher $ reduction × lower effort = higher rank
    def _effort_for(c: Control) -> str:
        # Heuristic: if response_type=yes_no and weight high → high impact, likely medium effort
        if c.weight >= 1.5:
            return "medium"
        return "low" if c.weight < 1.0 else "medium"

    effort_factor = {"low": 1.0, "medium": 0.7, "high": 0.4}

    ranked = sorted(
        candidates,
        key=lambda t: (t[1] + t[2] / 10_000.0) * effort_factor[_effort_for(t[0])],
        reverse=True,
    )[:max_items]

    items: list[RemediationItem] = []
    for rank, (c, uplift, loss_red) in enumerate(ranked, start=1):
        citations: list[str] = []
        for fw in ["nist_csf_2_0", "iso_27001_2022", "cis_v8"]:
            refs = getattr(c.crosswalk, fw, [])
            if refs:
                citations.extend([f"{fw.upper()}:{r}" for r in refs[:2]])
        items.append(RemediationItem(
            control_id=c.control_id,
            title=c.question_text[:140],
            domain=c.domain,
            score_uplift_potential=round(uplift, 1),
            annual_loss_reduction_usd=round(loss_red, 2),
            effort=_effort_for(c),
            priority_rank=rank,
            framework_citations=citations[:6],
        ))
    return items
