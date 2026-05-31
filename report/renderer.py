"""Render CIDAReport to JSON and PDF (HTML → WeasyPrint).

Two report types are produced:
  - Underwriting scorecard (report.html.j2)  → render_pdf() / render_html()
  - Policyholder Report    (policyholder_report.html.j2) → render_policyholder_report()
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from actuarial.model import ActuarialResult
from actuarial.premium import compute_premium
from config.loader import context_for
from enrich.calibration import calibrate_score
from ml.anomaly import detect_anomalies
from ml.breach_classifier import compute_breach_probabilities
from ml.modifier import predict_modifier
from ml.peer_store import _peer_store
from models import (
    CIDAReport,
    CompanyIntelSnapshot,
    Finding,
    OrgProfile,
    PremiumRecommendation,
    QuestionnaireResponses,
    Sector,
)
from posture.compliance import build_remediation_roadmap, compute_posture
from scoring.engine import ScoringResult
from scoring.risk_summary import build_risk_summary

TEMPLATE_DIR = Path(__file__).parent / "templates"

_MAX_THUMB_BYTES = 500_000   # 500 KB max base64 embed per image


def build_report(
    org: OrgProfile,
    responses: QuestionnaireResponses,
    scoring: ScoringResult,
    actuarial: ActuarialResult,
    findings: list | None = None,
    intel: CompanyIntelSnapshot | None = None,
    intel_summary: dict | None = None,
    apply_ml_modifier: bool = True,
    assessment_limitations: list[str] | None = None,
    evidence_images: list | None = None,
    unclassified_files: list[dict] | None = None,
) -> CIDAReport:
    try:
        country_ctx = context_for(org.country)
    except FileNotFoundError:
        country_ctx = None

    # Apply ML residual modifier (1.0 if no trained model exists)
    ml_mod = 1.0
    if apply_ml_modifier:
        try:
            ml_mod = predict_modifier(org, responses, findings or [], actuarial)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] ML modifier failed: {e}; using 1.0")

    if ml_mod != 1.0:
        # Scale aggregate + per-driver expected losses; leave VaR/TVaR ratios intact
        actuarial.aggregate_expected_loss_usd *= ml_mod
        actuarial.aggregate_var_95_usd *= ml_mod
        actuarial.aggregate_tvar_99_usd *= ml_mod
        for d in actuarial.per_driver:
            d.expected_annual_loss_usd *= ml_mod
            d.var_95_usd *= ml_mod
            d.tvar_99_usd *= ml_mod
        actuarial.inputs_used["ml_modifier"] = ml_mod

    posture = compute_posture(
        responses,
        Sector(org.sector) if not isinstance(org.sector, Sector) else org.sector,
        country_ctx,
    )

    driver_el_map = {d.driver.value: d.expected_annual_loss_usd for d in actuarial.per_driver}
    remediation = build_remediation_roadmap(responses, driver_el_map)

    premium: PremiumRecommendation = compute_premium(
        actuarial,
        Sector(org.sector) if not isinstance(org.sector, Sector) else org.sector,
        org.annual_revenue_usd,
        scoring.overall_score,
        local_currency=country_ctx.country.currency if country_ctx else org.local_currency,
    )

    risk_summary = build_risk_summary(org, scoring, actuarial, findings or [], intel=intel)

    # --- Derive Policyholder Report fields from findings ---
    all_findings = findings or []
    compromised_emails = _extract_compromised_emails(all_findings)
    dns_records = _extract_dns_records(all_findings)

    # --- Evidence images: generate base64 thumbnails ---
    evidence_image_dicts = _build_evidence_image_dicts(evidence_images or [])

    # --- Predictive modeling features ---
    sector_val = Sector(org.sector) if not isinstance(org.sector, Sector) else org.sector

    # Feature 1: Breach probability classifier
    breach_probs: dict = {}
    try:
        bp = compute_breach_probabilities(actuarial, scoring, sector=sector_val)
        breach_probs = bp.to_dict()
    except Exception as e:  # noqa: BLE001
        print(f"[warn] Breach probability computation failed: {e}")

    # Feature 2: Score calibration against dark web / credential evidence
    calibration_flags: list[dict] = []
    ci_low = scoring.overall_score_ci_low
    ci_high = scoring.overall_score_ci_high
    try:
        cal = calibrate_score(scoring, all_findings, org)
        calibration_flags = [f.__dict__ if hasattr(f, "__dict__") else f for f in cal.flags]
        calibration_flags = [
            {"flag_type": f.flag_type, "description": f.description,
             "severity": f.severity, "recommendation": f.recommendation}
            for f in cal.flags
        ]
        ci_low = cal.adjusted_ci_low
        ci_high = cal.adjusted_ci_high
    except Exception as e:  # noqa: BLE001
        print(f"[warn] Score calibration failed: {e}")

    # Feature 3: VAPT narrative context (extracted upstream in parse_vapt_pdf;
    # assembled here from finding metadata if available)
    assessment_context: dict = {}

    # Feature 4: Anomaly detection on questionnaire responses
    anomaly_flags: list[dict] = []
    try:
        flags = detect_anomalies(responses, all_findings, scoring, sector=sector_val)
        anomaly_flags = [
            {"flag_type": f.flag_type, "description": f.description,
             "affected_domain": f.affected_domain, "severity": f.severity,
             "recommendation": f.recommendation}
            for f in flags
        ]
    except Exception as e:  # noqa: BLE001
        print(f"[warn] Anomaly detection failed: {e}")

    # Feature 5: Peer benchmarking
    peer_comparison: dict = {}
    try:
        pc = _peer_store.get_percentiles(sector_val, org.country, scoring)
        peer_comparison = pc.to_dict()
        # Record this assessment for future peer comparisons (anonymised)
        _peer_store.record(sector_val, org.country, scoring)
    except Exception as e:  # noqa: BLE001
        print(f"[warn] Peer benchmarking failed: {e}")

    return CIDAReport(
        org=org,
        generated_at=datetime.now(tz=timezone.utc),
        overall_score=scoring.overall_score,
        overall_score_ci_low=ci_low,
        overall_score_ci_high=ci_high,
        tier=scoring.tier,
        domain_scores=scoring.domain_scores,
        loss_estimates=actuarial.per_driver,
        aggregate_expected_loss_usd=actuarial.aggregate_expected_loss_usd,
        aggregate_var_95_usd=actuarial.aggregate_var_95_usd,
        aggregate_tvar_99_usd=actuarial.aggregate_tvar_99_usd,
        risk_summary=risk_summary,
        premium=premium,
        posture=posture,
        remediation=remediation,
        findings_summary=scoring.findings_summary,
        intel_summary=intel_summary or {},
        # Policyholder report fields
        compromised_emails=compromised_emails,
        dns_records=dns_records,
        assessment_limitations=assessment_limitations or [],
        evidence_images=evidence_image_dicts,
        unclassified_files=unclassified_files or [],
        # Predictive modeling outputs
        breach_probabilities=breach_probs,
        calibration_flags=calibration_flags,
        anomaly_flags=anomaly_flags,
        peer_comparison=peer_comparison,
        assessment_context=assessment_context,
    )


def _extract_compromised_emails(findings: list[Finding]) -> list[str]:
    emails: list[str] = []
    email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    for f in findings:
        src = (f.source or "").lower()
        title = (f.title or "").lower()
        if ("darkweb" in src or "credleak" in src or "stealer" in src
                or "compromised" in title or "credential" in title or "leaked" in title):
            # Try to extract from asset, evidence, description
            for text in [f.asset, f.evidence or "", f.description]:
                if text:
                    emails.extend(email_re.findall(text))
    # Deduplicate preserving order
    seen: set[str] = set()
    return [e for e in emails if not (e in seen or seen.add(e))]  # type: ignore[func-returns-value]


def _extract_dns_records(findings: list[Finding]) -> dict[str, list[str]]:
    dns: dict[str, list[str]] = {}
    for f in findings:
        src = (f.source or "").lower()
        if "attack_surface" in src or "asm" in src or "amass" in src:
            raw = f.raw or {}
            for rtype in ("A", "MX", "NS", "CNAME", "TXT"):
                vals = raw.get(rtype) or raw.get(rtype.lower())
                if isinstance(vals, list) and vals:
                    dns.setdefault(rtype, []).extend(str(v) for v in vals)
    return dns


def _build_evidence_image_dicts(evidence_images: list) -> list[dict]:
    """Convert EvidenceImage objects to template-friendly dicts with optional base64 thumbs."""
    out = []
    for img in evidence_images:
        d: dict = {
            "filename": img.filename,
            "caption": img.caption,
            "size_bytes": img.size_bytes,
            "ext": img.path.suffix.lstrip(".").lower() if hasattr(img, "path") else "png",
            "b64_thumb": None,
        }
        try:
            path = img.path if hasattr(img, "path") else None
            if path and path.exists():
                file_bytes = path.read_bytes()
                if len(file_bytes) <= _MAX_THUMB_BYTES:
                    # Try to resize if Pillow available; else embed raw
                    try:
                        from PIL import Image as PILImage
                        import io as _io
                        with PILImage.open(_io.BytesIO(file_bytes)) as pil_img:
                            pil_img.thumbnail((800, 600))
                            buf = _io.BytesIO()
                            fmt = "PNG" if d["ext"] in ("png", "svg") else "JPEG"
                            pil_img.save(buf, format=fmt)
                            d["b64_thumb"] = base64.b64encode(buf.getvalue()).decode()
                            d["ext"] = fmt.lower()
                    except ImportError:
                        d["b64_thumb"] = base64.b64encode(file_bytes).decode()
        except Exception:
            pass
        out.append(d)
    return out


def _make_jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["fmt_usd"] = lambda v: f"${v:,.0f}" if isinstance(v, (int, float)) else v
    env.filters["fmt_pct"] = lambda v: f"{v:.1f}%" if isinstance(v, (int, float)) else v
    env.filters["fmt_num"] = lambda v: f"{v:,.2f}" if isinstance(v, (int, float)) else v
    return env


def render_json(report: CIDAReport, out_path: str | Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return out_path


def render_html(report: CIDAReport, out_path: str | Path | None = None) -> str:
    env = _make_jinja_env()
    tmpl = env.get_template("report.html.j2")
    html = tmpl.render(report=report)
    if out_path:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
    return html


def render_policyholder_html(
    report: CIDAReport,
    findings: list | None = None,
    out_path: str | Path | None = None,
) -> str:
    """Render the Policyholder Report to HTML."""
    env = _make_jinja_env()
    tmpl = env.get_template("policyholder_report.html.j2")
    html = tmpl.render(report=report, findings=findings or [])
    if out_path:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
    return html


def render_policyholder_pdf(
    report: CIDAReport,
    findings: list | None = None,
    out_path: str | Path | None = None,
) -> Path:
    """Render Policyholder Report to PDF."""
    html = render_policyholder_html(report, findings=findings)
    if out_path is None:
        slug = re.sub(r"[^\w]", "_", report.org.name.lower())[:32]
        out_path = Path(f"{slug}_policyholder_report.pdf")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from weasyprint import HTML
        HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(out_path))
        return out_path
    except Exception as e:
        weasy_err = e

    try:
        from xhtml2pdf import pisa
        with open(out_path, "wb") as f:
            result = pisa.CreatePDF(html, dest=f)
        if not result.err:
            return out_path
    except Exception as e:
        print(f"[warn] xhtml2pdf unavailable ({e}); WeasyPrint err: {weasy_err}")

    html_path = out_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    return html_path


def render_pdf(report: CIDAReport, out_path: str | Path) -> Path:
    """Render to PDF - tries WeasyPrint first, then xhtml2pdf (pure-Python fallback),
    then writes HTML as last resort. Works cross-platform without native deps."""
    html = render_html(report)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Attempt 1: WeasyPrint (best output; needs GTK on Windows)
    try:
        from weasyprint import HTML
        HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(out_path))
        return out_path
    except Exception as e:
        weasy_err = e

    # Attempt 2: xhtml2pdf (pure Python; works on Windows out of the box)
    try:
        from xhtml2pdf import pisa
        with open(out_path, "wb") as f:
            result = pisa.CreatePDF(html, dest=f)
        if not result.err:
            return out_path
        print(f"[warn] xhtml2pdf reported {result.err} errors")
    except Exception as e:
        print(f"[warn] xhtml2pdf unavailable ({e}); WeasyPrint err: {weasy_err}")

    # Last resort: write HTML
    html_path = out_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    return html_path
