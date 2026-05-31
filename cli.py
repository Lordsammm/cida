"""CIDA command-line interface.

Examples:
    cida demo --out report.pdf
    cida score --questionnaire q.csv --findings findings/ --org-profile org.yaml --out report.pdf
    cida list-countries
    cida list-regulators --kind insurance
"""
from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

from actuarial.model import run_actuarial_model
from backtest.runner import run_backtest, save_results
from config.loader import list_countries as _list_countries, list_regulators as _list_regulators
from enrich.cve import enrich_findings
from enrich.intel import gather_company_intel
from ingest.cida_docx import ingest_cida_docx
from ingest.findings import load_findings_from_dir
from ingest.questionnaire import parse_questionnaire_csv
from models import OrgProfile
from report.renderer import (
    build_report, render_html, render_json, render_pdf,
    render_policyholder_html, render_policyholder_pdf,
)
from scoring.engine import score_organization


app = typer.Typer(add_completion=False, help="CIDA - Cyber Intelligence Decision Algorithm")


def _load_org_profile(path: Path) -> OrgProfile:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return OrgProfile.model_validate(data)


@app.command()
def score(
    questionnaire: Path = typer.Option(..., "--questionnaire", "-q", exists=True, help="Filled questionnaire CSV"),
    org_profile: Path = typer.Option(..., "--org-profile", "-o", exists=True, help="Organization profile YAML"),
    findings: Path | None = typer.Option(None, "--findings", "-f", help="Directory with VAPT / scanner outputs"),
    out: Path = typer.Option(Path("./out/report.pdf"), "--out", help="Output PDF path"),
    offline: bool = typer.Option(False, "--offline", help="Skip CVE/EPSS/KEV enrichment"),
    seed: int = typer.Option(42, "--seed", help="Monte Carlo seed"),
) -> None:
    """Run a full CIDA assessment end-to-end and emit JSON + PDF."""
    typer.echo(f"[cida] Loading org profile from {org_profile}")
    org = _load_org_profile(org_profile)

    typer.echo(f"[cida] Parsing questionnaire {questionnaire}")
    responses = parse_questionnaire_csv(questionnaire, org_id=org.org_id)
    typer.echo(f"[cida] Parsed {len(responses.responses)} responses.")

    found = []
    if findings:
        typer.echo(f"[cida] Loading findings from {findings}")
        found = load_findings_from_dir(findings, org_email_domains=org.email_domains)
        typer.echo(f"[cida] Loaded {len(found)} findings; enriching with CVE/EPSS/KEV...")
        found = enrich_findings(found, offline=offline)

    typer.echo("[cida] Scoring...")
    scoring = score_organization(responses, found)
    typer.echo(f"[cida] Overall score = {scoring.overall_score}  (Tier {scoring.tier.tier} – {scoring.tier.label})")

    typer.echo(f"[cida] Fetching per-assessment public intelligence on '{org.name}' (Proshare + BusinessDay)...")
    intel = gather_company_intel(org, offline=offline)
    typer.echo(
        f"[cida] Intel: {len(intel.recent_news)} headlines, "
        f"{len(intel.breach_mentions)} breach/fraud, "
        f"{len(intel.regulatory_actions)} regulatory, "
        f"{len(intel.executive_changes)} exec changes"
    )

    typer.echo("[cida] Running Bayesian actuarial model + Monte Carlo (10,000 sims)...")
    actuarial = run_actuarial_model(org, responses, seed=seed, findings=found, intel=intel)
    typer.echo(f"[cida] Aggregate EL = ${actuarial.aggregate_expected_loss_usd:,.0f}")

    typer.echo("[cida] Building report...")
    report = build_report(org, responses, scoring, actuarial, findings=found, intel=intel)

    json_path = out.with_suffix(".json")
    render_json(report, json_path)
    typer.echo(f"[cida] JSON  -> {json_path}")

    pdf_path = render_pdf(report, out)
    typer.echo(f"[cida] PDF   -> {pdf_path}")

    html_out = out.with_suffix(".html")
    render_html(report, html_out)
    typer.echo(f"[cida] HTML  -> {html_out}")

    policyholder_html_out = out.with_name(out.stem + "_policyholder.html")
    render_policyholder_html(report, findings=found, out_path=policyholder_html_out)
    typer.echo(f"[cida] Policyholder HTML -> {policyholder_html_out}")


@app.command()
def demo(
    out: Path = typer.Option(Path("./out/demo_report.pdf"), "--out", help="Output PDF path"),
    offline: bool = typer.Option(True, "--offline", help="Skip live CVE/EPSS/KEV calls"),
) -> None:
    """Run a demo assessment using bundled sample data."""
    examples = Path(__file__).parent / "examples"
    score(
        questionnaire=examples / "sample_questionnaire.csv",
        org_profile=examples / "sample_org_profile.yaml",
        findings=examples / "sample_findings",
        out=out,
        offline=offline,
        seed=42,
    )


@app.command("score-doc")
def score_doc(
    doc: Path = typer.Option(..., "--doc", "-d", exists=True,
                             help="CIDA-style narrative Word report (.docx)"),
    out: Path = typer.Option(Path("./out/report_from_doc.pdf"), "--out",
                             help="Output PDF path"),
    country: str = typer.Option("NG", "--country",
                                help="ISO-3166 alpha-2 country code for the assessed org"),
    offline: bool = typer.Option(False, "--offline",
                                 help="Skip CVE/EPSS/KEV enrichment AND public-intel fetch"),
    seed: int = typer.Option(42, "--seed", help="Monte Carlo seed"),
) -> None:
    """Score a CIDA narrative Word report directly.

    The analyst writes the assessment as a Word doc (Email Security, Vulns,
    OSINT, Compliance, etc.).  This command reads that doc, extracts the
    findings + declared posture + org metadata, runs the full CIDA pipeline,
    and writes the scored Risk Summary / Likelihoods / EL block back out.
    """
    typer.echo(f"[cida] Parsing CIDA narrative report: {doc}")
    org, responses, findings, parsed = ingest_cida_docx(doc, country=country)
    typer.echo(f"[cida] Org: {org.name}  sector={org.sector.value}  country={org.country}")
    typer.echo(f"[cida] Parsed {len(findings)} findings; "
               f"{len(parsed.compromised_emails)} compromised mailbox(es); "
               f"declared: {parsed.declared}")

    typer.echo("[cida] Scoring...")
    scoring = score_organization(responses, findings)
    typer.echo(f"[cida] Overall score = {scoring.overall_score}  "
               f"(Tier {scoring.tier.tier} – {scoring.tier.label})")

    typer.echo(f"[cida] Public intelligence on '{org.name}' "
               f"({'offline-skip' if offline else 'live Proshare + BusinessDay'})...")
    intel = gather_company_intel(org, offline=offline)

    typer.echo("[cida] Bayesian actuarial + 10k Monte Carlo...")
    actuarial = run_actuarial_model(org, responses, seed=seed, findings=findings, intel=intel)
    typer.echo(f"[cida] Aggregate EL = ${actuarial.aggregate_expected_loss_usd:,.0f}")

    report = build_report(org, responses, scoring, actuarial, findings=findings, intel=intel)

    json_path = out.with_suffix(".json")
    render_json(report, json_path)
    typer.echo(f"[cida] JSON  -> {json_path}")
    pdf_path = render_pdf(report, out)
    typer.echo(f"[cida] PDF   -> {pdf_path}")

    # Also dump a compact "scored block" suitable for pasting back into the
    # original Word template (Risk Score / Likelihoods / EL).
    import math, json as _json
    drivers = {d.driver.value: d for d in actuarial.per_driver}
    def _p(lam: float) -> float: return 1.0 - math.exp(-max(0.0, lam))
    likelihoods = {
        "Ransomware":      _p(drivers["cyber_extortion"].annual_frequency_mean
                              + drivers["data_recovery"].annual_frequency_mean * 0.5),
        "DDoS":            _p(drivers["business_interruption"].annual_frequency_mean),
        "Data Breach":     _p(drivers["privacy_liability"].annual_frequency_mean),
        "Insider Threat":  _p(drivers["privacy_liability"].annual_frequency_mean * 0.35
                              + drivers["computer_fraud"].annual_frequency_mean * 0.25),
        "Phishing / BEC":  _p(drivers["social_engineering"].annual_frequency_mean),
        "Compliance":      _p(drivers["regulatory_penalties"].annual_frequency_mean),
    }
    block = {
        "org": {"name": org.name, "sector": org.sector.value, "country": org.country,
                 "industry_raw": parsed.industry, "revenue_raw": parsed.revenue_raw,
                 "date_of_assessment": parsed.assessment_date},
        "risk_score": report.risk_summary.risk_score,
        "risk_band":  report.risk_summary.risk_band,
        "overall_cida_score": scoring.overall_score,
        "tier": {"tier": scoring.tier.tier, "label": scoring.tier.label},
        "likelihood_multiplier_vs_peer": report.risk_summary.likelihood_multiplier_vs_peer,
        "likelihoods_pct": {k: round(v * 100, 1) for k, v in likelihoods.items()},
        "aggregate_expected_loss_usd": actuarial.aggregate_expected_loss_usd,
        "aggregate_var_95_usd":  actuarial.aggregate_var_95_usd,
        "aggregate_tvar_99_usd": actuarial.aggregate_tvar_99_usd,
        "loss_p50_usd": report.risk_summary.composite_loss_p50_usd,
        "loss_p90_usd": report.risk_summary.composite_loss_p90_usd,
        "loss_p99_usd": report.risk_summary.composite_loss_p99_usd,
        "technical_premium_usd": report.premium.technical_premium_usd,
        "finding_counts": report.risk_summary.finding_counts,
        "declared_signals": parsed.declared,
        "compromised_emails": parsed.compromised_emails,
    }
    scored_block_path = out.with_name(out.stem + "_scored_block.json")
    scored_block_path.write_text(_json.dumps(block, indent=2), encoding="utf-8")
    typer.echo(f"[cida] Scored block -> {scored_block_path}")


@app.command("score-project")
def score_project(
    project_dir: Path = typer.Argument(
        ..., help="Client folder under cida/clients/ (e.g. 'cida/clients/XYZ Bank')"
    ),
    offline: bool = typer.Option(False, "--offline", help="Skip CVE/EPSS/KEV enrichment and public-intel fetch"),
    seed: int = typer.Option(42, "--seed", help="Monte Carlo seed"),
    yoa: bool = typer.Option(True, "--policyholder/--no-policyholder", help="Also render Policyholder Report"),
    limitation: list[str] = typer.Option(
        [], "--limitation", help="Assessment scope limitation note (repeatable)"
    ),
) -> None:
    """Score a CIDA client project from a drop-zone directory.

    Create a folder under cida/clients/ with the client name, drop all artefacts in,
    then run:

        cida score-project "cida/clients/XYZ Bank"
        cida score-project "cida/clients/Summit 2025" --limitation "GCP not assessed"

    The folder must contain org_profile.yaml and questionnaire.csv.
    All other files are auto-discovered and classified by content (not filename).

    Output goes to cida/clients/<name>/output/:
        <org_id>_report.pdf           (underwriting scorecard)
        <org_id>_policyholder_report.pdf       (Policyholder Report, if --yoa)
        <org_id>_report.json          (full data payload)
        <org_id>_scored_block.json    (compact underwriting payload)
    """
    import json as _json
    from ingest.project import load_project

    typer.echo(f"[cida] Loading project from {project_dir}")
    org, responses, found, evidence_images, unclassified = load_project(
        project_dir, offline=offline
    )
    typer.echo(f"[cida] {len(responses.responses)} questionnaire responses, {len(found)} findings, "
               f"{len(evidence_images)} evidence images.")

    typer.echo("[cida] Scoring...")
    scoring = score_organization(responses, found)
    typer.echo(f"[cida] Overall score = {scoring.overall_score}  (Tier {scoring.tier.tier} - {scoring.tier.label})")

    typer.echo(f"[cida] Public intelligence on '{org.name}' ({'offline-skip' if offline else 'live Proshare + BusinessDay'})...")
    intel = gather_company_intel(org, offline=offline)

    typer.echo("[cida] Bayesian actuarial + 10,000 Monte Carlo simulations...")
    actuarial = run_actuarial_model(org, responses, seed=seed, findings=found, intel=intel)
    typer.echo(f"[cida] Aggregate EL = ${actuarial.aggregate_expected_loss_usd:,.0f}")

    typer.echo("[cida] Building report...")
    report = build_report(
        org, responses, scoring, actuarial,
        findings=found, intel=intel,
        assessment_limitations=list(limitation),
        evidence_images=evidence_images,
        unclassified_files=unclassified,
    )

    # Output directory: <project_dir>/output/
    out_dir = Path(project_dir) / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = org.org_id

    json_path = out_dir / f"{slug}_report.json"
    render_json(report, json_path)
    typer.echo(f"[cida] JSON         -> {json_path}")

    pdf_path = render_pdf(report, out_dir / f"{slug}_report.pdf")
    typer.echo(f"[cida] Scorecard PDF  -> {pdf_path}")

    html_out = out_dir / f"{slug}_report.html"
    render_html(report, html_out)
    typer.echo(f"[cida] Scorecard HTML -> {html_out}")

    if yoa:
        policyholder_path = render_policyholder_pdf(report, findings=found,
                                  out_path=out_dir / f"{slug}_policyholder_report.pdf")
        typer.echo(f"[cida] Policyholder PDF       -> {policyholder_path}")

        policyholder_html_out = out_dir / f"{slug}_policyholder_report.html"
        render_policyholder_html(report, findings=found, out_path=policyholder_html_out)
        typer.echo(f"[cida] Policyholder HTML      -> {policyholder_html_out}")

    # Compact scored block (for SaaS integration)
    rs = report.risk_summary
    inc_probs = {i.key: i.probability_pct for i in rs.incident_probabilities} if rs else {}
    block = {
        "org": {
            "name": org.name,
            "sector": org.sector.value if hasattr(org.sector, "value") else str(org.sector),
            "country": org.country,
        },
        "risk_score": rs.risk_score if rs else None,
        "risk_band": rs.risk_band if rs else None,
        "overall_cida_score": scoring.overall_score,
        "tier": {"tier": scoring.tier.tier, "label": scoring.tier.label},
        "security_posture_pct": round(100 - rs.risk_score, 1) if rs else None,
        "likelihood_multiplier_vs_peer": rs.likelihood_multiplier_vs_peer if rs else None,
        "incident_probabilities_pct": inc_probs,
        "aggregate_expected_loss_usd": actuarial.aggregate_expected_loss_usd,
        "aggregate_var_95_usd": actuarial.aggregate_var_95_usd,
        "aggregate_tvar_99_usd": actuarial.aggregate_tvar_99_usd,
        "loss_p50_usd": rs.composite_loss_p50_usd if rs else None,
        "loss_p90_usd": rs.composite_loss_p90_usd if rs else None,
        "loss_p99_usd": rs.composite_loss_p99_usd if rs else None,
        "technical_premium_usd": report.premium.technical_premium_usd,
        "maximum_probable_loss_usd": report.premium.maximum_probable_loss_usd,
        "suggested_aggregate_limit_usd": report.premium.suggested_aggregate_limit_usd,
        "suggested_retention_usd": report.premium.suggested_retention_usd,
        "local_currency": {
            "code": report.premium.local_currency_code,
            "fx_rate_to_usd": report.premium.fx_rate_to_usd,
            "technical_premium": report.premium.technical_premium_local,
            "maximum_probable_loss": report.premium.maximum_probable_loss_local,
            "suggested_aggregate_limit": report.premium.suggested_aggregate_limit_local,
            "suggested_retention": report.premium.suggested_retention_local,
        },
        "finding_counts": rs.finding_counts if rs else {},
        "conditions_recommended": report.premium.conditions_recommended,
        "exclusions_recommended": report.premium.exclusions_recommended,
        "regulatory_risk_flags": report.premium.regulatory_risk_flags,
        "compromised_emails_count": len(report.compromised_emails),
        "evidence_images_count": len(evidence_images),
        "unclassified_files_count": len(unclassified),
    }
    scored_block_path = out_dir / f"{slug}_scored_block.json"
    scored_block_path.write_text(_json.dumps(block, indent=2), encoding="utf-8")
    typer.echo(f"[cida] Scored block -> {scored_block_path}")

    pr = report.premium
    cur = pr.local_currency_code or "USD"

    def _fmt_money(usd_val: float, local_val: float | None) -> str:
        if local_val is not None and pr.local_currency_code:
            return f"${usd_val:,.0f} USD  /  {pr.local_currency_code} {local_val:,.0f}"
        return f"${usd_val:,.0f} USD"

    typer.echo("\n-- UNDERWRITING SUMMARY --------------------------------------------------")
    typer.echo(f"  Organisation    : {org.name}  ({org.sector} / {org.country})")
    if pr.local_currency_code and pr.fx_rate_to_usd:
        typer.echo(f"  Currency        : {pr.local_currency_code}  (1 USD = {pr.fx_rate_to_usd:,.2f} {pr.local_currency_code})")
    if rs:
        typer.echo(f"  Security Posture: {100 - rs.risk_score:.0f}%  ({rs.risk_band} RISK)")
    typer.echo(f"  Tier            : {scoring.tier.tier} -- {scoring.tier.label}")
    typer.echo(f"  Expected Annual Loss   : {_fmt_money(actuarial.aggregate_expected_loss_usd, actuarial.aggregate_expected_loss_usd * (pr.fx_rate_to_usd or 1) if pr.fx_rate_to_usd else None)}")
    typer.echo(f"  Max Probable Loss (P99): {_fmt_money(pr.maximum_probable_loss_usd, pr.maximum_probable_loss_local)}")
    typer.echo(f"  Technical Premium      : {_fmt_money(pr.technical_premium_usd, pr.technical_premium_local)}")
    typer.echo(f"  Suggested Limit        : {_fmt_money(pr.suggested_aggregate_limit_usd, pr.suggested_aggregate_limit_local)}")
    typer.echo(f"  Suggested Retention    : {_fmt_money(pr.suggested_retention_usd, pr.suggested_retention_local)}")
    if rs:
        fc = rs.finding_counts
        typer.echo(f"  Findings: {fc.get('critical',0)} Critical  {fc.get('high',0)} High  {fc.get('medium',0)} Medium  {fc.get('low',0)} Low")
        if rs.incident_probabilities:
            typer.echo("  Incident Probabilities:")
            for inc in rs.incident_probabilities:
                typer.echo(f"    {inc.label:<30} {inc.probability_pct:.1f}%")
    if unclassified:
        typer.echo(f"  [!] {len(unclassified)} file(s) could not be classified -- check diagnostics above")
    typer.echo("--------------------------------------------------------------------------")


@app.command("list-countries")
def list_countries_cmd() -> None:
    """List all 54 supported African countries with their ISO code, name, currency, and region."""
    import yaml as _yaml
    from pathlib import Path as _Path
    countries_dir = _Path(__file__).parent / "config" / "countries"
    rows = []
    for f in sorted(countries_dir.glob("*.yaml")):
        d = _yaml.safe_load(f.read_text(encoding="utf-8"))
        rows.append((d["iso_a2"], d["name"], d.get("currency", "?"), d.get("region", "")))
    col_w = [4, 46, 6, 16]
    header = f"{'Code':<{col_w[0]}}  {'Country':<{col_w[1]}}  {'Currency':<{col_w[2]}}  {'Region'}"
    typer.echo(header)
    typer.echo("-" * (sum(col_w) + 6))
    for code, name, cur, region in rows:
        typer.echo(f"{code:<{col_w[0]}}  {name:<{col_w[1]}}  {cur:<{col_w[2]}}  {region}")


@app.command("list-regulators")
def list_regulators_cmd(kind: str | None = typer.Option(None, "--kind", help="insurance|data_protection|financial|sector")) -> None:
    for r in _list_regulators(kind):
        typer.echo(r)


@app.command()
def version() -> None:
    typer.echo("CIDA 0.1.0")


@app.command()
def backtest(
    out: Path = typer.Option(Path("./out/backtest.json"), "--out", help="Output JSON path"),
    offline: bool = typer.Option(True, "--offline", help="Skip CVE enrichment"),
) -> None:
    """Run reference cases and report tier/score/EL accuracy."""
    typer.echo("[cida] Running backtest...")
    result = run_backtest(offline=offline)
    save_results(result, out)
    typer.echo(f"[cida] {result.n_passed}/{result.n_cases} cases fully passed")
    typer.echo(f"[cida] Tier accuracy:    {result.tier_accuracy}%")
    typer.echo(f"[cida] Score-band acc:   {result.score_band_accuracy}%")
    typer.echo(f"[cida] EL-band acc:      {result.el_band_accuracy}%")
    typer.echo(f"[cida] Results JSON -> {out}")
    for c in result.cases:
        flag = "PASS" if c.all_pass else "FAIL"
        typer.echo(f"  [{flag}] {c.case_id}: score={c.overall_score} tier={c.tier} EL=${c.aggregate_el_usd:,.0f}")


@app.command("update-priors")
def update_priors_cmd(
    claims: Path = typer.Option(..., "--claims", exists=True, help="YAML file with observed claims"),
    out: Path = typer.Option(..., "--out", help="Output updated priors YAML"),
) -> None:
    """Update Bayesian priors from observed claims data (conjugate posterior)."""
    import yaml as _yaml
    from actuarial.posterior_update import ClaimObservation, update_priors_file
    from models import LossDriver

    data = _yaml.safe_load(claims.read_text(encoding="utf-8"))
    obs = [
        ClaimObservation(
            driver=LossDriver(o["driver"]),
            exposure_years=float(o.get("exposure_years", 1.0)),
            event_count=int(o["event_count"]),
            severities_usd=[float(s) for s in o.get("severities_usd", [])],
            country=o.get("country"),
            sector=o.get("sector"),
        )
        for o in data.get("observations", [])
    ]
    update_priors_file(obs, out_path=out)
    typer.echo(f"[cida] Posterior priors written to {out} ({len(obs)} observations applied)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
