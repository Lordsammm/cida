"""Backtest runner - validates the model against known reference cases.

Cases live in tests/backtest/cases/. Each defines an org, responses, findings,
and the expected tier / score band / EL band. Run after any config change to
catch regressions: python -m cida.cli backtest
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from actuarial.model import run_actuarial_model
from enrich.cve import enrich_findings
from models import ControlResponse, Finding, OrgProfile, QuestionnaireResponses
from scoring.engine import score_organization

CASES_DIR = Path(__file__).parent.parent / "tests" / "backtest" / "cases"


@dataclass
class CaseResult:
    case_id: str
    overall_score: float
    tier: int
    aggregate_el_usd: float
    tier_pass: bool
    score_pass: bool
    el_pass: bool
    notes: str = ""

    @property
    def all_pass(self) -> bool:
        return self.tier_pass and self.score_pass and self.el_pass


@dataclass
class BacktestResult:
    timestamp: str
    n_cases: int
    n_passed: int
    tier_accuracy: float          # % cases with tier within expected range
    score_band_accuracy: float    # % cases with overall score within expected range
    el_band_accuracy: float       # % cases with EL within expected band
    cases: list[CaseResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def load_case(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _build_responses(org_id: str, raw_responses: list[dict]) -> QuestionnaireResponses:
    from catalog.loader import load_catalog
    from ingest.questionnaire import _score_response

    catalog = load_catalog()
    by_id = {c.control_id: c for c in catalog.controls}
    out: list[ControlResponse] = []
    for r in raw_responses:
        cid = r["control_id"]
        if cid not in by_id:
            continue
        score = _score_response(r["answer"], by_id[cid])
        out.append(ControlResponse(
            control_id=cid, raw_answer=str(r["answer"]), score=score,
            notes=r.get("notes"),
        ))
    return QuestionnaireResponses(
        org_id=org_id, submitted_at=datetime.now(tz=timezone.utc), responses=out,
    )


def _run_one(case_path: Path, offline: bool = True) -> CaseResult:
    spec = load_case(case_path)
    org = OrgProfile.model_validate(spec["org"])
    responses = _build_responses(org.org_id, spec.get("responses", []))
    findings_raw = spec.get("findings", []) or []
    findings = [Finding.model_validate(f) for f in findings_raw]
    if findings and not offline:
        findings = enrich_findings(findings, offline=False)

    scoring = score_organization(responses, findings)
    actuarial = run_actuarial_model(org, responses, seed=42, findings=findings)

    expected = spec.get("expected", {})
    tier_in = expected.get("tier_in", [1, 2, 3, 4, 5])
    score_range = expected.get("overall_score_range", [0, 100])
    el_range = expected.get("el_range_usd", [0, 10**12])

    tier_pass = scoring.tier.tier in tier_in
    score_pass = score_range[0] <= scoring.overall_score <= score_range[1]
    el_pass = el_range[0] <= actuarial.aggregate_expected_loss_usd <= el_range[1]

    return CaseResult(
        case_id=case_path.stem,
        overall_score=scoring.overall_score,
        tier=scoring.tier.tier,
        aggregate_el_usd=actuarial.aggregate_expected_loss_usd,
        tier_pass=tier_pass,
        score_pass=score_pass,
        el_pass=el_pass,
        notes=expected.get("notes", ""),
    )


def run_backtest(cases_dir: Path | None = None, offline: bool = True) -> BacktestResult:
    cases_dir = cases_dir or CASES_DIR
    if not cases_dir.exists():
        raise FileNotFoundError(f"No backtest cases dir at {cases_dir}")
    case_files = sorted(cases_dir.glob("*.yaml"))
    if not case_files:
        raise ValueError(f"No *.yaml case files in {cases_dir}")

    results: list[CaseResult] = []
    for path in case_files:
        try:
            results.append(_run_one(path, offline=offline))
        except Exception as e:  # noqa: BLE001
            print(f"[backtest] {path.name} FAILED to execute: {e}")

    n = len(results)
    n_passed = sum(1 for r in results if r.all_pass)
    return BacktestResult(
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        n_cases=n,
        n_passed=n_passed,
        tier_accuracy=round(100 * sum(r.tier_pass for r in results) / max(n, 1), 1),
        score_band_accuracy=round(100 * sum(r.score_pass for r in results) / max(n, 1), 1),
        el_band_accuracy=round(100 * sum(r.el_pass for r in results) / max(n, 1), 1),
        cases=results,
    )


def save_results(result: BacktestResult, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
    return out_path
