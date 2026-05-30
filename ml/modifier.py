"""ML modifier layer - XGBoost ensemble that learns the residual on log(EL)
that the Bayesian actuarial baseline doesn't capture.

Training data: rows of (org features + questionnaire + findings features) →
actual annual loss observed for that org.

Inference: returns a multiplicative modifier (≥ 0) applied to the baseline EL.
If the model is not trained, `predict_modifier()` returns 1.0 (neutral).

Model file: cida/ml/artifacts/modifier.json (XGBoost native format).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import numpy as np

from actuarial.model import ActuarialResult
from models import (
    Finding,
    LossDriver,
    OrgProfile,
    QuestionnaireResponses,
    Sector,
    Severity,
)

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "modifier.json"
FEATURE_SCHEMA_PATH = ARTIFACTS_DIR / "feature_schema.json"


@dataclass
class FeatureVector:
    """Flat numeric feature vector for the ML modifier."""
    values: list[float] = field(default_factory=list)
    names: list[str] = field(default_factory=list)

    def add(self, name: str, value: float) -> None:
        self.names.append(name)
        self.values.append(float(value))


def _sector_one_hot(sector: Sector | str) -> dict[str, float]:
    s = sector.value if isinstance(sector, Sector) else str(sector)
    return {f"sector_{member.value}": 1.0 if member.value == s else 0.0 for member in Sector}


def build_features(
    org: OrgProfile,
    responses: QuestionnaireResponses,
    findings: Iterable[Finding],
    baseline: ActuarialResult,
) -> FeatureVector:
    fv = FeatureVector()

    # Org features
    fv.add("log_revenue_usd", math.log(max(org.annual_revenue_usd or 1.0, 1.0)))
    fv.add("log_employees", math.log(max(org.employees, 1)))
    fv.add("public_facing_assets", float(org.public_facing_assets))
    sens_map = {"low": 0, "medium": 1, "high": 2, "very_high": 3}
    fv.add("data_sensitivity", float(sens_map.get(org.data_sensitivity, 1)))

    # Sector one-hot
    for k, v in _sector_one_hot(org.sector).items():
        fv.add(k, v)

    # Questionnaire summary stats
    scores = [r.score for r in responses.responses]
    if scores:
        fv.add("resp_mean", float(np.mean(scores)))
        fv.add("resp_std", float(np.std(scores)))
        fv.add("resp_min", float(np.min(scores)))
        fv.add("resp_pct_failing", float(sum(1 for s in scores if s < 70) / len(scores)))
        fv.add("resp_count", float(len(scores)))
    else:
        for n in ["resp_mean", "resp_std", "resp_min", "resp_pct_failing", "resp_count"]:
            fv.add(n, 0.0)

    # Findings features
    findings = list(findings)
    sev_counts = {s.value: 0 for s in Severity}
    kev_count = 0
    epss_high = 0
    internet_exposed = 0
    for f in findings:
        sev_key = f.severity.value if hasattr(f.severity, "value") else f.severity
        sev_counts[sev_key] = sev_counts.get(sev_key, 0) + 1
        if f.kev_listed:
            kev_count += 1
        if f.epss_score and f.epss_score > 0.5:
            epss_high += 1
        if f.exposure == "internet":
            internet_exposed += 1
    for sev, n in sev_counts.items():
        fv.add(f"findings_{sev}", float(n))
    fv.add("findings_kev", float(kev_count))
    fv.add("findings_epss_high", float(epss_high))
    fv.add("findings_internet_exposed", float(internet_exposed))
    fv.add("findings_total", float(len(findings)))

    # Baseline actuarial outputs (the ML residualises on top of these)
    fv.add("baseline_log_el", math.log(max(baseline.aggregate_expected_loss_usd, 1.0)))
    fv.add("baseline_log_var95", math.log(max(baseline.aggregate_var_95_usd, 1.0)))
    for d in baseline.per_driver:
        fv.add(f"baseline_log_el_{d.driver.value}",
               math.log(max(d.expected_annual_loss_usd, 1.0)))

    return fv


def _model_available() -> bool:
    return MODEL_PATH.exists() and FEATURE_SCHEMA_PATH.exists()


def predict_modifier(
    org: OrgProfile,
    responses: QuestionnaireResponses,
    findings: Iterable[Finding],
    baseline: ActuarialResult,
) -> float:
    """Return a multiplicative EL modifier. 1.0 if no model is trained."""
    if not _model_available():
        return 1.0
    try:
        import xgboost as xgb
    except ImportError:
        return 1.0

    fv = build_features(org, responses, findings, baseline)
    schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    # Reorder fv to schema
    name_to_val = dict(zip(fv.names, fv.values))
    row = np.array([[name_to_val.get(n, 0.0) for n in schema["feature_names"]]], dtype=float)

    booster = xgb.Booster()
    booster.load_model(str(MODEL_PATH))
    dmat = xgb.DMatrix(row, feature_names=schema["feature_names"])
    log_residual = float(booster.predict(dmat)[0])
    modifier = math.exp(log_residual)
    # Clip extreme predictions defensively
    return float(np.clip(modifier, 0.2, 5.0))


def train_modifier(
    training_rows: list[tuple[FeatureVector, float]],
    out_dir: Path | None = None,
) -> Path:
    """Train the residual model.

    training_rows: list of (FeatureVector, observed_actual_annual_loss_usd).
    The label is log(actual / baseline_predicted), where baseline_predicted is
    embedded in the feature vector as `baseline_log_el`. This makes the model
    learn the residual (not the absolute loss), which is much smaller-variance.
    """
    try:
        import xgboost as xgb
    except ImportError as e:
        raise RuntimeError("Install with: pip install -e .[ml]") from e

    out_dir = out_dir or ARTIFACTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if not training_rows:
        raise ValueError("No training rows provided.")

    feature_names = training_rows[0][0].names
    X = np.array([row[0].values for row in training_rows], dtype=float)
    # Label = log(actual_loss) − baseline_log_el  (residual on log scale)
    baseline_idx = feature_names.index("baseline_log_el")
    y = np.array([math.log(max(row[1], 1.0)) - row[0].values[baseline_idx]
                  for row in training_rows], dtype=float)

    dmat = xgb.DMatrix(X, label=y, feature_names=feature_names)
    params = {
        "objective": "reg:squarederror",
        "max_depth": 4,
        "eta": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
    }
    booster = xgb.train(params, dmat, num_boost_round=300)

    booster.save_model(str(out_dir / "modifier.json"))
    (out_dir / "feature_schema.json").write_text(
        json.dumps({"feature_names": feature_names, "n_training_rows": len(training_rows)}, indent=2),
        encoding="utf-8",
    )
    return out_dir / "modifier.json"
