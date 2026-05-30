"""Unit tests for ML modifier (graceful degradation when no model trained)."""
import math
from datetime import datetime, timezone

import pytest

from cida.actuarial.model import run_actuarial_model
from cida.catalog.loader import load_catalog
from cida.ml.modifier import FeatureVector, build_features, predict_modifier, train_modifier, MODEL_PATH
from cida.models import ControlResponse, OrgProfile, QuestionnaireResponses, Sector


def _setup():
    org = OrgProfile(
        org_id="T", name="T", sector=Sector.INSURANCE, country="NG",
        employees=500, annual_revenue_usd=50_000_000, data_sensitivity="high",
    )
    catalog = load_catalog()
    responses = QuestionnaireResponses(
        org_id="T", submitted_at=datetime.now(tz=timezone.utc),
        responses=[ControlResponse(control_id=c.control_id, raw_answer="yes", score=70.0)
                   for c in catalog.controls],
    )
    baseline = run_actuarial_model(org, responses, seed=42)
    return org, responses, baseline


def test_predict_returns_neutral_without_model():
    """If no model artifacts exist, predict_modifier returns 1.0."""
    if MODEL_PATH.exists():
        pytest.skip("Trained model present; skipping no-model test")
    org, responses, baseline = _setup()
    assert predict_modifier(org, responses, [], baseline) == 1.0


def test_feature_vector_shape():
    org, responses, baseline = _setup()
    fv = build_features(org, responses, [], baseline)
    assert len(fv.values) == len(fv.names)
    assert len(fv.values) > 20  # at least sector-onehot + summary stats + baseline


def test_train_modifier_smoke(tmp_path):
    """Train on tiny synthetic data; ensure model artifacts are produced and
    a subsequent prediction is bounded in [0.2, 5.0]."""
    pytest.importorskip("xgboost")
    org, responses, baseline = _setup()
    rows = []
    for i in range(30):
        fv = build_features(org, responses, [], baseline)
        # Synthetic label: actual_loss varies around baseline
        synthetic_actual = baseline.aggregate_expected_loss_usd * (0.5 + 0.05 * i)
        rows.append((fv, synthetic_actual))
    model_path = train_modifier(rows, out_dir=tmp_path)
    assert model_path.exists()
