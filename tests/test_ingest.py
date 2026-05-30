"""Unit tests for ingestion."""
from pathlib import Path

import pytest

from cida.ingest.questionnaire import parse_questionnaire_csv, _score_yes_no, _score_scale_1_5
from cida.ingest.findings import load_findings_from_dir

EXAMPLES = Path(__file__).resolve().parent.parent / "cida" / "examples"


def test_yes_no_scoring():
    assert _score_yes_no("yes") == 100.0
    assert _score_yes_no("no") == 0.0
    assert _score_yes_no("YES") == 100.0
    assert _score_yes_no("") == 0.0
    assert _score_yes_no(1) == 100.0
    assert _score_yes_no(0) == 0.0


def test_scale_scoring():
    assert _score_scale_1_5(1) == 0.0
    assert _score_scale_1_5(3) == 50.0
    assert _score_scale_1_5(5) == 100.0
    assert _score_scale_1_5(6) == 100.0   # clamped
    assert _score_scale_1_5(0) == 0.0     # clamped


def test_parse_questionnaire():
    responses = parse_questionnaire_csv(EXAMPLES / "sample_questionnaire.csv", org_id="X")
    assert responses.org_id == "X"
    assert len(responses.responses) == 41
    # All scores must be in [0, 100]
    for r in responses.responses:
        assert 0.0 <= r.score <= 100.0


def test_load_findings():
    findings = load_findings_from_dir(EXAMPLES / "sample_findings")
    assert len(findings) >= 5
    assert all(f.source for f in findings)
    assert all(f.severity for f in findings)
