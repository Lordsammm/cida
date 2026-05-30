"""Run the full backtest suite and assert directional accuracy."""
from backtest.runner import run_backtest


def test_backtest_tier_accuracy_minimum():
    """At least 60% of reference cases should fall in their expected tier band.

    This is the calibration target - improvements to priors should never
    drop tier accuracy below this floor.
    """
    result = run_backtest(offline=True)
    assert result.n_cases >= 10
    assert result.tier_accuracy >= 60.0, (
        f"Tier accuracy regressed to {result.tier_accuracy}%; "
        f"see individual cases: {[(c.case_id, c.tier, c.tier_pass) for c in result.cases]}"
    )


def test_backtest_score_band_minimum():
    result = run_backtest(offline=True)
    assert result.score_band_accuracy >= 50.0
