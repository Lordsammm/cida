"""Backtest harness - validate priors against reference cases.

Each reference case is a YAML file under `tests/backtest/cases/` containing:
    org:        an OrgProfile
    responses:  a list of {control_id, answer} pairs
    findings:   a list of Finding dicts (optional)
    expected:
        tier_in:        list[int]      # acceptable tiers (range)
        overall_score_range: [low, high]
        el_range_usd:   [low, high]    # acceptable EL band (wide)
        notes:          str

The harness reports per-case pass/fail and aggregates metrics: tier accuracy,
EL within-band rate. Drives prior calibration.
"""
from cida.backtest.runner import run_backtest, BacktestResult, load_case, save_results

__all__ = ["run_backtest", "BacktestResult", "load_case", "save_results"]
