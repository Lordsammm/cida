"""Actuarial models - Bayesian frequency + severity + Monte Carlo aggregate loss."""
from cida.actuarial.model import run_actuarial_model
from cida.actuarial.premium import compute_premium

__all__ = ["run_actuarial_model", "compute_premium"]
