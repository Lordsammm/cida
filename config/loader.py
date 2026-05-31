"""YAML config loaders for countries, regulators, sectors, priors, FX rates, and the vector matrix.

All load functions are cached. Legacy 7-driver keys (bec, ransomware, …) are rewritten
to the current 10-driver names at load time via LEGACY_LOSS_DRIVER_ALIASES.
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

from models import (
    Country,
    LEGACY_LOSS_DRIVER_ALIASES,
    Priors,
    Regulator,
    SectorOverlay,
)

CONFIG_DIR = Path(__file__).parent


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _alias_driver_keys(d: Any) -> Any:
    """Recursively rewrite legacy loss-driver keys to canonical names.

    Walks any nested dict and replaces top-level keys matching the legacy
    alias map (`bec`, `ransomware`, `data_breach`, `ddos`, `insider`,
    `third_party`, `mobile_money_fraud`). New canonical keys take precedence
    if both old and new exist (which should not happen in practice).
    """
    if isinstance(d, dict):
        out: dict[str, Any] = {}
        for k, v in d.items():
            new_key = LEGACY_LOSS_DRIVER_ALIASES.get(k, k) if isinstance(k, str) else k
            v2 = _alias_driver_keys(v)
            # Honor canonical key if both old + new are present
            if new_key in out and new_key != k:
                continue
            out[new_key] = v2
        return out
    if isinstance(d, list):
        return [_alias_driver_keys(x) for x in d]
    return d


@functools.lru_cache(maxsize=None)
def load_country(iso_a2: str) -> Country:
    path = CONFIG_DIR / "countries" / f"{iso_a2.upper()}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No country config for {iso_a2}: {path}")
    return Country.model_validate(_alias_driver_keys(_load_yaml(path)))


@functools.lru_cache(maxsize=None)
def load_regulator(regulator_id: str) -> Regulator:
    # search across all regulator subfolders
    for sub in ("insurance", "data_protection", "financial", "sector"):
        path = CONFIG_DIR / "regulators" / sub / f"{regulator_id}.yaml"
        if path.exists():
            return Regulator.model_validate(_load_yaml(path))
    raise FileNotFoundError(f"Regulator not found: {regulator_id}")


@functools.lru_cache(maxsize=None)
def load_sector(name: str) -> SectorOverlay:
    path = CONFIG_DIR / "sectors" / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Sector overlay not found: {name}")
    return SectorOverlay.model_validate(_alias_driver_keys(_load_yaml(path)))


@functools.lru_cache(maxsize=None)
def load_priors() -> Priors:
    global_p = _alias_driver_keys(_load_yaml(CONFIG_DIR / "priors" / "global.yaml"))
    africa = _alias_driver_keys(_load_yaml(CONFIG_DIR / "priors" / "africa-overlay.yaml"))
    # Africa overlay shape: frequency_adjustments: { driver: { multiplier: x } }
    merged = dict(global_p)
    for driver, spec in africa.get("frequency_adjustments", {}).items():
        if driver not in merged.get("frequency_priors", {}):
            continue
        mult = spec.get("multiplier", 1.0) if isinstance(spec, dict) else float(spec)
        merged["frequency_priors"][driver]["alpha"] *= mult
    merged.setdefault("source_notes", []).extend(africa.get("source_notes", []))
    return Priors.model_validate(merged)


@functools.lru_cache(maxsize=None)
def load_vector_matrix() -> dict[str, Any]:
    """Loads the 14-vector x 10-driver multiplier matrix + metadata."""
    path = CONFIG_DIR / "vector_matrix.yaml"
    data = _alias_driver_keys(_load_yaml(path))
    return data


@functools.lru_cache(maxsize=None)
def load_framework(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / "frameworks" / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Framework not found: {name}")
    return _load_yaml(path)


@functools.lru_cache(maxsize=None)
def load_fx_rates() -> dict[str, float]:
    """Load indicative FX rates from fx_rates.yaml.

    Returns a dict of {ISO-4217 currency code: rate} where 1 USD = rate local units.
    Returns an empty dict if the file is missing (graceful degradation).
    """
    path = CONFIG_DIR / "fx_rates.yaml"
    if not path.exists():
        return {}
    data = _load_yaml(path)
    return {k: float(v) for k, v in data.get("rates", {}).items()}


def fx_rate_for_currency(currency_code: str) -> float | None:
    """Return the indicative rate (1 USD = X local) for the given ISO-4217 code.

    Returns None if the currency is not in the FX table.
    """
    return load_fx_rates().get(currency_code.upper())


@functools.lru_cache(maxsize=None)
def load_scoring_weights() -> dict:
    """Load domain weights, severity penalties, and tier bands from scoring_weights.yaml."""
    return _load_yaml(CONFIG_DIR / "scoring_weights.yaml")


def list_countries() -> list[str]:
    return sorted(p.stem for p in (CONFIG_DIR / "countries").glob("*.yaml"))


def list_regulators(kind: str | None = None) -> list[str]:
    base = CONFIG_DIR / "regulators"
    subs = [kind] if kind else ["insurance", "data_protection", "financial", "sector"]
    out: list[str] = []
    for s in subs:
        out.extend(sorted(p.stem for p in (base / s).glob("*.yaml")))
    return out


class CountryContext:
    """Resolved bundle: country + its regulators."""

    def __init__(self, country: Country):
        self.country = country
        self.insurance = self._resolve(country.regulators.insurance)
        self.data_protection = self._resolve(country.regulators.data_protection)
        self.central_bank = self._resolve(country.regulators.central_bank)
        self.capital_markets = self._resolve(country.regulators.capital_markets)
        self.telecoms = self._resolve(country.regulators.telecoms)
        self.sector_regulators = {
            k: self._resolve(v) for k, v in country.regulators.sector.items() if v
        }

    @staticmethod
    def _resolve(rid: str | None) -> Regulator | None:
        if not rid:
            return None
        try:
            return load_regulator(rid)
        except FileNotFoundError:
            return None

    def all_applicable_directives(self) -> list[tuple[str, "RegulatorDirective"]]:
        """Returns (regulator_id, directive) pairs for compliance posture computation."""
        out = []
        for reg in [
            self.insurance,
            self.data_protection,
            self.central_bank,
            self.capital_markets,
            self.telecoms,
            *self.sector_regulators.values(),
        ]:
            if reg:
                for d in reg.directives:
                    out.append((reg.id, d))
        return out


def context_for(iso_a2: str) -> CountryContext:
    return CountryContext(load_country(iso_a2))
