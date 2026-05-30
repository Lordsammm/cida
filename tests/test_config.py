"""Unit tests for config + catalog loaders."""
import pytest

from catalog.loader import load_catalog
from config.loader import (
    CountryContext,
    list_countries,
    list_regulators,
    load_country,
    load_priors,
    load_regulator,
    load_sector,
)
from models import Domain, LossDriver, Sector


def test_53_or_more_countries():
    countries = list_countries()
    assert len(countries) >= 54  # 53 + MR
    assert "NG" in countries
    assert "ZA" in countries
    assert "MR" in countries


def test_catalog_has_all_domains():
    catalog = load_catalog()
    domains_covered = {c.domain for c in catalog.controls}
    assert domains_covered == set(Domain)


def test_catalog_weights_positive():
    catalog = load_catalog()
    for c in catalog.controls:
        assert c.weight > 0


def test_priors_load_with_africa_overlay():
    p = load_priors()
    # africa overlay multiplies social_engineering alpha by 1.6 - so it must
    # be > the global 0.40 prior.
    assert p.frequency_priors[LossDriver.SOCIAL_ENGINEERING]["alpha"] > 0.5
    # Sector mults exist
    assert Sector.INSURANCE in p.sector_frequency_multipliers


def test_country_context_resolves_regulators():
    ctx = CountryContext(load_country("NG"))
    assert ctx.insurance is not None
    assert ctx.insurance.id == "NAICOM"
    assert ctx.data_protection is not None


def test_sector_overlays_load():
    for s in Sector:
        try:
            ov = load_sector(s.value)
            assert ov.name == s
        except FileNotFoundError:
            pytest.fail(f"Missing sector overlay: {s.value}")


def test_regulator_resolution():
    naicom = load_regulator("NAICOM")
    assert naicom.type == "insurance"
    assert naicom.country == "NG"
