"""Load the master control catalog (cida/catalog/control_catalog.yaml).

Applies LEGACY_LOSS_DRIVER_ALIASES so older catalog entries using the
7-driver names (bec, ransomware, data_breach …) load without modification.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from config.loader import _alias_driver_keys
from models import ControlCatalog

CATALOG_PATH = Path(__file__).parent / "control_catalog.yaml"


def load_catalog() -> ControlCatalog:
    with CATALOG_PATH.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return ControlCatalog.model_validate(_alias_driver_keys(raw))
