"""Peer benchmarking store for CIDA assessments.

Provides sector × region percentile lookups based on accumulated real
assessment data, seeded with published industry benchmarks when no real
data exists.

Phase A (immediate): ml/peer_benchmarks.yaml holds seeded distributions
  derived from Coalition 2025, CIS v8 Community Defence Model, ENISA 2024,
  and Serianu 2024/2025. Available from day one with data_source="synthetic_seeded".

Phase B (accumulates): After each real assessment, PeerStore.record()
  stores anonymised aggregate statistics. The seeded benchmarks are
  progressively replaced. data_source becomes "accumulated_n=47" etc.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

_BENCHMARKS_PATH = Path(__file__).parent / "peer_benchmarks.yaml"
_ACCUMULATED_PATH = Path(__file__).parent / "peer_accumulated.json"

# Map country ISO-2 to region (same regions used in peer_benchmarks.yaml)
_COUNTRY_REGION: dict[str, str] = {
    "NG": "west_africa", "GH": "west_africa", "CI": "west_africa", "SN": "west_africa",
    "ML": "west_africa", "BF": "west_africa", "NE": "west_africa", "TG": "west_africa",
    "BJ": "west_africa", "GN": "west_africa", "SL": "west_africa", "LR": "west_africa",
    "GM": "west_africa", "GW": "west_africa", "CV": "west_africa", "MR": "west_africa",
    "KE": "east_africa",  "TZ": "east_africa",  "UG": "east_africa",  "RW": "east_africa",
    "ET": "east_africa",  "BI": "east_africa",  "DJ": "east_africa",  "SO": "east_africa",
    "SS": "east_africa",  "SD": "east_africa",  "ER": "east_africa",  "KM": "east_africa",
    "MG": "east_africa",  "MU": "east_africa",  "SC": "east_africa",
    "ZA": "southern_africa", "ZW": "southern_africa", "ZM": "southern_africa",
    "MW": "southern_africa", "MZ": "southern_africa", "BW": "southern_africa",
    "NA": "southern_africa", "LS": "southern_africa", "SZ": "southern_africa",
    "CM": "central_africa", "CD": "central_africa", "CG": "central_africa",
    "CF": "central_africa", "TD": "central_africa", "GA": "central_africa",
    "GQ": "central_africa", "AO": "central_africa", "ST": "central_africa",
    "EG": "north_africa",   "MA": "north_africa",   "DZ": "north_africa",
    "TN": "north_africa",   "LY": "north_africa",
}


@lru_cache(maxsize=1)
def _load_seeded() -> list[dict]:
    data = yaml.safe_load(_BENCHMARKS_PATH.read_text(encoding="utf-8"))
    return data.get("cohorts", [])


def _load_accumulated() -> dict:
    if _ACCUMULATED_PATH.exists():
        return json.loads(_ACCUMULATED_PATH.read_text(encoding="utf-8"))
    return {}


def _normal_cdf(z: float) -> float:
    """Approximate standard normal CDF using Abramowitz & Stegun."""
    if z < -6:
        return 0.0
    if z > 6:
        return 1.0
    t = 1.0 / (1.0 + 0.2316419 * abs(z))
    p = t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))))
    phi = math.exp(-0.5 * z * z) / math.sqrt(2 * math.pi)
    cdf = 1.0 - phi * p
    return cdf if z >= 0 else 1.0 - cdf


def _percentile(score: float, mean: float, std: float) -> float:
    """Return percentile (0-100) of score within Normal(mean, std)."""
    if std <= 0:
        return 50.0
    z = (score - mean) / std
    return round(_normal_cdf(z) * 100, 1)


@dataclass
class PeerComparison:
    sector: str
    region: str
    n_peers: int                         # 0 = seeded/synthetic
    overall_score_percentile: float      # 0-100; higher = stronger than more peers
    domain_percentiles: dict[str, float] = field(default_factory=dict)
    data_source: str = "synthetic_seeded"

    def to_dict(self) -> dict:
        return {
            "sector": self.sector,
            "region": self.region,
            "n_peers": self.n_peers,
            "overall_score_percentile": self.overall_score_percentile,
            "domain_percentiles": self.domain_percentiles,
            "data_source": self.data_source,
        }


class PeerStore:
    """Retrieve and record peer benchmark statistics."""

    def _find_cohort(self, sector: str, region: str) -> dict | None:
        cohorts = _load_seeded()
        # Exact match first
        for c in cohorts:
            if c["sector"] == sector and c["region"] == region:
                return c
        # Sector match with any region
        for c in cohorts:
            if c["sector"] == sector:
                return c
        # Fallback to "other / africa"
        for c in cohorts:
            if c["sector"] == "other":
                return c
        return None

    def get_percentiles(
        self,
        sector: str,
        country: str,
        scoring,
    ) -> PeerComparison:
        """Compute percentile ranks for the assessed org vs its peer cohort.

        Args:
            sector:   Org sector (Sector enum value or plain string).
            country:  ISO-2 country code; used to determine region.
            scoring:  ScoringResult.
        """
        sector_str = sector.value if hasattr(sector, "value") else str(sector)
        region = _COUNTRY_REGION.get(country.upper(), "africa")

        # Check for accumulated real data first
        acc = _load_accumulated()
        acc_key = f"{sector_str}:{region}"
        n_real = 0

        if acc_key in acc and acc[acc_key].get("n_orgs", 0) >= 5:
            cohort = acc[acc_key]
            n_real = cohort["n_orgs"]
            data_source = f"accumulated_n={n_real}"
        else:
            cohort = self._find_cohort(sector_str, region)
            data_source = "synthetic_seeded"

        if cohort is None:
            return PeerComparison(
                sector=sector_str, region=region, n_peers=0,
                overall_score_percentile=50.0, data_source="no_data",
            )

        overall_pct = _percentile(
            scoring.overall_score,
            cohort.get("overall_mean", 50.0),
            cohort.get("overall_std", 15.0),
        )

        domain_pcts: dict[str, float] = {}
        domain_means = cohort.get("domain_means", {})
        for ds in scoring.domain_scores:
            d_name = ds.domain.value
            if d_name in domain_means:
                domain_pcts[d_name] = _percentile(ds.score, domain_means[d_name], 14.0)

        return PeerComparison(
            sector=sector_str,
            region=region,
            n_peers=n_real,
            overall_score_percentile=overall_pct,
            domain_percentiles=domain_pcts,
            data_source=data_source,
        )

    def record(
        self,
        sector: str,
        country: str,
        scoring,
    ) -> None:
        """Record an anonymised assessment for future peer comparison.

        Updates the running mean, std, and count for the sector×region cohort.
        Only aggregate statistics are stored — no org identifiers.
        """
        sector_str = sector.value if hasattr(sector, "value") else str(sector)
        region = _COUNTRY_REGION.get(country.upper(), "africa")
        key = f"{sector_str}:{region}"

        acc = _load_accumulated()
        entry = acc.get(key, {
            "n_orgs": 0,
            "overall_sum": 0.0,
            "overall_sum_sq": 0.0,
            "overall_mean": 50.0,
            "overall_std": 15.0,
            "domain_sums": {},
            "domain_sum_sqs": {},
            "sector": sector_str,
            "region": region,
        })

        n = entry["n_orgs"] + 1
        s = entry["overall_sum"] + scoring.overall_score
        sq = entry["overall_sum_sq"] + scoring.overall_score ** 2
        entry["n_orgs"] = n
        entry["overall_sum"] = s
        entry["overall_sum_sq"] = sq
        entry["overall_mean"] = s / n
        variance = max(0.0, sq / n - (s / n) ** 2)
        entry["overall_std"] = math.sqrt(variance) if variance > 0 else 1.0

        d_sums = entry.setdefault("domain_sums", {})
        d_sq = entry.setdefault("domain_sum_sqs", {})
        for ds in scoring.domain_scores:
            k = ds.domain.value
            d_sums[k] = d_sums.get(k, 0.0) + ds.score
            d_sq[k] = d_sq.get(k, 0.0) + ds.score ** 2

        acc[key] = entry
        _ACCUMULATED_PATH.write_text(json.dumps(acc, indent=2), encoding="utf-8")


# Singleton used by build_report
_peer_store = PeerStore()
