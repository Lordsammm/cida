"""Generate country YAML files for the remaining 49 African countries.

Run once to populate `cida/config/countries/`. Idempotent: skips files that already exist
(NG, ZA, KE, GH, EG were created by hand with detailed values).

Usage:
    python -m scripts.generate_countries
"""
from __future__ import annotations

from pathlib import Path

import yaml

OUT_DIR = Path(__file__).resolve().parent.parent / "cida" / "config" / "countries"

# (iso_a2, iso_a3, name, region, currency, official_languages, ccTLDs (excluding base),
#  itu_gci_score, mobile_money_penetration, disclosure_factor,
#  insurance_regulator, data_protection_regulator, central_bank_regulator, cert,
#  freq_mult_overrides_dict)
# itu_gci_score = 0.0 means unknown -> defaults to 0.4
COUNTRIES = [
    # West Africa
    ("BJ", "BEN", "Benin", "West Africa", "XOF", ["fr"], 0.683, "high", 4.0,
     "CIMA", "GENERIC-DP", "BCEAO", "BJ-CERT", {"mobile_money_fraud": 3.0}),
    ("BF", "BFA", "Burkina Faso", "West Africa", "XOF", ["fr"], 0.587, "high", 4.5,
     "CIMA", "GENERIC-DP", "BCEAO", None, {"mobile_money_fraud": 3.0}),
    ("CI", "CIV", "Côte d'Ivoire", "West Africa", "XOF", ["fr"], 0.795, "high", 3.5,
     "CIMA", "GENERIC-DP", "BCEAO", "CI-CERT", {"mobile_money_fraud": 3.2}),
    ("GW", "GNB", "Guinea-Bissau", "West Africa", "XOF", ["pt"], 0.345, "medium", 5.0,
     "CIMA", "GENERIC-DP", "BCEAO", None, {}),
    ("ML", "MLI", "Mali", "West Africa", "XOF", ["fr"], 0.520, "high", 4.5,
     "CIMA", "GENERIC-DP", "BCEAO", None, {"mobile_money_fraud": 3.0}),
    ("NE", "NER", "Niger", "West Africa", "XOF", ["fr"], 0.504, "high", 4.5,
     "CIMA", "GENERIC-DP", "BCEAO", None, {}),
    ("SN", "SEN", "Senegal", "West Africa", "XOF", ["fr"], 0.789, "high", 3.5,
     "CIMA", "GENERIC-DP", "BCEAO", "SN-CSIRT", {"mobile_money_fraud": 3.2}),
    ("TG", "TGO", "Togo", "West Africa", "XOF", ["fr"], 0.679, "high", 4.0,
     "CIMA", "GENERIC-DP", "BCEAO", None, {}),
    ("GM", "GMB", "Gambia", "West Africa", "GMD", ["en"], 0.456, "medium", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("GN", "GIN", "Guinea", "West Africa", "GNF", ["fr"], 0.510, "medium", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("LR", "LBR", "Liberia", "West Africa", "LRD", ["en"], 0.430, "medium", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("SL", "SLE", "Sierra Leone", "West Africa", "SLE", ["en"], 0.515, "medium", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("CV", "CPV", "Cape Verde", "West Africa", "CVE", ["pt"], 0.622, "low", 3.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    # Central Africa
    ("CM", "CMR", "Cameroon", "Central Africa", "XAF", ["fr", "en"], 0.595, "high", 4.0,
     "CIMA", "GENERIC-DP", "BEAC", "CM-CERT", {"mobile_money_fraud": 3.0}),
    ("CF", "CAF", "Central African Republic", "Central Africa", "XAF", ["fr"], 0.215, "low", 5.5,
     "CIMA", "GENERIC-DP", "BEAC", None, {}),
    ("TD", "TCD", "Chad", "Central Africa", "XAF", ["fr", "ar"], 0.250, "medium", 5.0,
     "CIMA", "GENERIC-DP", "BEAC", None, {}),
    ("CG", "COG", "Republic of the Congo", "Central Africa", "XAF", ["fr"], 0.450, "medium", 4.5,
     "CIMA", "GENERIC-DP", "BEAC", None, {}),
    ("GQ", "GNQ", "Equatorial Guinea", "Central Africa", "XAF", ["es", "fr", "pt"], 0.401, "low", 5.0,
     "CIMA", "GENERIC-DP", "BEAC", None, {}),
    ("GA", "GAB", "Gabon", "Central Africa", "XAF", ["fr"], 0.620, "medium", 4.0,
     "CIMA", "GENERIC-DP", "BEAC", None, {}),
    ("CD", "COD", "Democratic Republic of the Congo", "Central Africa", "CDF", ["fr"], 0.395, "medium", 5.0,
     "ARCA", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("AO", "AGO", "Angola", "Central Africa", "AOA", ["pt"], 0.518, "low", 4.5,
     "ARSEG", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("ST", "STP", "São Tomé and Príncipe", "Central Africa", "STN", ["pt"], 0.298, "low", 5.0,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    # East Africa
    ("UG", "UGA", "Uganda", "East Africa", "UGX", ["en", "sw"], 0.690, "very_high", 3.5,
     "IRA-UG", "GENERIC-DP", "GENERIC-CB", "UG-CERT", {"mobile_money_fraud": 3.5}),
    ("TZ", "TZA", "Tanzania", "East Africa", "TZS", ["sw", "en"], 0.659, "very_high", 3.5,
     "TIRA", "GENERIC-DP", "GENERIC-CB", "TZ-CERT", {"mobile_money_fraud": 3.5}),
    ("RW", "RWA", "Rwanda", "East Africa", "RWF", ["rw", "fr", "en"], 0.792, "high", 3.0,
     "NBR-INS", "GENERIC-DP", "GENERIC-CB", "RW-CSIRT", {"mobile_money_fraud": 2.8}),
    ("BI", "BDI", "Burundi", "East Africa", "BIF", ["fr", "rn"], 0.310, "medium", 5.0,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("ET", "ETH", "Ethiopia", "East Africa", "ETB", ["am"], 0.554, "medium", 4.0,
     "NBE-INS", "GENERIC-DP", "GENERIC-CB", "Eth-CERT", {}),
    ("ER", "ERI", "Eritrea", "East Africa", "ERN", ["ti", "ar"], 0.190, "low", 5.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("DJ", "DJI", "Djibouti", "East Africa", "DJF", ["fr", "ar"], 0.330, "medium", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("SO", "SOM", "Somalia", "East Africa", "SOS", ["so", "ar"], 0.190, "high", 5.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {"mobile_money_fraud": 3.5}),
    ("SS", "SSD", "South Sudan", "East Africa", "SSP", ["en"], 0.150, "low", 5.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("SD", "SDN", "Sudan", "East Africa", "SDG", ["ar", "en"], 0.405, "medium", 5.0,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("KM", "COM", "Comoros", "East Africa", "KMF", ["ar", "fr"], 0.230, "low", 5.0,
     "CIMA", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("MG", "MDG", "Madagascar", "East Africa", "MGA", ["fr", "mg"], 0.405, "medium", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("MU", "MUS", "Mauritius", "East Africa", "MUR", ["en", "fr"], 0.785, "medium", 2.5,
     "FSC-MU", "GENERIC-DP", "GENERIC-CB", "CSIRT-MU", {}),
    ("SC", "SYC", "Seychelles", "East Africa", "SCR", ["en", "fr"], 0.652, "low", 3.0,
     "FSA-SC", "GENERIC-DP", "GENERIC-CB", None, {}),
    # Southern Africa
    ("ZW", "ZWE", "Zimbabwe", "Southern Africa", "ZWL", ["en", "sn", "nd"], 0.598, "medium", 4.0,
     "IPEC", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("ZM", "ZMB", "Zambia", "Southern Africa", "ZMW", ["en"], 0.643, "high", 3.5,
     "PIA-ZM", "GENERIC-DP", "GENERIC-CB", "ZM-CIRT", {"mobile_money_fraud": 2.8}),
    ("MW", "MWI", "Malawi", "Southern Africa", "MWK", ["en", "ny"], 0.502, "high", 4.0,
     "RBM-INS", "GENERIC-DP", "GENERIC-CB", None, {"mobile_money_fraud": 2.8}),
    ("MZ", "MOZ", "Mozambique", "Southern Africa", "MZN", ["pt"], 0.490, "high", 4.0,
     "ISSM", "GENERIC-DP", "GENERIC-CB", None, {"mobile_money_fraud": 2.5}),
    ("BW", "BWA", "Botswana", "Southern Africa", "BWP", ["en", "tn"], 0.715, "medium", 3.0,
     "NBFIRA", "GENERIC-DP", "GENERIC-CB", "BW-CSIRT", {}),
    ("NA", "NAM", "Namibia", "Southern Africa", "NAD", ["en"], 0.625, "medium", 3.5,
     "NAMFISA", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("LS", "LSO", "Lesotho", "Southern Africa", "LSL", ["en", "st"], 0.510, "medium", 4.0,
     "CBL-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("SZ", "SWZ", "Eswatini", "Southern Africa", "SZL", ["en", "ss"], 0.555, "medium", 4.0,
     "FSRA-SZ", "GENERIC-DP", "GENERIC-CB", None, {}),
    # North Africa
    ("MA", "MAR", "Morocco", "North Africa", "MAD", ["ar", "fr"], 0.843, "medium", 2.8,
     "ACAPS", "GENERIC-DP", "GENERIC-CB", "CERT-MA", {}),
    ("DZ", "DZA", "Algeria", "North Africa", "DZD", ["ar", "fr"], 0.713, "low", 3.5,
     "CNA-DZ", "GENERIC-DP", "GENERIC-CB", None, {}),
    ("TN", "TUN", "Tunisia", "North Africa", "TND", ["ar", "fr"], 0.825, "medium", 2.8,
     "CGA", "GENERIC-DP", "GENERIC-CB", "TN-CERT", {}),
    ("LY", "LBY", "Libya", "North Africa", "LYD", ["ar"], 0.440, "low", 4.5,
     "GENERIC-INS", "GENERIC-DP", "GENERIC-CB", None, {}),
]

DEFAULT_FREQ = {
    "bec": 1.20,
    "ransomware": 0.85,
    "data_breach": 1.05,
    "ddos": 0.85,
    "insider": 1.20,
    "third_party": 1.00,
    "mobile_money_fraud": 2.50,
}

ITU_TIER_THRESHOLDS = [(0.85, "T1"), (0.65, "T2"), (0.45, "T3"), (0.0, "T4")]


def tier_for(score: float) -> str:
    for threshold, tier in ITU_TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "T5"


def build_country(row: tuple) -> dict:
    iso2, iso3, name, region, currency, langs, gci, mm_pen, disc, ins, dp, cb, cert, freq_over = row
    base = currency  # not used further
    freq = dict(DEFAULT_FREQ)
    freq.update(freq_over)
    # Adjust mobile money frequency by penetration
    pen_mult = {"very_high": 1.4, "high": 1.0, "medium": 0.7, "low": 0.4}.get(mm_pen, 1.0)
    freq["mobile_money_fraud"] = round(freq["mobile_money_fraud"] * pen_mult, 2)

    cctlds = [f".{iso2.lower()}"]
    out = {
        "iso_a2": iso2,
        "iso_a3": iso3,
        "name": name,
        "region": region,
        "sub_region": "North Africa" if region == "North Africa" else "Sub-Saharan Africa",
        "currency": currency,
        "official_languages": langs,
        "ccTLDs": cctlds,
        "disclosure_correction_factor": disc,
        "mobile_money_penetration": mm_pen,
        "base_frequency_multipliers": freq,
        "regulators": {
            "insurance": ins,
            "data_protection": dp,
            "central_bank": cb,
            "sector": {},
        },
        "cert": cert,
        "intel_sources": [],
    }
    if gci > 0:
        out["itu_gci"] = {"edition": 6, "year": 2024, "score": gci, "tier": tier_for(gci)}
    return out


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    created = skipped = 0
    for row in COUNTRIES:
        iso2 = row[0]
        path = OUT_DIR / f"{iso2}.yaml"
        if path.exists():
            skipped += 1
            continue
        data = build_country(row)
        with path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
        created += 1
    print(f"Created {created} country files, skipped {skipped} (already existed).")
    print(f"Total country files: {len(list(OUT_DIR.glob('*.yaml')))}")


if __name__ == "__main__":
    main()
