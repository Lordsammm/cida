# Config

All calibration lives here as plain YAML. No code changes needed to add a country, update a prior, or add a regulator.

```
countries/           54 African countries - regulators, FX currency, frequency multipliers, disclosure correction
regulators/
  insurance/         NAICOM, FSCA, IRA-KE, NIC-GH, CIMA, TIRA, IPEC …
  data_protection/   NDPC, IR-ZA (POPIA), ODPC-KE, DPC-GH …
  financial/         CBN, SARB, CBK, BoG, BCEAO, BEAC …
  sector/            NITDA, NCC, PenCom, SEC-NG
sectors/             9 verticals - frequency + severity multipliers per industry
frameworks/          13 compliance frameworks - crosswalked to the control catalog
priors/
  global.yaml        Bayesian frequency + severity priors, 20+ cited sources
  africa-overlay.yaml  Continental frequency lifts, 13 African sources
fx_rates.yaml        Indicative USD→local rates for all 54 currencies
vector_matrix.yaml   14 × 10 ThreatVector × LossDriver multiplier table
```

## countries/

`{ISO2}.yaml`, key fields:

| Field | Notes |
|-------|-------|
| `currency` | ISO-4217 code - drives local currency premium output |
| `disclosure_correction_factor` | Under-reporting multiplier (3–5 typical for Africa) |
| `mobile_money_penetration` | `low` / `medium` / `high` / `very_high` |
| `base_frequency_multipliers` | Per-driver lift on top of global + Africa priors |
| `regulators` | References to insurance / data_protection / central_bank IDs |

```powershell
python -m cida.cli list-countries
```

## regulators/

Referenced by ID from country configs. Each file holds the authority's name, scope, and cyber-relevant directives that feed into posture scoring.

```powershell
python -m cida.cli list-regulators --kind insurance
python -m cida.cli list-regulators --kind data_protection
python -m cida.cli list-regulators --kind financial
python -m cida.cli list-regulators --kind sector
```

## sectors/

| File | Covers |
|------|--------|
| `banking.yaml` | Banks, MFIs |
| `insurance.yaml` | Life, general, composite |
| `fintech.yaml` | Payments, neobanks, digital lenders |
| `pension.yaml` | PFAs, trustees |
| `healthcare.yaml` | Hospitals, HMOs |
| `telecom.yaml` | MNOs, ISPs |
| `education.yaml` | Universities, e-learning |
| `manufacturing.yaml` | Industrial / OT |
| `other.yaml` | Default |

Each file: `base_frequency_multipliers`, `severity_multipliers`, `required_frameworks`.

## frameworks/

Posture = % of crosswalked controls scoring ≥ 70. Applied by sector and country automatically.

`nist-csf-2.0.yaml` · `iso-27001-2022.yaml` · `cis-v8.yaml` · `pci-dss-v4.yaml` · `hipaa.yaml` · `eu-gdpr.yaml` · `ndpr-2023.yaml` · `malabo-convention.yaml` · `fsca-js1-2023.yaml`

New framework: add a YAML + crosswalk entries in the control catalog.

## priors/

`global.yaml`, Gamma frequency priors + Lognormal severity priors for all 10 LossDrivers. Sources: DBIR, NetDiligence, Coalition, IBM/Ponemon, Sophos, Hiscox, IC3, ENISA, Mandiant, CrowdStrike, Cyentia IRIS, Munich Re, CRO Forum, Chainalysis, Dragos, CBN, NDPC, POPIA IR, AON Africa.

`africa-overlay.yaml`, multipliers on top of global. Sources: Interpol Africa, Serianu, GSMA, Mastercard Africa, Smile ID, KE-CIRT, ngCERT, CSEAN, AON Africa, AfDB.

Update with real claims: `python -m cida.cli update-priors --claims claims.yaml --out cida/config/priors/global.yaml`

## fx_rates.yaml

Indicative mid-2026 rates (1 USD = X local). Used for premium output in local currency. Update periodically, these don't affect the actuarial calculations, only the display.

## vector_matrix.yaml

14 × 10 multiplier: frequency lift when a threat vector is fully saturated (score = 100). Engine interpolates linearly between 1.0 (score 0) and the cell value (score 100). Calibration: DBIR 2024, Coalition 2024, IBM 2024, Mandiant 2024, CrowdStrike 2024, MITRE ATT&CK v15, CISA KEV, FBI IC3, Sophos 2024, GSMA/Mastercard Africa 2024.
