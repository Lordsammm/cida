# CIDA, Cyber Intelligence Decision Algorithm

Underwriting decision-support engine for cyber-insurance carriers operating in Africa.

CIDA ingests a filled questionnaire (CSV) and technical assessment artefacts (VAPT reports, vulnerability scans, cloud CSPM, attack-surface data, dark-web intel, DMARC checks), enriches vulnerabilities with CVE / EPSS / KEV, scores the organisation on a **two-layer model, 14 ThreatVectors × 10 LossDrivers** wired through a calibrated multiplier matrix, runs a hierarchical Bayesian actuarial model with blended global + African priors, and produces JSON + HTML + PDF underwriting reports.

> **CIDA is decision support.** Final pricing and binding authority remain with the issuing carrier.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical design.

## Quick start

```powershell
# Install (Python 3.11+)
pip install -e .

# Run the built-in demo (bundled sample data, no internet required)
python -m cida.cli demo --offline

# Validate the model against the 10 reference cases
python -m cida.cli backtest

# Inspect supported jurisdictions
python -m cida.cli list-countries
python -m cida.cli list-regulators --kind data_protection
```

## Scoring a real client

```powershell
Copy-Item -Recurse "clients\_TEMPLATE" "clients\Tangerine Bank 2025"
# fill in org_profile.yaml, drop in the questionnaire.csv export

python -m cida.cli score-project "clients/Tangerine Bank 2025"
python -m cida.cli score-project "clients/Tangerine Bank 2025" --offline  # skip live CVE/news
python -m cida.cli score-project "clients/Tangerine Bank 2025" --limitation "GCP not in scope"
```

Drop any combination of artefacts in the folder, file names don't matter, content is auto-detected:

```
clients/Tangerine Bank 2025/
  org_profile.yaml          ← required
  questionnaire.csv         ← required (merged export from the CIDA platform)
  nessus_scan.xml           ← any name
  vapt_report.pdf
  prowler_output.json
  shodan_export.json
  darkweb_intel.csv
  dmarc_check.json
  screenshot1.png
```

Output goes to `clients/Tangerine Bank 2025/output/`:

| File | For |
|------|-----|
| `<org_id>_yoa_report.html` | Client |
| `<org_id>_report.html` | Underwriter |
| `<org_id>_report.json` | Full data payload |
| `<org_id>_scored_block.json` | Compact underwriting summary |

Terminal output (Nigerian org, all figures in USD + NGN):

```
-- UNDERWRITING SUMMARY --------------------------------------------------
  Organisation    : Tangerine Bank Plc  (banking / NG)
  Currency        : NGN  (1 USD = 1,610.00 NGN)
  Security Posture: 58%  (ELEVATED RISK)
  Tier            : 3 -- Adequate
  Expected Annual Loss   : $4,210,000 USD  /  NGN 6,778,100,000
  Max Probable Loss (P99): $18,900,000 USD  /  NGN 30,429,000,000
  Technical Premium      : $6,350,000 USD  /  NGN 10,223,500,000
  Suggested Limit        : $5,000,000 USD  /  NGN 8,050,000,000
  Suggested Retention    : $63,500 USD  /  NGN 102,235,000
  Findings: 3 Critical  8 High  14 Medium  6 Low
  Incident Probabilities:
    Ransomware Risk                23.4%
    Phishing / BEC                 41.2%
    Data Breach / Privacy Liability 18.7%

```

## Pricing and local currency

All actuarial calculations, expected loss, VaR, TVaR, premium, are computed in USD, which is the universal reinsurance reference currency. At output time, every monetary figure is converted to the org's local currency using the rate from `cida/config/fx_rates.yaml`.

The conversion is automatic: the org's `country` field in `org_profile.yaml` resolves the currency code from the country config (e.g. `NG → NGN`, `ZA → ZAR`, `KE → KES`), which maps to the FX rate table. No manual input needed.

**What the underwriter gets:**

| Output | USD | Local currency |
|--------|-----|---------------|
| Technical premium | ✓ | ✓ |
| Suggested aggregate limit | ✓ | ✓ |
| Suggested retention | ✓ | ✓ |
| Maximum probable loss (P99) | ✓ | ✓ |
| Per-driver sub-limits | ✓ | - |

The FX rates in `fx_rates.yaml` are indicative mid-2026 mid-market estimates. Update them periodically or swap in a live API call if needed, they only affect display output, not the actuarial model.

## Alternative: explicit file paths

For scripting or CI, pass files directly instead of using a folder:

```powershell
python -m cida.cli score `
  --org-profile path/to/org.yaml `
  --questionnaire path/to/responses.csv `
  --findings path/to/scanner_outputs/ `
  --out out/report.pdf
```

## How CIDA scores an organisation

```
Questionnaire CSV  +  Org profile YAML  +  Assessment artefacts
        │
        ▼
   1. Scoring engine
        per-control score (0–100) → per-domain rollup → overall score → Tier 1–5

        ▼
   2. Threat vector scoring (14 vectors)
        findings routed by source type → severity points
        questionnaire responses → control deficit
        combined → VectorScore(0–100, HIGH/MEDIUM/LOW confidence)

        ▼
   3. Bayesian actuarial model (10 LossDrivers × 10,000 Monte Carlo sims)
        λ = (α/β prior) × sector_mult × country_mult × disclosure_correction
                        × Π over 14 vectors of (1 + score/100 × matrix_cell)
        Gamma(λ) → Poisson(counts) → Lognormal(severity)
        → EL, VaR₉₅, TVaR₉₉, P50/P90/P99 per driver + aggregate

        ▼
   4. ML residual layer (XGBoost on log-EL residual; neutral 1.0× until trained)

        ▼
   5. Risk summary
        risk_score, likelihood vs peer, attack surface,
        posture signals, vector scores, likelihood drivers

        ▼
   JSON + HTML + PDF reports
```

## Supported assessment artefacts

Classification is content-based, file names and extensions do not matter.

| Category | Supported tools |
|----------|----------------|
| **Vulnerability scanners** | Nessus, Qualys, OpenVAS/Greenbone, Rapid7 InsightVM/Nexpose, Metasploit, Tenable.io |
| **Web app scanners** | Burp Suite, OWASP ZAP, Nikto, Acunetix, IBM AppScan, w3af, Arachni |
| **Network scanners** | Nmap, Masscan, Zmap |
| **AWS CSPM** | AWS Prowler v3/v4, AWS Security Hub (ASFF) |
| **Azure CSPM** | Azure Defender for Cloud, Microsoft Sentinel, ScoutSuite (Azure) |
| **GCP CSPM** | GCP Security Command Center, ScoutSuite (GCP) |
| **Multi-cloud** | Wiz, Orca Security, Prisma Cloud |
| **Attack surface / OSINT** | Shodan, Censys, Amass, theHarvester, Recon-ng, BBOT, Subfinder, Nuclei |
| **Dark web / credential intel** | SpyCloud, DeHashed, Hudson Rock, Flare, HIBP, stealer log dumps (RedLine, Raccoon, Vidar, Lumma) |
| **Email security** | checkdmarc, hardenize, dmarcian, mail-tester |
| **VAPT reports** | Any PDF - pdfplumber text + table extraction |
| **Evidence** | PNG, JPEG, SVG, WebP screenshots - embedded in YOA report |
| **Pre-normalised** | CIDA Finding JSON (skip parsing, go straight to scoring) |

Full tool list with supported formats → [`cida/ingest/README.md`](cida/ingest/README.md)

## Compliance frameworks

Posture is scored as the % of crosswalked controls scoring ≥ 70. Applicable
frameworks are selected automatically based on sector and country.

| Framework | Applies to |
|-----------|-----------|
| NIST Cybersecurity Framework 2.0 | All sectors |
| ISO/IEC 27001:2022 | All sectors |
| CIS Controls v8 | All sectors |
| SOC 2 TSC | All sectors |
| PCI-DSS v4.0 | Banking, fintech, insurance (card issuers) |
| HIPAA Security Rule | Healthcare, HMOs |
| EU GDPR | Any org handling EU personal data |
| Nigeria NDPR / NDPA 2023 | Nigerian organisations |
| South Africa POPIA | South African organisations |
| CCPA | Orgs with California data subjects |
| African Union Malabo Convention | AU member states |
| FSCA Joint Standard 1:2023 | South African financial services |

Full framework config → [`cida/config/README.md`](cida/config/README.md)

## Supported countries (54)

All actuarial, regulatory, and disclosure parameters are calibrated per country.
Run `python -m cida.cli list-countries` for the full table, or see below:

| Code | Country | Currency | Region |
|------|---------|----------|--------|
| AO | Angola | AOA | Central Africa |
| BF | Burkina Faso | XOF | West Africa |
| BI | Burundi | BIF | East Africa |
| BJ | Benin | XOF | West Africa |
| BW | Botswana | BWP | Southern Africa |
| CD | DR Congo | CDF | Central Africa |
| CF | Central African Republic | XAF | Central Africa |
| CG | Republic of the Congo | XAF | Central Africa |
| CI | Côte d'Ivoire | XOF | West Africa |
| CM | Cameroon | XAF | Central Africa |
| CV | Cape Verde | CVE | West Africa |
| DJ | Djibouti | DJF | East Africa |
| DZ | Algeria | DZD | North Africa |
| EG | Egypt | EGP | North Africa |
| ER | Eritrea | ERN | East Africa |
| ET | Ethiopia | ETB | East Africa |
| GA | Gabon | XAF | Central Africa |
| GH | Ghana | GHS | West Africa |
| GM | Gambia | GMD | West Africa |
| GN | Guinea | GNF | West Africa |
| GQ | Equatorial Guinea | XAF | Central Africa |
| GW | Guinea-Bissau | XOF | West Africa |
| KE | Kenya | KES | East Africa |
| KM | Comoros | KMF | East Africa |
| LR | Liberia | LRD | West Africa |
| LS | Lesotho | LSL | Southern Africa |
| LY | Libya | LYD | North Africa |
| MA | Morocco | MAD | North Africa |
| MG | Madagascar | MGA | East Africa |
| ML | Mali | XOF | West Africa |
| MR | Mauritania | MRU | West Africa |
| MU | Mauritius | MUR | East Africa |
| MW | Malawi | MWK | Southern Africa |
| MZ | Mozambique | MZN | Southern Africa |
| NA | Namibia | NAD | Southern Africa |
| NE | Niger | XOF | West Africa |
| NG | Nigeria | NGN | West Africa |
| RW | Rwanda | RWF | East Africa |
| SC | Seychelles | SCR | East Africa |
| SD | Sudan | SDG | East Africa |
| SL | Sierra Leone | SLE | West Africa |
| SN | Senegal | XOF | West Africa |
| SO | Somalia | SOS | East Africa |
| SS | South Sudan | SSP | East Africa |
| ST | São Tomé & Príncipe | STN | Central Africa |
| SZ | Eswatini | SZL | Southern Africa |
| TD | Chad | XAF | Central Africa |
| TG | Togo | XOF | West Africa |
| TN | Tunisia | TND | North Africa |
| TZ | Tanzania | TZS | East Africa |
| UG | Uganda | UGX | East Africa |
| ZA | South Africa | ZAR | Southern Africa |
| ZM | Zambia | ZMW | Southern Africa |
| ZW | Zimbabwe | ZWL | Southern Africa |

## Currency handling

All actuarial calculations (expected loss, VaR, premium) are in **USD** as the
universal base currency. In `org_profile.yaml`:

* `annual_revenue_usd`, used by the actuarial model for severity scaling
* `annual_revenue_local` + `local_currency`, displayed in the report header for the client's reference, not used in calculations

Exchange rates are not applied automatically. If the client's revenue is stated
in a local currency, convert to USD before entering it in `annual_revenue_usd`.

## Supported regulators

Run `python -m cida.cli list-regulators --kind <type>` where type is one of
`insurance`, `data_protection`, `financial`, or `sector`.

| ID | Name | Type | Country / Scope |
|----|------|------|----------------|
| NAICOM | National Insurance Commission | insurance | NG |
| FSCA | Financial Sector Conduct Authority | insurance | ZA |
| IRA-KE | Insurance Regulatory Authority | insurance | KE |
| NIC-GH | National Insurance Commission | insurance | GH |
| CIMA | Conférence Interafricaine des Marchés d'Assurances | insurance | UEMOA/CEMAC |
| TIRA | Tanzania Insurance Regulatory Authority | insurance | TZ |
| IRA-UG | Insurance Regulatory Authority | insurance | UG |
| IPEC | Insurance and Pensions Commission | insurance | ZW |
| NDPC | Nigeria Data Protection Commission | data_protection | NG |
| IR-ZA | Information Regulator (POPIA) | data_protection | ZA |
| ODPC-KE | Office of Data Protection Commissioner | data_protection | KE |
| DPC-GH | Data Protection Commission | data_protection | GH |
| CBN | Central Bank of Nigeria | financial | NG |
| SARB | South African Reserve Bank | financial | ZA |
| CBK | Central Bank of Kenya | financial | KE |
| BoG | Bank of Ghana | financial | GH |
| BCEAO | Banque Centrale des États de l'Afrique de l'Ouest | financial | UEMOA |
| NITDA | National IT Development Agency | sector | NG |
| NCC | Nigerian Communications Commission | sector | NG |
| PenCom | National Pension Commission | sector | NG |
| SEC-NG | Securities and Exchange Commission | sector | NG |

Full regulator config → [`cida/config/README.md`](cida/config/README.md)

## Repository layout

```
cida/                        ← project root
  clients/                   ← client assessment folders (gitignored - sensitive data)
    _TEMPLATE/               ← copy this for each new client
      org_profile.yaml
      questionnaire.csv
  cida/                      ← Python package
    catalog/                 ← control catalog (YAML) + framework crosswalks
    config/
      countries/             ← 54 African country configs
      regulators/            ← NAICOM / FSCA / IRA-KE / CIMA / NITDA / NDPC / …
      sectors/               ← banking, insurance, fintech, pension, education, …
      frameworks/            ← NIST CSF 2.0, ISO 27001, CIS v8, PCI-DSS v4, …
      priors/                ← global.yaml + africa-overlay.yaml (source-cited)
      vector_matrix.yaml     ← 14×10 ThreatVector × LossDriver multipliers
    ingest/                  ← parsers: questionnaire CSV, Nessus, Burp, Prowler,
                             ←          Shodan, VAPT PDF, dark-web, DMARC
    enrich/                  ← CVE / EPSS / KEV enrichment + news intel adapters
    scoring/                 ← engine.py, vectors.py, risk_summary.py
    actuarial/               ← model.py (Bayesian MC), premium.py, posterior_update.py
    ml/                      ← XGBoost residual layer (neutral until trained)
    posture/                 ← multi-framework compliance posture
    report/                  ← HTML + PDF renderers + Jinja2 templates
    backtest/                ← 10-case reference runner
    cli.py                   ← Typer CLI
    examples/                ← bundled sample data for `cida demo`
  tests/                     ← pytest suite + backtest cases
  docs/                      ← ARCHITECTURE.md + design notes
  scripts/                   ← generate_countries.py (one-time scaffold utility)
  foundation/                ← source reference documents (BRD, sample reports, …)
```

## Status

| Check | Result |
|-------|--------|
| Unit tests (`pytest tests/`) | 161 passed, 1 skipped |
| Backtest (10 reference cases) | Tier 100% · Score-band 100% · EL-band 100% |
| Monte Carlo simulations per run | 10,000 |
| ThreatVectors | 14 |
| LossDrivers (coverage lines) | 10 |
| African country configs | 54 |
| Regulator profiles | 30+ |
| Compliance frameworks | 13 |
| Source citations in priors | 20+ |

The ML residual layer ships neutral (1.0×) until trained on real African claim data. The Bayesian baseline carries the full prediction until then.

## Refreshing priors with real claims

Once pilot carriers feed back observed claims:

```powershell
python -m cida.cli update-priors --claims path/to/claims.yaml --out cida/config/priors/global.yaml
```

The command runs Gamma (frequency) and Lognormal (severity) conjugate posterior updates and writes the updated priors back to the config. This sharpens all future assessments without retraining the ML layer.

## Disclaimer

CIDA outputs are **advisory**. Cyber risk is irreducibly stochastic; every estimate ships with a calibrated uncertainty interval (90% CI on score, P50/P90/P99 on aggregate loss). Carriers retain full underwriting authority.
