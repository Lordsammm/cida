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
cida demo --offline

# Validate the model against the 10 reference cases
cida backtest

# Inspect supported jurisdictions
cida list-countries
cida list-regulators --kind data_protection
```

## Scoring a real client

```powershell
Copy-Item -Recurse "clients\_TEMPLATE" "clients\Apex Bank 2025"
# fill in org_profile.yaml, drop in the questionnaire.csv export

cida score-project "clients/Apex Bank 2025"
cida score-project "clients/Apex Bank 2025" --offline  # skip live CVE/news
cida score-project "clients/Apex Bank 2025" --limitation "GCP not in scope"
```

Drop any combination of artefacts in the folder, file names don't matter, content is auto-detected:

```
clients/Apex Bank 2025/
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

Output goes to `clients/Apex Bank 2025/output/`:

| File | For |
|------|-----|
| `<org_id>_policyholder_report.html` | Client |
| `<org_id>_report.html` | Underwriter |
| `<org_id>_report.json` | Full data payload |
| `<org_id>_scored_block.json` | Compact underwriting summary |

Terminal output (Nigerian org, all figures in USD + NGN):

```
-- UNDERWRITING SUMMARY --------------------------------------------------
  Organisation    : Apex Bank Plc  (banking / NG)
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

All actuarial calculations, expected loss, VaR, TVaR, premium, are computed in USD, which is the universal reinsurance reference currency. At output time, every monetary figure is converted to the org's local currency using the rate from `config/fx_rates.yaml`.

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
cida score `
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
        Domain weights loaded from config/scoring_weights.yaml
        Calibrated from 16 primary sources (Verizon DBIR, Coalition, IBM,
        Sophos, Mandiant, CrowdStrike, Munich Re, Corvus, Beazley, Interpol
        Africa, Serianu, GSMA, Smile ID, At-Bay, WEF, Munich Re)

        ▼
   2. Threat vector scoring (14 vectors)
        findings routed by source type → severity points
        questionnaire responses → control deficit
        combined → VectorScore(0–100, HIGH/MEDIUM/LOW confidence)

        ▼
   3. Bayesian actuarial model (10 LossDrivers × 10,000 Monte Carlo sims)
        λ = (α/β prior) × sector_mult × country_mult × ctrl_mult × intel_mult
                        × disclosure_correction_driver  (per-driver observability-weighted)
        Gamma(λ) → correlated via Gaussian copula (Iman-Conover) → Poisson(counts)
        → Lognormal(severity, revenue^elasticity_driver × sector_sev_mult)
        → EL, VaR₉₅, TVaR₉₉, P50/P90/P99 per driver + aggregate
        Three improvements over a basic model:
          * Loss driver correlation: single event triggers multiple coverage lines
          * Per-driver disclosure: regulatory penalties (90% observed) vs. fraud (30%)
          * Per-driver elasticity: BI scales at revenue^0.60; BEC at revenue^0.25

        ▼
   4. ML residual layer (XGBoost on log-EL residual; neutral 1.0× until trained)

        ▼
   5. Risk summary
        risk_score, likelihood vs peer, attack surface,
        posture signals, vector scores, likelihood drivers

        ▼
   JSON + HTML + PDF reports
```

Domain weights by source (from `config/scoring_weights.yaml`):

| Domain | Weight | Key evidence |
|--------|--------|--------------|
| Identity and Access Management | 16% | Coalition 2025: 60% of claims = BEC/FTF; Verizon DBIR 2024: credentials in 38% of breaches |
| Endpoint Security | 13% | Corvus 2024: EDR = 60% severity reduction; Sophos 2024: ransomware hit 59% of orgs |
| Detection and Response | 13% | IBM Ponemon 2024: AI/automation saves $1.88M per breach |
| Resilience and Recovery | 10% | Corvus 2024: backup presence = 72% lower median claim cost |
| Network Security | 10% | Corvus Q3 2024: VPN vulns = 28.7% of ransomware incidents |
| Third-Party and Supply Chain | 9% | WEF 2024: 41% of firms affected by third-party incident; GSMA 2024: mobile money API risk |
| Governance | 8% | Mandatory under CBN 2024, FSCA JS2 2024, SARB Directive 01/2024 |
| Asset and Data Management | 8% | CrowdStrike 2025: 52% of vulns require asset visibility to detect |
| Application Security | 7% | Mandiant M-Trends 2025: exploits = 33% of initial access |
| Cloud Security | 6% | Africa-specific: cloud penetration below global average |

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
| **Evidence** | PNG, JPEG, SVG, WebP screenshots - embedded in Policyholder Report |
| **Pre-normalised** | CIDA Finding JSON (skip parsing, go straight to scoring) |

Full tool list with supported formats → [`ingest/README.md`](ingest/README.md)

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
| FSCA Joint Standard 1:2023 | South African financial institutions |
| FSCA Joint Standard 2:2024 | South African financial institutions (effective June 2025) |
| CBN Risk-Based Cybersecurity Framework 2024 | Nigerian deposit money banks and payment service banks |
| NIST SP 800-53 Rev 5 | All sectors; referenced in CBN 2024, BdM 2025, CBE frameworks |

Full framework config → [`config/README.md`](config/README.md)

## Supported countries (54)

All actuarial, regulatory, and disclosure parameters are calibrated per country.
Run `cida list-countries` for the full table, or see below:

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

FX conversion is automatic: the org's country resolves the currency code (e.g. NG gives NGN, ZA gives ZAR), which maps to the rate in `config/fx_rates.yaml`. Revenue should always be entered in USD in `annual_revenue_usd` for accurate actuarial scaling.

## Supported regulators

Run `cida list-regulators --kind <type>` where type is one of
`insurance`, `data_protection`, `financial`, or `sector`.

**Insurance supervisors (25+)**

| ID | Name | Country / Scope |
|----|------|----------------|
| NAICOM | National Insurance Commission | Nigeria |
| FSCA | Financial Sector Conduct Authority | South Africa |
| IRA-KE | Insurance Regulatory Authority | Kenya |
| NIC-GH | National Insurance Commission | Ghana |
| CIMA | Conference Interafricaine des Marches d'Assurances | UEMOA/CEMAC (14 states) |
| TIRA | Tanzania Insurance Regulatory Authority | Tanzania |
| IRA-UG | Insurance Regulatory Authority | Uganda |
| IPEC | Insurance and Pensions Commission | Zimbabwe |
| ACAPS | Autorite de Controle des Assurances | Morocco |
| FRA-EG | Financial Regulatory Authority | Egypt |
| FSC-MU | Financial Services Commission | Mauritius |
| NAMFISA | Namibia Financial Institutions Supervisory Authority | Namibia |
| NBR-INS | National Bank of Rwanda Insurance | Rwanda |
| ...and 12 more | Full list: `cida list-regulators --kind insurance` | |

**Data protection authorities (38)**

37 African countries with enacted data protection laws are mapped to a specific authority. 17 countries have no enacted law and correctly use a generic framework. Key entries:

| ID | Name | Law | Notification | Country |
|----|------|-----|-------------|---------|
| NDPC | Nigeria Data Protection Commission | NDPA 2023 | 72h | Nigeria |
| IR-ZA | Information Regulator (POPIA) | POPIA 2013 | 72h | South Africa |
| ODPC-KE | Office of Data Protection Commissioner | DPA 2019 | 72h | Kenya |
| DPC-GH | Data Protection Commission | DPA 2012 | 72h | Ghana |
| ODPC-ZM | Office of Data Protection Commissioner | DPA No. 3 of 2021 | 24h | Zambia |
| POTRAZ-ZW | POTRAZ (Cyber and Data Protection) | Act 2021; SI 155/2024 | 24h | Zimbabwe |
| MACRA-MW | Malawi Communications Regulatory Authority | DPA 2024 | 72h | Malawi |
| ECA-ET | Ethiopian Communications Authority | Proclamation 1321/2024 | 72h | Ethiopia |
| DPC-BW | Office of Data Protection Commissioner | DPA No. 18 of 2024 | 72h | Botswana |
| IC-GM | Information Commission of The Gambia | PDPPA 2025 | 72h | Gambia |
| IC-SC | Information Commission of Seychelles | DPA No. 24 of 2023 | 72h | Seychelles |
| ANPDP-DZ | Autorite Nationale de Protection des Donnees | Law 18-07 (amended 2025) | 5 days | Algeria |
| APD-AO | Agencia de Protecao de Dados | Law 22/11 of 2011 | 24h | Angola |
| ANPDP-MZ | Agencia Nacional de Protecao de Dados Pessoais | Law 7/2021 | 72h | Mozambique |
| DPDPA-SL | Data Protection and Privacy Authority | DPA 2022 | 72h | Sierra Leone |
| ...and 23 more | Full list: `cida list-regulators --kind data_protection` | | |

**Central banks and financial regulators (43)**

All 54 African countries are mapped to a specific central bank or regional monetary authority. Key entries with published cybersecurity directives:

| ID | Name | Key cyber directive | Scope |
|----|------|---------------------|-------|
| CBN | Central Bank of Nigeria | Risk-Based Cybersecurity Framework 2024 (effective July 2024) | Nigeria |
| SARB | South African Reserve Bank | Directive 01/2024 (2hr RTO); Joint Standard 2/2024 (June 2025) | South Africa |
| CBK | Central Bank of Kenya | Risk-Based Cybersecurity Framework | Kenya |
| BoG | Bank of Ghana | Cybersecurity Directive | Ghana |
| CBE | Central Bank of Egypt | Financial Cybersecurity Framework; sectoral CERT | Egypt |
| BAM | Bank Al-Maghrib | Circular 5/W/2014; Cyber Resilience Directive 2023 | Morocco |
| BNR | National Bank of Rwanda | Cyber Regulation 2021 | Rwanda |
| BoT | Bank of Tanzania | Cybersecurity Directive 2023 | Tanzania |
| BOU-UG | Bank of Uganda | Cyber Risk Management Guidelines (mandatory December 2024) | Uganda |
| RBZ-ZW | Reserve Bank of Zimbabwe | Cybersecurity and Resilience Guideline August 2025 | Zimbabwe |
| NBE-ET | National Bank of Ethiopia | Directive MFI/33/2022; SBB/94/2025 | Ethiopia |
| BDM-MZ | Banco de Mocambique | Notice 8/GBM/2025 (mandatory 24h incident reporting) | Mozambique |
| CBL-LY | Central Bank of Libya | IT Governance Regulation 2023/21 (COBIT 2019, 105 pages) | Libya |
| CBE-SZ | Central Bank of Eswatini | Guidelines on Cybersecurity No. 1 of 2021 (binding) | Eswatini |
| BOM-MU | Bank of Mauritius | Cybersecurity Framework for Financial Institutions 2023 | Mauritius |
| BCEAO | Banque Centrale des Etats de l Afrique de l Ouest | Regional framework | 8 UEMOA countries |
| BEAC | Banque des Etats de l Afrique Centrale | Regional framework | 6 CEMAC countries |
| ...and 26 more | Full list: `cida list-regulators --kind financial` | | |

**Sector regulators (6)**

| ID | Name | Sector | Country |
|----|------|--------|---------|
| NITDA | National IT Development Agency | Technology / data | Nigeria |
| NCC | Nigerian Communications Commission | Telecoms | Nigeria |
| PenCom | National Pension Commission | Pension | Nigeria |
| SEC-NG | Securities and Exchange Commission | Capital markets | Nigeria |
| CA-KE | Communications Authority of Kenya | Telecoms / critical infrastructure | Kenya |
| NCSA-RW-SECTOR | Rwanda National Cyber Security Authority | Cross-sector CII | Rwanda |

Full regulator config → [`config/README.md`](config/README.md)

## Repository layout

```
cida/                        ← project root (flat layout: source at root, not in a subfolder)
  cli.py                     ← Typer CLI: score-project, score, demo, backtest, update-priors
  models.py                  ← all Pydantic data models; single source of truth
  clients/                   ← client assessment folders (gitignored - sensitive data)
    _TEMPLATE/               ← copy this for each new client
      org_profile.yaml
      questionnaire.csv
  catalog/                   ← 41 controls with multi-framework crosswalks
  config/
    countries/               ← 54 African country configs (regulators, currency, multipliers)
    regulators/
      insurance/             ← 26 insurance supervisors (NAICOM, FSCA, CIMA, IRA-KE ...)
      data_protection/       ← 38 data protection authorities (NDPC, IR-ZA, ODPC-KE ...)
      financial/             ← 43 central banks and financial regulators
      sector/                ← 6 sector regulators (NITDA, NCC, CA-KE ...)
    sectors/                 ← sector frequency and severity overlays
    frameworks/              ← 15 compliance frameworks (NIST CSF, ISO 27001, POPIA ...)
    priors/
      global.yaml            ← Bayesian priors (19 global sources, 10×10 copula matrix)
      africa-overlay.yaml    ← Africa frequency adjustments + per-driver observability
    fx_rates.yaml            ← indicative FX rates for local currency output
    vector_matrix.yaml       ← 14×10 ThreatVector × LossDriver multiplier table
    scoring_weights.yaml     ← domain weights (16 cited sources), severity penalties, tier bands
  ingest/                    ← parsers: questionnaire CSV, Nessus, Burp, Prowler,
                             ←          Shodan, VAPT PDF, dark-web, DMARC
  enrich/                    ← CVE / EPSS / KEV enrichment + news intel adapters
  scoring/                   ← engine.py, vectors.py, risk_summary.py
  actuarial/
    model.py                 ← Bayesian MC with Gaussian copula, per-driver disclosure and elasticity
    premium.py               ← premium construction + FX conversion
    posterior_update.py      ← Bayesian update from observed claims
  ml/                        ← XGBoost residual layer (neutral 1.0× until trained on claims data)
  posture/                   ← multi-framework compliance posture + remediation roadmap
  report/                    ← HTML + PDF renderers + Jinja2 templates
  backtest/                  ← 10-case reference runner
  examples/                  ← bundled sample data for `cida demo`
  tests/                     ← pytest suite + backtest cases
  docs/                      ← ARCHITECTURE.md + design notes
  foundation/                ← source reference documents (gitignored)
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
| Insurance regulators | 26 |
| Data protection authorities | 38 (37 countries with enacted laws) |
| Central banks / financial regulators | 43 (all 54 countries covered) |
| Sector regulators | 6 |
| Compliance frameworks | 15 |
| Domain weight source citations | 16 primary reports |
| Actuarial prior sources | 31 (19 global + 12 Africa-specific) |
| Actuarial model improvements | Gaussian copula; per-driver disclosure; per-driver elasticity |

The ML residual layer ships neutral (1.0×) until trained on real African claim data. The Bayesian baseline carries the full prediction until then.

## Refreshing priors with real claims

Once pilot carriers feed back observed claims:

```powershell
cida update-priors --claims path/to/claims.yaml --out config/priors/global.yaml
```

The command runs Gamma (frequency) and Lognormal (severity) conjugate posterior updates and writes the updated priors back to the config. This sharpens all future assessments without retraining the ML layer.

## Disclaimer

CIDA outputs are **advisory**. Cyber risk is irreducibly stochastic; every estimate ships with a calibrated uncertainty interval (90% CI on score, P50/P90/P99 on aggregate loss). Carriers retain full underwriting authority.
