# CIDA Architecture

**Cyber Intelligence Decision Algorithm**
Underwriting decision support for cyber insurance in Africa

## What is CIDA?

CIDA is a risk scoring and actuarial engine built for cyber insurance underwriters operating across African markets. It takes structured questionnaire data from an assessed organisation, combines it with technical security findings from a full 360-degree assessment, and produces a carrier-ready underwriting package: a risk score, an expected loss estimate, a technical premium recommendation in both USD and local currency, and two detailed reports.

The output tells an insurer: how risky is this organisation, how likely are specific cyber incidents, how much should coverage cost, and what conditions or exclusions should be attached to the policy.

## The Problem CIDA Solves

Writing a cyber insurance policy requires actuarial data: historical incident frequencies, loss sizes, and sector benchmarks. For markets like auto or property insurance, decades of claims data exist. For cyber insurance in Africa, this data is almost nonexistent. African incident reporting rates are estimated at roughly one in every three or four actual incidents.

CIDA addresses this cold-start problem with a Bayesian approach. Rather than waiting for claims data that does not yet exist, it starts from global actuarial priors drawn from 20+ international industry reports and applies Africa-specific overlays calibrated from continental cybersecurity research. As real claims data accumulates over time, the model updates itself through Bayesian posterior updates, getting sharper without being rebuilt from scratch.

## Assessment Workflow

A CIDA assessment runs in two phases.

### Phase 1: Onboarding and Questionnaire

Three representatives from the client organisation are onboarded onto the CIDA platform. Each covers their domain:

* **SecOps**, security operations, threat detection, incident response
* **ITOps**, infrastructure, patching, endpoint management, backups
* **RiskOps**, governance, compliance, third-party risk, business continuity

They complete hundreds of structured questions across ten security domains. The questions are tailored to the organisation's sector: a bank answers different SecOps questions than a hospital or a pension fund. When all three have submitted, the platform exports a single merged CSV file.

### Phase 2: Technical Security Assessment

The client's environment is assessed across every attack surface:

* External network and attack surface exposure
* Web application vulnerabilities (VAPT, penetration testing)
* Cloud security posture (AWS, Azure, GCP)
* Internal network and server scanning
* Email security (DMARC, SPF, DKIM)
* Dark web and credential exposure monitoring
* OSINT and public intelligence gathering
* Compliance control gap analysis
* Incident response readiness review

The outputs from all assessment tools are dropped into a client folder alongside the questionnaire CSV. One command processes everything:

```
cida score-project "clients/Tangerine Bank 2025"
```

## How CIDA Scores an Organisation

The scoring pipeline has five sequential stages.

### Stage 1: Control Scoring

Each questionnaire response maps to a control in the master catalog. Controls are scored 0 to 100:

* Yes/no controls: 100 for yes, 0 for no
* Scale controls (1 to 5): maps to 0, 25, 50, 75, 100
* Evidence controls: 100 if evidence is provided, 0 if absent

Technical findings apply additional penalties. A Critical finding deducts 8 points from its domain; High deducts 3.5; Medium deducts 1. A CVE on the CISA Known Exploited Vulnerabilities list adds a further 6-point penalty.

### Stage 2: Domain Scoring

Controls roll up into ten security domains, each scored as the weighted mean of its controls minus technical penalties from findings.

Weights are loaded from `config/scoring_weights.yaml` and calibrated from 16 primary claims and threat-intelligence sources (see Prior Sources). Every weight has an inline citation in that file and can be adjusted by the carrier without touching Python code.

| Domain | Weight | Calibration basis |
|--------|--------|-------------------|
| Identity and Access Management | 16% | Coalition 2025: 60% of claims from BEC/FTF; Verizon DBIR 2024: credentials in 38% of breaches; CrowdStrike 2025: 35% of cloud incidents = valid account misuse |
| Endpoint Security | 13% | Sophos 2024: ransomware hit 59% of orgs; Corvus 2024: EDR presence = 60% severity reduction |
| Detection and Response | 13% | IBM Ponemon 2024: AI/automation saves $1.88M per breach; Mandiant M-Trends 2025: internal detection = 5-day dwell vs 26-day external notification |
| Resilience and Recovery | 10% | Corvus 2024: backup presence = 72% lower median claim cost; Sophos 2024: ransom payments up 500% for orgs without clean backups |
| Network Security | 10% | Corvus Q3 2024: VPN vulnerabilities = 28.7% of ransomware incidents; Mandiant M-Trends 2025: exploits = 33% of initial access |
| Third-Party and Supply Chain | 9% | WEF 2024: 41% of firms affected by third-party incident; GSMA 2024: mobile money API exposure; Smile ID 2024: KYC API supply-chain risk |
| Governance | 8% | Beazley 2024: 75% of executives over-estimate preparedness; regulatory mandates (CBN 2024, FSCA JS2 2024, SARB Directive 01/2024, CBE framework) |
| Asset and Data Management | 8% | CrowdStrike 2025: 52% of vulnerabilities tied to initial access require asset visibility to detect; Mandiant: 34% of initial vectors unknown due to unmanaged assets |
| Application Security | 7% | Mandiant M-Trends 2025: exploits = 33% initial access; lower weighting reflects Africa's current credential-dominant threat profile vs global benchmark |
| Cloud Security | 6% | Africa-specific: cloud penetration below global average; weight to be reviewed upward annually as hyperscaler adoption increases |

### Stage 3: Overall Score and Tier

The overall score is the weighted geometric mean of domain scores. A geometric mean is used because it punishes weakness in any single domain more harshly than an arithmetic mean: an organisation cannot average a critical gap away with strong scores elsewhere.

| Tier | Score | Label | Underwriting implication |
|------|-------|-------|--------------------------|
| 1 | 85 and above | Excellent | Preferred risk, standard terms |
| 2 | 70 to 84 | Good | Strong programme, standard terms |
| 3 | 55 to 69 | Adequate | Acceptable, remediation conditions required |
| 4 | 40 to 54 | Below Standard | Material gaps, restricted terms or sub-limits |
| 5 | Below 40 | High Risk | Declination or conditional cover only |

### Stage 4: Threat Vector Scoring

Fourteen threat vectors are scored from a blend of technical findings and questionnaire responses, each on a scale of 0 (no exposure) to 100 (fully saturated). A confidence flag, HIGH, MEDIUM, or LOW, tells the underwriter how much hard telemetry backs each score.

| Vector | What it measures |
|--------|-----------------|
| External Network Exposure | Open ports, exposed services, misconfigured perimeter |
| Unpatched Vulnerabilities | CVE coverage, patch SLA adherence, KEV presence |
| Web Application Weaknesses | OWASP Top 10, injection, broken authentication |
| Email Hygiene | DMARC, SPF, DKIM, phishing simulation results |
| Identity and Access | MFA coverage, PAM, privileged access controls |
| Endpoint Security | EDR deployment, patch compliance, USB controls |
| Cloud Misconfiguration | CSPM findings, public storage buckets, over-privileged IAM |
| Data Protection | DLP controls, encryption at rest, data classification |
| Third-Party Supply Chain | Vendor due diligence, contractual clauses, monitoring |
| Detection and Response | SIEM coverage, SOC hours, IR playbooks, exercises |
| Credential and Secrets Exposure | Dark web leaks, stealer logs, hardcoded secrets |
| DDoS Resilience | Anti-DDoS controls, uptime SLAs, scrubbing capacity |
| Insider Risk | Access monitoring, user behaviour analytics, offboarding |
| Mobile Agent Network | USSD/mobile money controls, agent fraud monitoring |

### Stage 5: Bayesian Actuarial Model

For each of ten insurance coverage lines (called Loss Drivers), the model computes annual frequency and severity using:

* A Bayesian Gamma prior calibrated from global industry reports
* An Africa-specific frequency overlay from continental research
* A per-country adjustment for local threat environment and under-reporting rates
* A sector multiplier for the organisation's industry
* A vector-derived modifier: each threat vector score lifts or suppresses specific driver frequencies through a calibrated multiplier matrix

The model runs 10,000 Monte Carlo simulations per assessment and produces:

* Expected Annual Loss
* 95th percentile Value at Risk (VaR95)
* Tail VaR at the 99th percentile (TVaR99), the Maximum Probable Loss
* Loss percentiles at P50, P90, P99

## The Two-Layer Risk Model

The central design decision is separating *how attackers get in* (Threat Vectors) from *what the insurer pays for* (Loss Drivers). This prevents double-counting and maps cleanly to actual policy schedule wording.

```
THREAT VECTORS                        LOSS DRIVERS
(how attackers get in)                (what the policy covers)

External Network Exposure  ---------> Cyber Extortion
Unpatched Vulnerabilities  ---------> Business Interruption
Web Application Weaknesses ---------> Data Recovery and Forensics
Email Hygiene              ---------> Funds Transfer Fraud
Identity and Access        ---+-----> Social Engineering / BEC
Endpoint Security          ---+-----> Computer Fraud (USSD, API abuse)
Cloud Misconfiguration     ---+-----> Privacy Liability (data breach)
Data Protection            ---+-----> Network Security Liability
Third-Party Supply Chain   ---+-----> Regulatory Penalties
Detection and Response     ---+-----> PCI Fines
Credential Exposure        ---+
DDoS Resilience            ---+
Insider Risk               ---+
Mobile Agent Network       ---+
```

Each vector-to-driver cell in the matrix holds a multiplier representing how much that vector lifts a driver's frequency when fully saturated (score = 100). The engine interpolates linearly between 1.0 at score 0 and the cell value at score 100.

Calibration sources: Verizon DBIR, Coalition Claims, IBM Cost of Data Breach, Mandiant M-Trends, CrowdStrike Global Threat Report, MITRE ATT&CK, CISA KEV, FBI IC3, Sophos State of Ransomware, GSMA Africa Fraud, Mastercard Africa data.

## Pricing and Premium Output

```
Technical Premium = Expected Annual Loss
                  + Risk Loading    (20% of VaR - EL, charges for variance)
                  + Expense Load    (25% - acquisition and administration)
                  + Profit Margin   (10%)
```

The premium is benchmarked against a sector base rate derived from market data. The ratio of technical premium to base rate is the pricing multiplier, telling the underwriter at a glance how this risk compares to sector peers.

Every monetary output appears in both USD and the organisation's local currency, resolved automatically from the country config. A Nigerian org produces NGN figures, South African produces ZAR, Kenyan produces KES, and so on across all 54 supported countries.

The underwriter also receives:

* Suggested aggregate limit
* Suggested retention / deductible (scaled to risk tier)
* Per-driver sub-limits (proportional to each coverage line's expected loss)
* Conditions: time-bound remediation requirements the insured must meet
* Exclusions: coverage lines restricted until specific controls are in place
* Regulatory risk flags: compliance gaps likely to generate regulatory fines

## Compliance Frameworks Evaluated

Framework selection is automatic based on the organisation's sector and country.

| Framework | Applies to |
|-----------|-----------|
| NIST Cybersecurity Framework 2.0 | All sectors |
| ISO/IEC 27001:2022 | All sectors |
| CIS Controls v8 | All sectors |
| SOC 2 Trust Services Criteria | All sectors |
| PCI-DSS v4.0 | Banks, fintechs, card issuers |
| HIPAA Security Rule | Healthcare, HMOs |
| EU GDPR | Any organisation handling EU personal data |
| Nigeria NDPR / NDPA 2023 | Nigerian organisations |
| South Africa POPIA | South African organisations |
| CCPA | Organisations with California data subjects |
| African Union Malabo Convention | AU member states |
| FSCA Joint Standard 1:2023 | South African financial institutions |
| FSCA Joint Standard 2:2024 | South African financial institutions (effective June 2025) |
| CBN Risk-Based Cybersecurity Framework 2024 | Nigerian deposit money banks and payment service banks |

Posture is measured as the percentage of crosswalked controls scoring 70 or above. A prioritised remediation roadmap ranks the highest-value controls to fix first, ordered by expected score improvement and annual loss reduction per unit of remediation effort.

## Regulators

### Insurance Supervisors

| ID | Authority | Country / Scope |
|----|-----------|-----------------|
| NAICOM | National Insurance Commission | Nigeria |
| FSCA | Financial Sector Conduct Authority | South Africa |
| IRA-KE | Insurance Regulatory Authority | Kenya |
| NIC-GH | National Insurance Commission | Ghana |
| CIMA | Conference Interafricaine des Marches d'Assurances | UEMOA/CEMAC (14 countries) |
| TIRA | Tanzania Insurance Regulatory Authority | Tanzania |
| IRA-UG | Insurance Regulatory Authority | Uganda |
| IPEC | Insurance and Pensions Commission | Zimbabwe |
| NBR-INS | National Bank of Rwanda - Insurance | Rwanda |
| NAMFISA | Namibia Financial Institutions Supervisory Authority | Namibia |
| NBFIRA | Non-Bank Financial Institutions Regulatory Authority | Botswana |
| FSC-MU | Financial Services Commission | Mauritius |
| FSA-SC | Financial Services Authority | Seychelles |
| ACAPS | Autorite de Controle des Assurances | Morocco |
| CGA | Comite General des Assurances | Tunisia |
| CNA-DZ | Conseil National des Assurances | Algeria |
| FRA-EG | Financial Regulatory Authority | Egypt |
| ARSEG | Agence de Regulation et de Supervision des Assurances | Angola |
| ARCA | Agence de Regulation et de Controle des Assurances | DR Congo |
| CBL-INS | Central Bank of Libya - Insurance | Libya |
| NBE-INS | National Bank of Ethiopia - Insurance | Ethiopia |
| FSRA-SZ | Financial Services Regulatory Authority | Eswatini |
| ISSM | Instituto de Supervisao de Seguros de Mocambique | Mozambique |
| PIA-ZM | Pensions and Insurance Authority | Zambia |
| RBM-INS | Reserve Bank of Malawi - Insurance | Malawi |

### Data Protection Authorities

| ID | Authority | Law | Country |
|----|-----------|-----|---------|
| NDPC | Nigeria Data Protection Commission | NDPA 2023 | Nigeria |
| IR-ZA | Information Regulator (POPIA) | POPIA 2013 | South Africa |
| ODPC-KE | Office of the Data Protection Commissioner | DPA 2019 | Kenya |
| DPC-GH | Data Protection Commission | DPA 2012 | Ghana |
| CNDP-MA | Commission Nationale de controle des Donnees Personnelles | Law 09-08 (2009) | Morocco |
| INPDP-TN | Instance Nationale de Protection des Donnees Personnelles | Organic Law 2004-63 | Tunisia |
| EGPDP-EG | Egypt Personal Data Protection (NTRA/MCIT oversight) | PDPL Law 151/2020 | Egypt |
| PDPO-UG | Personal Data Protection Office | PDPA 2019 | Uganda |
| PDPC-TZ | Personal Data Protection Commission | PDPA 2022 | Tanzania |
| DPC-MU | Data Protection Commissioner | DPA 2017 (GDPR-equivalent) | Mauritius |
| CDP-SN | Commission des Donnees Personnelles | Law 2008-12 | Senegal |
| NCSA-RW | National Cyber Security Authority | Law 058/2021 | Rwanda |

Breach notification windows: Nigeria 72h, South Africa 72h, Kenya 72h, Ghana 72h, Morocco 72h, Tunisia 48h, Egypt 72h, Uganda 48h, Tanzania 72h, Mauritius 72h, Senegal 72h, Rwanda 72h.

### Central Banks and Financial Regulators

| ID | Authority | Key cyber directive | Scope |
|----|-----------|---------------------|-------|
| CBN | Central Bank of Nigeria | Risk-Based Cybersecurity Framework 2024 (effective 2024-07-01) | Nigeria |
| SARB | South African Reserve Bank | Directive 01/2024 (2hr RTO, 8hr MTD for critical systems); Joint Standard 2/2024 | South Africa |
| CBK | Central Bank of Kenya | Risk-Based Cybersecurity Framework | Kenya |
| BoG | Bank of Ghana | Cybersecurity Directive | Ghana |
| CBE | Central Bank of Egypt | Financial Cybersecurity Framework; sectoral CERT operator | Egypt |
| BAM | Bank Al-Maghrib | Circular 5/W/2014; Cyber Resilience Directive 2023 | Morocco |
| BNR | National Bank of Rwanda | Cyber Regulation 2021 | Rwanda |
| BoT | Bank of Tanzania | Cybersecurity Directive 2023 | Tanzania |
| BCEAO | Banque Centrale des Etats de l'Afrique de l'Ouest | Regional cybersecurity framework | 8 UEMOA countries |
| BEAC | Banque des Etats de l'Afrique Centrale | Regional cybersecurity framework | 6 CEMAC countries |

### Sector Regulators

| ID | Authority | Sector | Country |
|----|-----------|--------|---------|
| NITDA | National IT Development Agency | Technology / data | Nigeria |
| NCC | Nigerian Communications Commission | Telecoms | Nigeria |
| PenCom | National Pension Commission | Pension | Nigeria |
| SEC-NG | Securities and Exchange Commission | Capital markets | Nigeria |
| CA-KE | Communications Authority of Kenya | Telecoms / CII | Kenya |
| NCSA-RW-SECTOR | Rwanda National Cyber Security Authority | Cross-sector CII | Rwanda |

## Supported Countries (54)

| Region | Countries |
|--------|-----------|
| West Africa | NG, GH, CI, SN, ML, BF, NE, TG, BJ, GN, SL, LR, GM, GW, CV, MR |
| East Africa | KE, TZ, UG, RW, ET, BI, DJ, SO, SS, SD, ER, KM, MG, MU, SC |
| Southern Africa | ZA, ZW, ZM, MW, MZ, BW, NA, LS, SZ |
| Central Africa | CM, CD, CG, CF, TD, GA, GQ, AO, ST |
| North Africa | EG, MA, DZ, TN, LY |

Each country carries: base frequency multipliers, disclosure correction factor, mobile money penetration level, currency code, and regulator references. Run `cida list-countries` for the full table.

## Supported Assessment Tools

File classification is content-based. Filenames never matter.

**Vulnerability scanners**
Nessus, Qualys, OpenVAS, Greenbone, Rapid7 InsightVM, Metasploit, Tenable.io

**Web application scanners**
Burp Suite, OWASP ZAP, Nikto, Acunetix, IBM AppScan, w3af, Arachni

**Network scanners**
Nmap, Masscan, Zmap

**Cloud CSPM**
AWS: Prowler v3/v4, Security Hub
Azure: Defender for Cloud, ScoutSuite
GCP: Security Command Center, ScoutSuite
Multi-cloud: Wiz, Orca, Prisma Cloud

**Attack surface management and OSINT**
Shodan, Censys, Amass, theHarvester, Recon-ng, BBOT, Subfinder, Nuclei

**Dark web and credential intelligence**
SpyCloud, DeHashed, Hudson Rock, Flare, HaveIBeenPwned, generic breach dumps, stealer log exports (RedLine, Raccoon, Vidar, Lumma)

**Email security**
checkdmarc, hardenize, dmarcian, mail-tester

**Other formats**
VAPT narrative PDFs, evidence screenshots (PNG/JPEG/SVG), CIDA narrative Word reports

## Report Outputs

| File | For |
|------|-----|
| `_yoa_report.html` | Client: risk score, incident costs, findings, compliance posture, remediation roadmap |
| `_report.html` | Underwriter: actuarial tables, vector scores, premium breakdown, policy conditions |
| `_yoa_report.pdf` | Client PDF |
| `_report.pdf` | Underwriter PDF |
| `_report.json` | Full machine-readable payload |
| `_scored_block.json` | Compact underwriting summary for SaaS or API integration |

The YOA (Year of Assessment) report is designed for the insured organisation. It explains the risk score, shows what specific cyber incidents would cost, lists findings by severity, maps compliance gaps, and gives a prioritised list of what to fix first. It includes an evidence appendix with screenshots from the assessment.

The underwriting scorecard is for the carrier's team. It includes actuarial detail, vector-to-driver contributions, peer comparison, premium construction, and proposed policy terms.

## Technical Architecture

```
cli.py                Typer CLI: score-project, score, demo, backtest, update-priors
models.py             All Pydantic data models, single source of truth

ingest/               File parsing
  sniffer.py          Content-based file classifier (never uses filenames)
  findings.py         Routes files to the right parser
  questionnaire.py    Questionnaire CSV parser
  project.py          Drop-zone loader, discovers all files recursively
  nessus.py           Nessus, Qualys, OpenVAS, Rapid7 parser
  vapt_pdf.py         PDF extraction (pdfplumber + optional LLM assist)
  attack_surface.py   Shodan, Censys, Amass parser
  cspm_aws.py         Prowler, Security Hub parser
  cspm_azure.py       Defender for Cloud, ScoutSuite Azure parser
  cspm_gcp.py         GCP Security Command Center parser
  darkweb.py          Credential leak, stealer log, forum mention parser
  dmarc.py            DMARC, SPF, DKIM parser
  cida_docx.py        CIDA narrative Word report parser

enrich/               External data enrichment
  cve.py              CVE, EPSS, KEV enrichment (NVD, FIRST, CISA)
  cwe.py              CWE and OWASP Top 10 mapping
  intel/              Public intelligence (Proshare, BusinessDay)

scoring/
  engine.py           Control scoring, domain rollup, overall score, tier
  vectors.py          14 threat vector scores
  risk_summary.py     Coalition-style risk summary builder

actuarial/
  model.py            Bayesian frequency x severity x 10k Monte Carlo
  premium.py          Premium construction + FX conversion to local currency
  posterior_update.py Bayesian update from observed claims

ml/
  modifier.py         XGBoost residual on log(EL), neutral until trained

posture/
  compliance.py       Framework posture scoring + remediation roadmap

catalog/
  control_catalog.yaml  41 controls with multi-framework crosswalks
  loader.py

config/               All calibration in plain YAML, no code changes needed
  countries/          54 country configs (regulators, currency, multipliers)
  regulators/         Insurance, data protection, financial, sector
  sectors/            Sector frequency and severity overlays
  frameworks/         Compliance framework descriptors
  priors/             Global Bayesian priors + Africa-specific overlays
  fx_rates.yaml       Indicative FX rates for local currency output
  vector_matrix.yaml  14x10 ThreatVector x LossDriver multiplier table
  scoring_weights.yaml  Domain weights, severity penalties, tier bands (sourced from 16 reports)

report/
  renderer.py         CIDAReport builder + HTML and PDF renderer
  templates/          Jinja2 templates for both report types

clients/              Client assessment folders (gitignored)
docs/                 ARCHITECTURE.md and design notes
tests/                pytest suite and 10 backtest cases
```

### Data Flow

```
org_profile.yaml + questionnaire.csv + assessment artefacts
                           |
                      sniffer.py
                     (classify files)
                           |
                 parsers + CVE enrichment
                           |
              +------------+------------+
              |                         |
       scoring/engine.py        scoring/vectors.py
       (domain scores, tier)    (14 vector scores)
              |                         |
              +------------+------------+
                           |
                  actuarial/model.py
                  (10,000 Monte Carlo sims)
                           |
                  actuarial/premium.py
                  (premium + FX conversion)
                           |
                  posture/compliance.py
                  (framework posture + roadmap)
                           |
                  report/renderer.py
                  (HTML + PDF + JSON output)
```

### Extending the model

**New country**: add `{ISO2}.yaml` to `config/countries/`

**New regulator**: add a YAML to the relevant `config/regulators/` subfolder, reference it from the country config

**New assessment tool**: write a parser returning `list[Finding]`, add signals to `sniffer.py`, add a dispatch case in `findings.py`

**New compliance framework**: add a YAML to `config/frameworks/`, add crosswalk entries in the control catalog

**Update priors from real claims**: `cida update-priors --claims claims.yaml --out config/priors/global.yaml`

## Calibration and Validation

Ten reference cases validate the model across sectors and countries. Run `cida backtest` after any config change.

| Case | Sector | Country | Primary validation |
|------|--------|---------|-------------------|
| 01 | Tier 1 bank | Nigeria | High EL, FTF dominant |
| 02 | Tier 1 insurer | South Africa | Moderate EL, POPIA flags |
| 03 | Tier 2 fintech | Kenya | Elevated EL, mobile fraud frequency |
| 04 | Tier 3 pension | Ghana | Moderate EL |
| 05 | Tier 3 manufacturing | Egypt | Business interruption dominant |
| 06 | Tier 4 insurer | Nigeria | Restricted terms output |
| 07 | Tier 4 telecom | Tanzania | DDoS dominant |
| 08 | Tier 5 SME | Cote d'Ivoire | Declination threshold |
| 09 | Tier 5 healthcare | Zimbabwe | HIPAA analogue gaps |
| 10 | Tier 2 education | South Africa | FSCA regulatory context |

## Prior Sources

**Global** (actuarial priors and domain weight calibration):

* Verizon Data Breach Investigations Report 2024 and 2025
* Coalition Cyber Claims Report 2024 and 2025
* IBM / Ponemon Cost of a Data Breach Report 2024
* Sophos State of Ransomware 2024
* Mandiant M-Trends 2025 (frontline IR engagement data)
* CrowdStrike Global Threat Report 2025
* Munich Re Cyber Insurance Risks and Trends 2024
* Corvus Insurance Ransomware and Cyber Threat Reports Q1-Q4 2024
* Beazley Spotlight on Cyber and Technology Risk 2024
* At-Bay Cyber Insurance Report 2024
* NetDiligence Cyber Claims Study
* Hiscox Cyber Readiness Report
* FBI IC3 Internet Crime Report
* ENISA Threat Landscape 2024
* World Economic Forum Global Cybersecurity Outlook 2024
* Cyentia IRIS
* Chainalysis Crypto Crime Report
* Dragos Year in Review (OT / ICS threats)
* AON Cyber Risk Report

**Africa-specific** (frequency overlays and regional calibration):

* Interpol African Cyberthreat Assessment Report 2024 and 2025
* Serianu Africa Cybersecurity Report 2024/2025
* GSMA Mobile Money State of the Industry 2024
* Smile ID State of KYC in Africa 2024
* Mastercard Cybersecurity in Africa 2024
* KE-CIRT (Kenya) Quarterly Threat Intelligence Reports 2024
* ngCERT (Nigeria) Incident Bulletins 2024
* CSEAN Cyber Threat Report Nigeria 2024
* AON Africa Survey
* African Development Bank Digital Finance Inclusion data
* CBN Annual Report and NDPC Enforcement Actions
* POPIA Information Regulator Annual Report (South Africa)

## Glossary

**CVE**, Common Vulnerabilities and Exposures. A public identifier for a known software vulnerability.

**EPSS**, Exploit Prediction Scoring System. A probability score (0 to 1) for how likely a CVE is to be exploited within 30 days.

**Expected Annual Loss (EL)**, The average total loss expected per year across all covered cyber incidents.

**KEV**, CISA Known Exploited Vulnerabilities. CVEs with confirmed active exploitation in the wild.

**Loss Driver**, One of ten insurance coverage lines: what the carrier actually pays out for.

**Monte Carlo simulation**, A technique that runs thousands of random scenarios to estimate a probability distribution. CIDA runs 10,000 simulations per assessment.

**NDPR**, Nigeria Data Protection Regulation (2019), superseded by NDPA 2023.

**POPIA**, Protection of Personal Information Act. South Africa's primary data protection legislation.

**Threat Vector**, One of fourteen technical attack pathways an attacker can exploit.

**Tier**, A 1-5 risk grade assigned by CIDA. Tier 1 is the best risk; Tier 5 is the highest.

**TVaR99**, Tail Value at Risk at the 99th percentile. The Maximum Probable Loss presented to the underwriter.

**VaR95**, Value at Risk at the 95th percentile. The loss level exceeded only 5% of simulated years.

**YOA**, Year of Assessment. The client-facing report format.
