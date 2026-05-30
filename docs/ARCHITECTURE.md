# CIDA Architecture

> Audience: engineers, actuaries, and underwriters who need to understand what
> CIDA does, *why* it produces a given number, and where to extend it.

---

## 1. Design goals

1. **Decision support, never opaque.** Every output number must be traceable back to a finding, a questionnaire response, a prior, or a documented multiplier.
2. **Two-layer model.** Separate *how* an attacker breaks in (ThreatVector) from *what the insurer pays* (LossDriver / coverage line). The old hybrid that mixed actors with coverage lines made the math nonsensical.
3. **Calibrated uncertainty.** Every estimate carries an interval. Confidence flags on each vector tell the underwriter when "we don't have telemetry for this".
4. **Africa-first, world-aware.** Global priors blended from 18 named industry sources, then lifted by an Africa overlay sourced from continental reporting; per-country YAMLs layer on top.
5. **Plain YAML over code.** Priors, regulators, sectors, frameworks, the vector × driver matrix - all human-readable, version-controllable, citable.

---

## 2. The two-layer risk model

```
                        ┌─────────────────────────────────────────┐
                        │       14 ThreatVectors (technical)      │
                        │  external_network_exposure              │
                        │  unpatched_vulnerabilities              │
                        │  web_application_weaknesses             │
                        │  email_hygiene                          │
                        │  identity_and_access                    │
                        │  endpoint_security                      │
                        │  cloud_misconfiguration                 │
                        │  data_protection                        │
                        │  third_party_supply_chain               │
                        │  detection_and_response                 │
                        │  credential_secrets_exposure            │
                        │  ddos_resilience                        │
                        │  insider_risk                           │
                        │  mobile_agent_network                   │
                        └────────────────┬────────────────────────┘
                                         │
                            14 × 10 multiplier matrix
                          (cida/config/vector_matrix.yaml)
                                         │
                        ┌────────────────▼────────────────────────┐
                        │     10 LossDrivers (coverage lines)     │
                        │  cyber_extortion                        │
                        │  business_interruption                  │
                        │  data_recovery                          │
                        │  funds_transfer_fraud                   │
                        │  social_engineering                     │
                        │  computer_fraud                         │
                        │  privacy_liability                      │
                        │  network_sec_liability                  │
                        │  regulatory_penalties                   │
                        │  pci_fines                              │
                        └─────────────────────────────────────────┘
```

**Why this matters.** Previously the engine had 7 "loss drivers" that mixed coverage lines (ransomware, BEC, data_breach) with attacker types (DDoS, insider, third_party). Two consequences fell out:

1. Frequencies couldn't be summed cleanly - a single intrusion could be counted as both *insider* and *data_breach*.
2. An African mobile-money fraud incident didn't map cleanly to any of the 7.

The new model fixes both: actor types are **vectors** (they *lift* the frequency of one or more coverage lines), and coverage lines align 1:1 with what carriers actually write on policy schedules (Coalition, Beazley, Munich Re wording).

---

## 3. Data flow (end-to-end)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  INPUTS                                                                  │
│  • Org profile YAML (sector, country, revenue, headcount, data class)    │
│  • Questionnaire CSV  (one row per control_id, 0–100 normalised)         │
│  • Findings  (Nessus / Burp / ZAP / Prowler / Shodan / VAPT-PDF /        │
│               dark-web / DMARC / SPF / ASM …)                            │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 1 - Scoring engine  (cida/scoring/engine.py)                       │
│  ▸ control_score[c] = response.score                                     │
│  ▸ domain_score[d]  = weighted_mean(controls_in_d) − tech_penalty(d)     │
│  ▸ overall_score    = weighted_geometric_mean(domains)                   │
│  ▸ tier             = 1–5 from threshold bands                           │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 2 - Threat vector scoring  (cida/scoring/vectors.py)               │
│  For each of the 14 vectors:                                             │
│   findings → routed by source string + Domain fallback                   │
│              → severity points (CRIT 25 / HIGH 12 / MED 4 / KEV +15 …)   │
│   controls → routed by Control.threat_vectors tag OR Domain fallback     │
│              → deficit = 100 − weighted_mean(score)                      │
│   Combine:                                                               │
│     no evidence       → 50 (neutral) + confidence LOW                    │
│     controls only     → deficit                                          │
│     findings only     → finding_pts × 100/70                             │
│     both              → 0.6 × deficit + 0.4 × finding_component          │
│   Confidence: HIGH (telemetry) / MED (mixed) / LOW (questionnaire only). │
│   Output: 14 × VectorScore(score_0_100, confidence, n_findings,          │
│                           n_controls, top_evidence, contributing_drivers)│
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 3 - Bayesian actuarial model  (cida/actuarial/model.py)            │
│  For each of the 10 LossDrivers:                                         │
│     α, β  ← priors/global.yaml × Africa overlay                          │
│     λ_eff = (α/β)                                                        │
│            × sector_freq_multiplier                                      │
│            × country_base_frequency_multiplier                           │
│            × disclosure_correction          (capped 2.0×)                │
│            × Π over 14 vectors of                                        │
│                (1 + score_v/100 × (matrix[v][driver] − 1))               │
│              (capped at 6.0× per driver)                                 │
│     Frequency uncertainty:  λ ~ Gamma(α, α/λ_eff)                        │
│     Counts:                 n ~ Poisson(λ_sample)        × 10 000 sims   │
│     Severity:               s ~ Lognormal(μ_adj, σ)                      │
│                             μ_adj = μ + ln(size_scale × sector_sev_mult) │
│                             size_scale = (revenue / $50M) ^ 0.45         │
│     Annual loss per driver: sum of severity draws over n events          │
│  Aggregate across drivers → EL, VaR₉₅, TVaR₉₉, P50 / P90 / P99           │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 4 - ML residual layer  (cida/ml/modifier.py)                       │
│  XGBoost trained on (features → log(actual_loss) − log(baseline_EL)).    │
│  Returns multiplier ∈ [0.2, 5.0]. Neutral 1.0× until artefact is shipped │
│  (no fabricated signal).                                                 │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  STEP 5 - Risk summary  (cida/scoring/risk_summary.py)                   │
│  risk_score = 100 − overall_score          (high = bad, Coalition style) │
│  likelihood_multiplier_vs_peer                                           │
│       = avg_org_vector_mult / avg_peer_baseline_vector_mult              │
│  attack_surface   = sub-domains, IPs, apps, services from findings + org │
│  posture_signals  = DMARC / SPF / Malware / Data Leaks …                 │
│  vector_scores         (carried through unchanged)                       │
│  top_likelihood_drivers = vectors ranked by                              │
│       Σ over drivers of (per_vector_mult − 1) × driver_freq_weight       │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
                            JSON + PDF report
```

---

## 4. Vector scoring - how the 14 scores get made

### 4.1 Source-to-vector routing (findings side)

Defined in `_SOURCE_TO_VECTORS` in `cida/scoring/vectors.py`. Examples:

| Finding source          | Vector(s) it feeds                                          |
|-------------------------|-------------------------------------------------------------|
| `shodan` / `censys` / `amass` | external_network_exposure                              |
| `nessus` / `qualys` / `tenable` | unpatched_vulnerabilities                            |
| `burp` / `zap` / `appsec`     | web_application_weaknesses                             |
| `vapt_pdf`              | web_application_weaknesses + unpatched_vulnerabilities      |
| `dmarc` / `spf` / `dkim`      | email_hygiene                                          |
| `prowler` / `securityhub` / `defender` / `scc` | cloud_misconfiguration              |
| `darkweb_credentials` / `darkweb_stealer` | credential_secrets_exposure              |

When the source string doesn't match, the finding falls back to the `Domain` → `ThreatVector` map (e.g. `Domain.APPSEC` → web_application_weaknesses).

### 4.2 Control-to-vector routing (questionnaire side)

Each `Control` can declare `threat_vectors: [...]` explicitly. When the catalog doesn't tag a control (legacy 41-control catalog), the loader falls back to a `Domain → [ThreatVector]` map in `vectors.py::_DOMAIN_FALLBACK`. This is how the old catalog continues to drive scoring without being rewritten.

### 4.3 Confidence

`Confidence` enum: `HIGH | MEDIUM | LOW`. Base tier per vector is in `_VECTOR_CONFIDENCE`. The actual emitted confidence downgrades when telemetry is absent:

- No findings AND no control responses → `LOW` (score 50 placeholder)
- No findings, base tier was `HIGH` → `MEDIUM`
- Otherwise → base tier

Questionnaire-only vectors (`third_party_supply_chain`, `detection_and_response`, `ddos_resilience`, `insider_risk`, `mobile_agent_network`) stay at their base `LOW` even with responses, because we can't independently verify.

---

## 5. The vector × driver matrix

Defined in [cida/config/vector_matrix.yaml](../cida/config/vector_matrix.yaml). Each cell holds the **frequency multiplier when the vector is fully saturated (score = 100)**. Linear interpolation between 1.0 (score 0) and the cell value (score 100):

```python
per_vector_mult = 1.0 + (score / 100) * (matrix_cell - 1.0)
combined_mult   = min( ∏ per_vector_mult,  per_driver_cap )    # cap = 6.0×
```

Calibration sources for the matrix:

- Verizon DBIR 2024 breach pattern × action mapping (Tables 3-4)
- Coalition 2024 Cyber Claims Report - initial access vector breakdown
- IBM Cost of a Data Breach 2024 - initial-attack-vector cost analysis
- Mandiant M-Trends 2024 - initial-compromise vector frequencies
- CrowdStrike Global Threat Report 2024 - TTP frequency tables
- MITRE ATT&CK technique catalog v15 + CISA KEV
- FBI IC3 BEC investigations 2024
- Sophos State of Ransomware 2024 - entry-point analysis
- GSMA / Mastercard Africa fraud reports (for mobile_agent_network → computer_fraud)
- Dragos Year in Review 2024 (for OT exposure to BI)

### Notable cells

| Vector → Driver | Multiplier | Why |
|-----------------|-----------:|------|
| identity_and_access → funds_transfer_fraud | 2.5× | Coalition'24: no-MFA = #1 root cause of FTF claims |
| email_hygiene → social_engineering         | 3.0× | IC3'24: DMARC absence correlates strongly with BEC |
| mobile_agent_network → computer_fraud      | 3.0× | GSMA'24 + Mastercard'24: USSD/agent fraud is the African signature |
| ddos_resilience → business_interruption    | 3.0× | ENISA'24 + Cloudflare'24: record 4.2 Tbps Q3'24 attacks |
| endpoint_security → cyber_extortion        | 2.2× | Sophos'24: no-EDR coverage doubles ransomware payout rate |
| unpatched_vulnerabilities → cyber_extortion| 2.0× | CISA KEV + EPSS: primary precursor to ransomware (Mandiant'24) |

---

## 6. Priors - the actuarial backbone

### 6.1 Global (`cida/config/priors/global.yaml`)

For each of the 10 LossDrivers, a Gamma prior over annual frequency:

```yaml
frequency_priors:
  cyber_extortion:        { alpha: 0.08, beta: 1.0 }
  business_interruption:  { alpha: 0.22, beta: 1.0 }
  data_recovery:          { alpha: 0.25, beta: 1.0 }
  funds_transfer_fraud:   { alpha: 0.18, beta: 1.0 }
  social_engineering:     { alpha: 0.40, beta: 1.0 }
  computer_fraud:         { alpha: 0.04, beta: 1.0 }
  privacy_liability:      { alpha: 0.12, beta: 1.0 }
  network_sec_liability:  { alpha: 0.02, beta: 1.0 }
  regulatory_penalties:   { alpha: 0.06, beta: 1.0 }
  pci_fines:              { alpha: 0.03, beta: 1.0 }
```

Severity priors are Lognormal in USD; e.g. cyber_extortion μ = 12.13, σ = 1.60 → median ≈ $185k (Coalition'24).

A `size_severity_elasticity` of 0.45 means a $500M revenue org has a roughly $50M-org's median × $(500/50)^{0.45}$ = ~2.8× severity scaling.

A 9-sector × 10-driver frequency multiplier matrix (banking, insurance, fintech, pension, education, healthcare, telecom, manufacturing, other) overlays sector-specific risk.

Cited sources (18): DBIR, NetDiligence, Coalition, IBM/Ponemon, Sophos, Hiscox, IC3, ENISA, Mandiant, CrowdStrike, Cyentia IRIS, Munich Re, CRO Forum, Chainalysis, CBN, NDPC, POPIA Info Reg, Dragos.

### 6.2 Africa overlay (`cida/config/priors/africa-overlay.yaml`)

Multipliers applied to `alpha` at load time:

| Driver                  | Africa lift | Rationale source |
|-------------------------|------------:|------------------|
| computer_fraud          | 3.50×       | GSMA'24 + Mastercard'24 - USSD/MMO fraud dominant |
| funds_transfer_fraud    | 1.80×       | Serianu'24 + CSEAN'24 - FTF dominates African FSI |
| social_engineering      | 1.60×       | Interpol'24 - BEC widespread + weak DMARC adoption |
| regulatory_penalties    | 1.30×       | NDPC'24 first 9-figure NGN fines; POPIA intensifying |
| privacy_liability       | 1.20×       | NDPR / POPIA enforcement maturing |
| business_interruption   | 1.10×       | Power/connectivity fragility + DDoS uplift |
| data_recovery           | 1.10×       | Slower MTTR + sparser IR talent |
| network_sec_liability   | 1.10×       | - |
| cyber_extortion         | 0.85×       | Sophos SA'24 historically lower, rising |
| pci_fines               | 0.80×       | Card penetration lower outside SA / KE / NG |

A `disclosure_correction_factor_continental_mean: 3.5` represents continental under-reporting - observed incidents are ~1/3.5 of true incidents. Per-country YAMLs refine this.

### 6.3 Country layer (`cida/config/countries/{ISO2}.yaml`)

Each country file references its regulators by ID and provides:
- `base_frequency_multipliers` (per-driver, on top of the Africa overlay)
- `disclosure_correction_factor` (country-specific under-reporting)

---

## 7. Module map

| Module | Responsibility |
|--------|----------------|
| [cida/models.py](../cida/models.py) | Pydantic source of truth - all enums + types. `LEGACY_LOSS_DRIVER_ALIASES` for backward compat. |
| [cida/config/loader.py](../cida/config/loader.py) | YAML loaders, `_alias_driver_keys` translation, `load_vector_matrix`, `CountryContext`. |
| [cida/catalog/loader.py](../cida/catalog/loader.py) | Control catalog loader (applies alias layer). |
| [cida/ingest/](../cida/ingest/) | Questionnaire CSV parser + finding parsers (Nessus, Burp, ZAP, Prowler, Shodan, VAPT-PDF, dark-web, DMARC/SPF). |
| [cida/enrich/](../cida/enrich/) | CVE / EPSS / KEV / news / breach mention enrichers. |
| [cida/scoring/engine.py](../cida/scoring/engine.py) | Per-control → per-domain → overall scoring + tier assignment. |
| [cida/scoring/vectors.py](../cida/scoring/vectors.py) | 14-vector scoring, finding routing, control routing, peer baseline. |
| [cida/scoring/risk_summary.py](../cida/scoring/risk_summary.py) | Builds the underwriter-facing `RiskSummary`. |
| [cida/actuarial/model.py](../cida/actuarial/model.py) | Bayesian frequency × severity × Monte Carlo. |
| [cida/actuarial/premium.py](../cida/actuarial/premium.py) | Technical premium, retention, sub-limits, exclusions. |
| [cida/actuarial/posterior_update.py](../cida/actuarial/posterior_update.py) | Gamma + Lognormal posterior updates from observed claims. |
| [cida/ml/modifier.py](../cida/ml/modifier.py) | XGBoost residual on log(EL). Neutral until trained. |
| [cida/posture/](../cida/posture/) | Multi-framework compliance scoring. |
| [cida/report/](../cida/report/) | JSON + PDF (xhtml2pdf / WeasyPrint) renderers + Jinja templates. |
| [cida/backtest/runner.py](../cida/backtest/runner.py) | 10 reference cases under `tests/backtest/cases/`. |
| [cida/cli.py](../cida/cli.py) | Typer CLI: score / demo / backtest / update-priors / list-countries / list-regulators / version. |

---

## 8. Backward compatibility

The 30+ country YAMLs and 41-control catalog were written against the **old 7-driver enum** (`bec`, `ransomware`, `data_breach`, `ddos`, `insider`, `third_party`, `mobile_money_fraud`). Rather than rewriting them all, the loader applies `LEGACY_LOSS_DRIVER_ALIASES` at load time:

```python
"bec":                "social_engineering"
"ransomware":         "cyber_extortion"
"data_breach":        "privacy_liability"
"ddos":               "business_interruption"
"insider":            "privacy_liability"
"third_party":        "privacy_liability"
"mobile_money_fraud": "computer_fraud"
```

The translation walks nested dicts recursively, so `loss_driver_modifiers`, `base_frequency_multipliers`, and `severity_multipliers` are all rewritten transparently. New configs should use the canonical names directly.

---

## 9. Output schema

`CIDAReport` (Pydantic) → JSON 1:1, and PDF via [cida/report/templates/report.html.j2](../cida/report/templates/report.html.j2).

The PDF structure:

| Section | Content |
|---------|---------|
| 1       | Executive summary - overall score, tier, EL, premium |
| 2.1     | Estimated loss by cyber incident type (per-driver: frequency, severity, EL, VaR, TVaR) |
| 2.2     | Attack surface analysed (sub-domains, IPs, apps, services) |
| 2.3     | Findings severity breakdown |
| 2.4     | Top findings grouped by title |
| 2.5     | Complete risk posture (DMARC / SPF / Data Leaks / Malware / …) |
| **2.6** | **Threat Vector Scores (14)** - score, confidence, evidence |
| **2.7** | **Drivers of Likelihood** - ranked vectors lifting frequency above peer |
| 3       | Underwriting snapshot (score, tier, EL, premium, multipliers) |
| 4       | Per-domain detail |
| 5       | Regulatory & compliance posture |
| 6       | Methodology + sources + disclaimer |

---

## 10. Calibration & validation

- **Unit tests** - `tests/test_*.py`, 43 passed + 1 skipped (the skipped one requires the ML artefact to be trained).
- **Backtest** - `tests/backtest/cases/*.yaml`, 10 reference cases spanning Tier 1 banks to Tier 5 SMEs, NG / ZA / KE / GH / EG / TZ / CI / ZW. Each case asserts tier, score band, and EL band. Currently 10 / 10.
- **Monte Carlo** - N = 10,000 simulations per run (deterministic with `--seed`).
- **Refreshing priors** - `python -m cida.cli update-priors --claims path/to/claims.csv` runs Gamma + Lognormal posterior updates and writes back to `priors/global.yaml`.

---

## 11. Known limitations & roadmap

1. **PDF render** falls back to HTML when `xhtml2pdf` chokes on the nested `@page { @bottom-center { ... } }` CSS rule. Fix: rewrite footer using `<pdf:pagenumber/>` syntax OR install `weasyprint` as the primary renderer.
2. **ML residual is neutral** until trained on real African claim data.
3. **Vector matrix calibration** is best-effort from public 2024 industry reports. As pilot carriers feed back claims, the matrix should be re-fit (left as a `update-priors`-style command).
4. **Control catalog** is 41 controls; mapping `threat_vectors:` explicitly on each (instead of relying on the domain fallback) would tighten vector scoring.
5. **Posture / regulatory layer** is parallel to risk scoring; a future build should blend regulatory deficiencies directly into `regulatory_penalties` frequency lift instead of treating them as separate report sections.

---

## 12. Glossary

- **ThreatVector** - one of 14 technical exposure areas an attacker can exploit.
- **LossDriver** - one of 10 insurance coverage lines (what the carrier actually pays out for).
- **Tier 1-5** - overall risk grading (Excellent → High Risk) from `score_organization`.
- **EL** - expected annual loss (USD), aggregate across all drivers.
- **VaR₉₅** - 95th percentile of aggregate annual loss.
- **TVaR₉₉** - mean loss conditional on exceeding the 99th percentile (tail-VaR).
- **Disclosure correction** - multiplier compensating for African under-reporting (continental mean 3.5×, capped at 2.0× in the actuarial path to avoid compounding explosion).
- **Confidence (HIGH / MEDIUM / LOW)** - telemetry-grounding of a vector score.
- **Peer baseline** - combined vector multiplier evaluated at vector score = 40, the empirical book average.
