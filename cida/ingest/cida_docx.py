"""Ingest a CIDA-style narrative Word report (.docx) and convert it into the
canonical CIDA inputs (OrgProfile + Findings + QuestionnaireResponses) so the
existing scoring/actuarial pipeline can produce the Risk Summary numbers that
are LEFT BLANK in the template the analyst delivers.

Why this exists
---------------
Analysts write up the technical assessment (Email Security, Vulnerabilities,
Domains/IP, Malware, OSINT, NDPR, etc.) as a Word document. CIDA's job is to
score that narrative - populate the Risk Score %, Risk Band, the six
likelihood-of-incident boxes (Ransomware / DDoS / Data Breach / Insider /
Phishing / Compliance) and the Expected-Loss block - without the analyst
having to also hand-build YAML + CSV + JSON.

How it works
------------
1. The .docx is unzipped (it's a ZIP of XML).  `word/document.xml` is walked
   paragraph-by-paragraph; namespaces are stripped to keep regex simple.
2. A state machine drives section detection (Email Security / Vulnerabilities
   / Web App / Cloud / Network / Malware / OSINT / Compliance / DNS).
3. Each finding is a paragraph whose trailing token matches one of
   {CRITICAL, HIGH, MEDIUM, LOW, LOW RISK}.  The paragraphs that follow up
   to the next finding or section boundary become the description; lines
   under "Impacted Asset(s)" become the asset list.
4. Declared posture signals ("PASSED" lines under DMARC / SPF / Blocklisted
   Domains / Honeypot / Malware / Torrents) are captured as boolean flags.
5. The compromised-emails list is captured as one consolidated dark-web
   finding (source = darkweb_credentials so the posture surfaces correctly).
6. The questionnaire is *synthesised* from the narrative - every CIDA
   control gets a default answer that reflects what the report says
   (e.g. "NDPR non-compliance" → GOV / governance controls flipped to NO;
   exposed admin panel → APP / appsec controls flipped to NO; DMARC PASSED →
   email-hygiene controls flipped to YES).

This is deliberately heuristic.  The analyst can post-edit the generated
artifacts before scoring if they want to override any inference.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cida.catalog.loader import load_catalog
from cida.models import (
    ControlResponse,
    Domain,
    Finding,
    OrgProfile,
    QuestionnaireResponses,
    Sector,
    Severity,
)

# --- Regex / constants -----------------------------------------------------

_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_SEV_TAIL_RE = re.compile(
    r"^(?P<title>.+?)\s*[\-–-]\s*(?P<sev>CRITICAL|HIGH|MEDIUM|LOW(?:\s*RISK)?)\s*$",
    re.IGNORECASE,
)
# Severity word at the END of any paragraph (Word docs often float the
# severity tag to the end of a description line because of inline formatting).
# Used as a secondary signal anchored to the previous short paragraph as the
# candidate title.
_SEV_END_RE = re.compile(
    r"(?:^|\s)(?P<sev>CRITICAL|HIGH|MEDIUM|LOW)(?:\s+RISK)?\s*$",
    re.IGNORECASE,
)
_SEV_INLINE_RE = re.compile(
    r"\b(CRITICAL|HIGH|MEDIUM|LOW)\s*RISK\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[\w\.\-\*]+@[\w\.\-]+\.[a-z]{2,}", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s,)\]]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b")
_DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]*\.(?:[a-z0-9\-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
_SECTION_HEADERS: dict[str, str] = {
    # marker text (lowercased) -> canonical section key
    "email security":     "email",
    "dmarc":              "email",
    "spf":                "email",
    "compromised email":  "osint_email",
    "vulnerabilities":    "vulns",
    "web application":    "appsec",
    "cloud services":     "cloud",
    "network security":   "network",
    "blacklisted domains":"reputation",
    "honeypot":           "honeypot",
    "malware":            "malware",
    "dns":                "dns",
    "non-compliance":     "compliance",
    "ndpr":               "compliance",
    "data protection":    "compliance",
    "open source intel":  "osint",
    "osint":              "osint",
    "torrents":           "reputation",
    "cyber incident decision":"cidt",
    "cyber incident detection":"detect",
}

_SEC_TO_DOMAIN: dict[str, Domain] = {
    "email":       Domain.IDENTITY,
    "osint_email": Domain.IDENTITY,
    "appsec":      Domain.APPSEC,
    "cloud":       Domain.CLOUD,
    "network":     Domain.NETWORK,
    "malware":     Domain.ENDPOINT,
    "compliance":  Domain.GOVERNANCE,
    "osint":       Domain.IDENTITY,
    "reputation":  Domain.NETWORK,
    "detect":      Domain.DETECT_RESPOND,
}

_SEVERITY_NORM: dict[str, Severity] = {
    "critical":  Severity.CRITICAL,
    "high":      Severity.HIGH,
    "medium":    Severity.MEDIUM,
    "low":       Severity.LOW,
    "low risk":  Severity.LOW,
}


# --- Data classes ----------------------------------------------------------

@dataclass
class ParsedFinding:
    title: str
    severity: Severity
    section: str
    description: str = ""
    assets: list[str] = field(default_factory=list)


@dataclass
class ParsedReport:
    org_name: str | None = None
    industry: str | None = None
    assessment_date: str | None = None
    revenue_raw: str | None = None
    findings: list[ParsedFinding] = field(default_factory=list)
    declared: dict[str, str] = field(default_factory=dict)  # e.g. {"dmarc": "PASSED"}
    compromised_emails: list[str] = field(default_factory=list)
    email_domains: list[str] = field(default_factory=list)
    websites: list[str] = field(default_factory=list)
    raw_text: str = ""


# --- Step 1: read paragraphs ----------------------------------------------

def _read_paragraphs(docx_path: Path) -> list[str]:
    with zipfile.ZipFile(docx_path) as z:
        with z.open("word/document.xml") as f:
            tree = ET.parse(f)
    paras: list[str] = []
    for p in tree.iter(f"{_W_NS}p"):
        texts = [t.text or "" for t in p.iter(f"{_W_NS}t")]
        line = "".join(texts).strip()
        if line:
            paras.append(line)
    return paras


# --- Step 2: section/finding state machine --------------------------------

def _section_for(line: str, current: str) -> str:
    """Detect a CIDA section header.  Only treat short, title-like lines
    (≤ 80 chars, not ending in punctuation typical of prose) as section
    headers - prevents descriptive paragraphs that happen to contain a
    section keyword (e.g. "In the course of OSINT...") from spuriously
    flipping the section.
    """
    if len(line) > 80:
        return current
    stripped = line.strip().rstrip(":")
    if stripped.endswith((".", "!", "?")):
        return current
    lo = stripped.lower()
    for marker, key in _SECTION_HEADERS.items():
        if marker in lo:
            return key
    return current


def _looks_like_finding_header(line: str) -> tuple[str, Severity] | None:
    """Return (title, severity) if this line is a finding header line."""
    m = _SEV_TAIL_RE.match(line)
    if m:
        sev_key = m.group("sev").lower().replace("  ", " ").strip()
        sev = _SEVERITY_NORM.get(sev_key) or _SEVERITY_NORM.get(sev_key.split()[0])
        if sev:
            return m.group("title").strip(), sev
    # Pattern used in KOA: "Missing Strict-Transport-Security Header ... LOW RISK"
    m2 = _SEV_INLINE_RE.search(line)
    if m2 and len(line) < 200 and not any(line.lower().startswith(w) for w in
                                          ("the ", "this ", "during", "for ", "if ", "while ")):
        sev_key = m2.group(1).lower()
        sev = _SEVERITY_NORM.get(sev_key)
        if sev:
            title = _SEV_INLINE_RE.sub("", line).rstrip(" \t-–-")
            if title:
                return title.strip(), sev
    return None


def parse_cida_docx(docx_path: str | Path) -> ParsedReport:
    """Extract org metadata, findings, and declared posture signals from
    a CIDA-style Word report.
    """
    docx_path = Path(docx_path)
    paras = _read_paragraphs(docx_path)
    pr = ParsedReport(raw_text="\n".join(paras))

    section = "header"
    current_finding: ParsedFinding | None = None
    capturing_assets = False
    capturing_emails = False
    awaiting_dmarc = False
    awaiting_spf = False
    awaiting_blocklist = False
    last_short_para: str | None = None  # candidate title for floating-severity findings
    compromised_finding_added = False

    # ---- Header pass: org name appears after "DEVELOPED FOR" ----
    for i, line in enumerate(paras[:40]):
        if line.strip().lower() == "developed for" and i + 1 < len(paras):
            # Walk forward to the first non-empty line that isn't a placeholder.
            for j in range(i + 1, min(i + 6, len(paras))):
                cand = paras[j].strip()
                if cand and cand.lower() != "developed for":
                    pr.org_name = cand
                    break
            break

    for i, line in enumerate(paras):
        lo = line.lower()

        # --- header fields ---
        if pr.industry is None and lo.startswith("industry:"):
            pr.industry = line.split(":", 1)[1].strip()
        if pr.assessment_date is None and "date of assessment" in lo:
            # The Word template smashes "Date of Assessment: X" and "Revenue: Y" into one paragraph.
            date_part = line.split("Date of Assessment", 1)[1].lstrip(": ").strip()
            if "Revenue" in date_part:
                date_part, rev_part = date_part.split("Revenue", 1)
                pr.revenue_raw = rev_part.lstrip(": ").strip()
            pr.assessment_date = date_part.strip().rstrip(".")
        if pr.revenue_raw is None and lo.startswith("revenue:"):
            pr.revenue_raw = line.split(":", 1)[1].strip()

        # --- section transitions ---
        prev_section = section
        section = _section_for(line, section)
        if section != prev_section:
            # New section closes any in-progress finding.
            if current_finding:
                pr.findings.append(current_finding)
                current_finding = None
            capturing_assets = False
            # email capture is sticky: only "Recommendation" terminates it,
            # not section drift caused by descriptive prose mentioning OSINT.

        # --- declared posture ---
        if lo.strip() == "passed":
            if awaiting_dmarc:
                pr.declared["dmarc"] = "PASSED"; awaiting_dmarc = False
            elif awaiting_spf:
                pr.declared["spf"] = "PASSED"; awaiting_spf = False
            elif awaiting_blocklist:
                pr.declared["blocklist"] = "PASSED"; awaiting_blocklist = False
        elif lo.strip() == "failed":
            if awaiting_dmarc:
                pr.declared["dmarc"] = "FAILED"; awaiting_dmarc = False
            elif awaiting_spf:
                pr.declared["spf"] = "FAILED"; awaiting_spf = False
            elif awaiting_blocklist:
                pr.declared["blocklist"] = "FAILED"; awaiting_blocklist = False
        if "dmarc" in lo and "passed" in lo:
            pr.declared["dmarc"] = "PASSED"
        elif "spf" in lo and "passed" in lo:
            pr.declared["spf"] = "PASSED"
        if "dmarc" in lo and not pr.declared.get("dmarc"):
            awaiting_dmarc = True
        if lo.startswith("spf") and not pr.declared.get("spf"):
            awaiting_spf = True
        if "blacklisted domains" in lo or "blocklist" in lo:
            awaiting_blocklist = True
        if "no torrent" in lo or "torrent" in lo and "not detected" in lo:
            pr.declared["torrents"] = "CLEAN"
        if section == "malware" and "no results were found" in lo:
            pr.declared["malware"] = "CLEAN"
        if section == "honeypot" and "no results were found" in lo:
            pr.declared["honeypot"] = "CLEAN"
        if "non-compliance" in lo and ("ndpr" in lo or "data protection" in lo):
            pr.declared["ndpr"] = "NON_COMPLIANT"
        if "no formal alignment" in lo and "ndpr" in lo:
            pr.declared["ndpr"] = "NON_COMPLIANT"

        # --- compromised emails block ---
        # Section-header form: "Compromised Email Addresses - CRITICAL".
        if "compromised email" in lo and len(line) < 80:
            capturing_emails = True
            if not compromised_finding_added:
                pr.findings.append(ParsedFinding(
                    title="Compromised email addresses found on dark-web breach dumps",
                    severity=Severity.CRITICAL,
                    section="osint_email",
                ))
                compromised_finding_added = True
            # Skip the finding-header detection below for this line so we
            # don't ALSO register a generic "Compromised Email Addresses"
            # finding (would double-count critical).
            last_short_para = line
            continue
        if capturing_emails:
            for em in _EMAIL_RE.findall(line):
                if em not in pr.compromised_emails:
                    pr.compromised_emails.append(em)
            if lo.startswith("recommendation"):
                capturing_emails = False

        # --- finding header detection ---
        hdr = _looks_like_finding_header(line)
        if hdr and section not in {"header", "cidt"}:
            # Close any previous finding first.
            if current_finding:
                pr.findings.append(current_finding)
            title, sev = hdr
            current_finding = ParsedFinding(title=title, severity=sev, section=section)
            capturing_assets = False
            last_short_para = None
            continue

        # --- floating-severity fallback ---
        # Some Word docs format a finding as: a short title paragraph,
        # followed by a description paragraph whose tail token is the
        # severity (e.g. KOA's "Missing Strict-Transport-Security Header"
        # finding where "LOW RISK" floats to the end of the next paragraph).
        if section not in {"header", "cidt"} and len(line) > 60:
            tail = _SEV_END_RE.search(line)
            if tail and last_short_para:
                sev = _SEVERITY_NORM.get(tail.group("sev").lower())
                if sev:
                    if current_finding:
                        pr.findings.append(current_finding)
                    current_finding = ParsedFinding(
                        title=last_short_para.strip(),
                        severity=sev,
                        section=section,
                        description=line,
                    )
                    capturing_assets = False
                    last_short_para = None
                    continue

        # Track the most recent short, non-prose paragraph as a candidate
        # title for the floating-severity form above.
        if 4 <= len(line) <= 120 and not line.endswith((".", "?", "!")):
            last_short_para = line

        # --- inside a finding: assets / description ---
        if current_finding is not None:
            if "impacted asset" in lo or "impacted assets" in lo:
                capturing_assets = True
                continue
            if lo.startswith("recommendation") or lo.startswith("references"):
                capturing_assets = False
                # don't include rec text in description
                continue
            if capturing_assets:
                # one asset per paragraph; could be URL, IP, or hostname
                for m in _URL_RE.findall(line):
                    current_finding.assets.append(m)
                for m in _IP_RE.findall(line):
                    if m not in current_finding.assets:
                        current_finding.assets.append(m)
                if not _URL_RE.search(line) and not _IP_RE.search(line):
                    # plain host
                    for m in _DOMAIN_RE.findall(line):
                        if m not in current_finding.assets:
                            current_finding.assets.append(m)
            else:
                current_finding.description += line + " "

        # --- collect URLs / domains for org profile ---
        for u in _URL_RE.findall(line):
            host = re.sub(r"https?://", "", u).split("/", 1)[0].split(":", 1)[0]
            if host and host not in pr.websites and len(pr.websites) < 12:
                pr.websites.append(host)

    if current_finding:
        pr.findings.append(current_finding)

    # Derive email domains from compromised emails + websites
    domains: list[str] = []
    for em in pr.compromised_emails:
        d = em.split("@", 1)[-1].lower()
        if d and d not in domains:
            domains.append(d)
    if not domains and pr.websites:
        # fallback: pick the shortest registrable-looking website
        for w in sorted(pr.websites, key=len):
            d = w.lower().lstrip("www.")
            if d.count(".") <= 2:
                domains.append(d); break
    pr.email_domains = domains

    return pr


# --- Step 3: map ParsedReport to CIDA inputs -------------------------------

_SECTOR_KEYWORDS = {
    Sector.BANKING:       ("bank", "microfinance"),
    Sector.INSURANCE:     ("insurance", "broker", "reinsur"),
    Sector.FINTECH:       ("fintech", "payment", "switch"),
    Sector.PENSION:       ("pension",),
    Sector.HEALTHCARE:    ("health", "hospital", "clinic"),
    Sector.TELECOM:       ("telecom", "isp", "mobile network"),
    Sector.MANUFACTURING: ("manufactur", "industrial"),
    Sector.EDUCATION:     ("education", "university", "school"),
}


def _infer_sector(industry_text: str | None) -> Sector:
    if not industry_text:
        return Sector.OTHER
    lo = industry_text.lower()
    for sector, kws in _SECTOR_KEYWORDS.items():
        if any(k in lo for k in kws):
            return sector
    return Sector.OTHER


def _slugify(s: str | None, fallback: str = "UNKNOWN") -> str:
    if not s:
        return fallback
    out = re.sub(r"[^A-Za-z0-9]+", "-", s.strip()).strip("-").upper()
    return out[:48] or fallback


def build_org_profile(pr: ParsedReport, country: str = "NG") -> OrgProfile:
    """Heuristically derive an OrgProfile.  Country defaults to NG (the
    Nigeria-centric audience of the existing CIDA reports) but callers can
    pass `country` if known."""
    sector = _infer_sector(pr.industry)
    revenue_usd = _parse_revenue_usd(pr.revenue_raw)
    return OrgProfile(
        org_id=_slugify(pr.org_name, "ASSESSED-ORG"),
        name=pr.org_name or "Assessed Organization",
        sector=sector,
        country=country,
        employees=_default_employees(sector, revenue_usd),
        annual_revenue_usd=revenue_usd,
        data_sensitivity="high",
        regulated_data_types=["PII", "NDPR"] if country == "NG" else ["PII"],
        public_facing_assets=min(len(pr.websites) or 4, 20),
        websites=pr.websites[:12],
        email_domains=pr.email_domains[:3] or ["unknown.local"],
    )


def _parse_revenue_usd(raw: str | None) -> float | None:
    if not raw:
        return None
    # Strip currency / commas / spaces.  Examples: "$12,000,000", "USD 5M", "₦10B"
    s = raw.replace(",", "").replace(" ", "").lower()
    mult = 1.0
    if s.endswith("b"):
        mult, s = 1e9, s[:-1]
    elif s.endswith("m"):
        mult, s = 1e6, s[:-1]
    elif s.endswith("k"):
        mult, s = 1e3, s[:-1]
    m = re.search(r"(\d+(?:\.\d+)?)", s)
    if not m:
        return None
    val = float(m.group(1)) * mult
    if "₦" in raw or "ngn" in s or "naira" in s:
        val = val / 1500.0  # rough NGN -> USD
    return round(val, 2) if val > 0 else None


def _default_employees(sector: Sector, revenue_usd: float | None) -> int:
    if revenue_usd:
        # Crude revenue-per-employee heuristic by sector.
        rev_per_emp = {Sector.BANKING: 250_000, Sector.INSURANCE: 200_000,
                       Sector.FINTECH: 220_000, Sector.HEALTHCARE: 90_000,
                       Sector.TELECOM: 300_000}.get(sector, 120_000)
        return max(20, min(50_000, int(revenue_usd / rev_per_emp)))
    return 100


def build_findings(pr: ParsedReport) -> list[Finding]:
    findings: list[Finding] = []
    for pf in pr.findings:
        # Map section -> domain
        domain = _SEC_TO_DOMAIN.get(pf.section, Domain.APPSEC)
        # Special case: the compromised-emails consolidated finding
        if pf.section == "osint_email":
            asset = pr.email_domains[0] if pr.email_domains else "corporate_mail"
            evidence = (f"{len(pr.compromised_emails)} mailbox(es) found in dark-web "
                        f"breach dumps: " + ", ".join(pr.compromised_emails[:8])
                        + ("..." if len(pr.compromised_emails) > 8 else ""))
            findings.append(Finding(
                source="darkweb_credentials",
                asset=asset,
                title=pf.title,
                severity=pf.severity,
                domain=Domain.IDENTITY,
                exposure="internet",
                asset_criticality="high",
                evidence=evidence,
                raw={"emails": pr.compromised_emails},
            ))
            continue

        # Choose primary asset; fall back to org domain.
        asset = pf.assets[0] if pf.assets else (pr.email_domains[0] if pr.email_domains else "unknown")
        exposure = ("internet" if any(_URL_RE.match(a) or "." in a.split(":")[0]
                                      and not a.startswith(("10.", "192.168.", "172."))
                                      for a in pf.assets[:1])
                    else ("internal" if pf.assets else "unknown"))
        criticality = ("crown_jewel" if pf.severity == Severity.CRITICAL
                       else "high" if pf.severity == Severity.HIGH
                       else "medium")
        findings.append(Finding(
            source="cida_docx",
            asset=asset,
            title=pf.title,
            severity=pf.severity,
            domain=domain,
            exposure=exposure,
            asset_criticality=criticality,
            evidence=(pf.description.strip()[:600] or None),
            raw={"section": pf.section, "all_assets": pf.assets[:10]},
        ))
    return findings


# ---- Synthesised questionnaire --------------------------------------------
# We bias toward NO/low when the narrative reveals a corresponding weakness,
# YES/high when the narrative declares a control as PASSED, and a neutral
# "3" (scale_1_5) for controls the narrative is silent about.

# Per-domain finding presence is the strongest signal we have.
_DOMAIN_FAIL_THRESHOLD = {
    Domain.APPSEC:    1,   # any web-app finding => weak SDLC/sec testing
    Domain.NETWORK:   1,   # any network finding => weak segmentation
    Domain.CLOUD:     1,
    Domain.IDENTITY:  1,
    Domain.GOVERNANCE:1,
}


def build_questionnaire(pr: ParsedReport, org_id: str) -> QuestionnaireResponses:
    catalog = load_catalog()
    findings_by_domain: dict[Domain, list[ParsedFinding]] = {}
    for pf in pr.findings:
        d = _SEC_TO_DOMAIN.get(pf.section, Domain.APPSEC)
        findings_by_domain.setdefault(d, []).append(pf)

    dmarc_pass = pr.declared.get("dmarc") == "PASSED"
    spf_pass = pr.declared.get("spf") == "PASSED"
    ndpr_fail = pr.declared.get("ndpr") == "NON_COMPLIANT"
    malware_clean = pr.declared.get("malware") == "CLEAN"
    blocklist_clean = pr.declared.get("blocklist") == "PASSED"
    has_compromised_emails = bool(pr.compromised_emails)

    responses: list[ControlResponse] = []
    for ctrl in catalog.controls:
        cid = ctrl.control_id
        domain = ctrl.domain
        domain_failed = (
            len(findings_by_domain.get(domain, [])) >= _DOMAIN_FAIL_THRESHOLD.get(domain, 99)
        )

        # default: neutral on scales / unknown on yes_no
        if ctrl.response_type == "scale_1_5":
            score = 60.0
            raw_answer: object = 3
        else:
            score = 50.0
            raw_answer = "unknown"

        # Domain-level inference
        if domain_failed:
            score = 25.0 if ctrl.response_type == "scale_1_5" else 0.0
            raw_answer = 2 if ctrl.response_type == "scale_1_5" else "no"

        # Targeted overrides by control_id keyed off the narrative
        if cid.startswith("GOV") and ndpr_fail:
            score, raw_answer = 0.0, "no"
        if cid in {"IAM-001", "IAM-002"} and has_compromised_emails:
            # Mailbox MFA clearly weak - flip to NO.
            score, raw_answer = 0.0, "no"
        if cid.startswith("APP") and findings_by_domain.get(Domain.APPSEC):
            score, raw_answer = 0.0, "no"
        if cid.startswith("NET") and findings_by_domain.get(Domain.NETWORK):
            score, raw_answer = (25.0, 2) if ctrl.response_type == "scale_1_5" else (0.0, "no")
        if cid.startswith("CLD") and findings_by_domain.get(Domain.CLOUD):
            score, raw_answer = (25.0, 2) if ctrl.response_type == "scale_1_5" else (0.0, "no")

        # Email hygiene boosts from declared signals
        if cid == "IAM-003" and dmarc_pass and spf_pass:
            score, raw_answer = 75.0, "yes"
        if cid == "GOV-001" and not ndpr_fail:
            score, raw_answer = 75.0, "yes"
        if cid == "END-001" and malware_clean:
            score = max(score, 70.0) if ctrl.response_type == "scale_1_5" else 100.0
            raw_answer = 4 if ctrl.response_type == "scale_1_5" else "yes"
        if cid == "NET-001" and blocklist_clean:
            score = max(score, 60.0)
            raw_answer = "yes" if ctrl.response_type == "yes_no" else 3

        responses.append(ControlResponse(
            control_id=cid,
            raw_answer=raw_answer,
            score=score,
            notes="auto-inferred from docx narrative",
        ))

    return QuestionnaireResponses(
        org_id=org_id,
        submitted_at=datetime.now(tz=timezone.utc),
        responses=responses,
    )


def ingest_cida_docx(
    docx_path: str | Path,
    country: str = "NG",
) -> tuple[OrgProfile, QuestionnaireResponses, list[Finding], ParsedReport]:
    """One-shot ingestion: docx file -> (org, questionnaire, findings, raw parse)."""
    pr = parse_cida_docx(docx_path)
    org = build_org_profile(pr, country=country)
    questionnaire = build_questionnaire(pr, org_id=org.org_id)
    findings = build_findings(pr)
    return org, questionnaire, findings, pr
