"""CIDA content-based file type sniffer.

Detects the *data category* of any file by probing its internal structure -
never by filename. Supports 500+ security tools by scoring broad, stable
signals rather than tool-specific field names.

Usage
-----
    from ingest.sniffer import sniff, SniffResult

    result = sniff(Path("whatever_the_client_named_it.json"))
    print(result.category)   # e.g. "cspm_aws"
    print(result.scores)     # {"cspm_aws": 70, "vuln_scan": 20, ...}

Categories
----------
cspm_aws        AWS cloud security posture (Prowler, SecurityHub, ScoutSuite, Wiz, etc.)
cspm_azure      Azure cloud security posture (Defender, ScoutSuite-Azure, etc.)
cspm_gcp        GCP cloud security posture (SCC, ScoutSuite-GCP, etc.)
vuln_scan       Vulnerability scanner output (Nessus, Qualys, OpenVAS, Rapid7, Metasploit, …)
web_app_scan    Web application scanner (OWASP ZAP, Burp Suite, Nikto, Acunetix, …)
network_scan    Network/port scanner (NMAP, Masscan, Zmap, …)
attack_surface  ASM / OSINT (Shodan, Censys, Amass, theHarvester, Recon-ng, BBOT, …)
darkweb         Credential leak / dark-web intel
dmarc           DMARC / SPF / DKIM / email-security check output
questionnaire   Questionnaire / assessment responses
generic_findings Pre-normalised CIDA Finding[] JSON
vapt_pdf        VAPT / pentest PDF report
evidence_image  Screenshot or diagram (PNG, JPEG, SVG, GIF, …)
skip            File carries no findings (PPTX, key, etc.)
unknown         Could not classify - diagnostic info provided
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------

_IMAGE_EXTS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp",
    ".tiff", ".tif", ".svg", ".ico", ".heic", ".heif",
    ".avif", ".jfif", ".jp2",
}
_SKIP_EXTS = {".pptx", ".ppsx", ".key", ".ppt"}
_SCORE_THRESHOLD = 40
_MAX_SAMPLE_BYTES = 100_000  # 100 KB - never load more for classification


@dataclass
class SniffContext:
    path: Path
    ext: str                    # lower-cased suffix
    head_bytes: bytes           # first 4 KB for magic byte detection
    sample: Any                 # parsed sample (list[dict] | dict | list[list])
    xml_root: str | None        # root element tag (XML files)
    all_keys: set[str]          # flattened, lower-cased key names from sample
    str_values: list[str]       # sample of string values found in sample


@dataclass
class SniffResult:
    category: str               # winning category label
    scores: dict[str, int]      # score per category (for diagnostics)
    top_keys: list[str]         # top keys found in sample
    sample_values: list[str]    # sample of string values


@dataclass
class SniffRule:
    category: str
    priority: int               # tiebreak: higher = preferred on equal score
    score_fn: Callable[[SniffContext], int]


# The global rule registry - extended by registering rules at module import time
RULES: list[SniffRule] = []


def register_rule(category: str, priority: int = 0) -> Callable:
    """Decorator to register a scoring function as a SniffRule."""
    def decorator(fn: Callable[[SniffContext], int]) -> Callable:
        RULES.append(SniffRule(category=category, priority=priority, score_fn=fn))
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Core sniff entry point
# ---------------------------------------------------------------------------

def sniff(path: Path) -> SniffResult:
    """Classify *path* by content. Returns a SniffResult with category and scores.

    Category is ``"unknown"`` when no rule scores above the threshold.
    Category is ``"evidence_image"`` or ``"skip"`` for non-finding file types.
    """
    ext = path.suffix.lower()

    # --- Fast-path: images ---
    if ext in _IMAGE_EXTS:
        return SniffResult(category="evidence_image", scores={}, top_keys=[], sample_values=[])

    # --- Fast-path: magic bytes (catches renamed image files) ---
    try:
        head = path.read_bytes()[:4096]
    except Exception:
        return SniffResult(category="unknown", scores={}, top_keys=[], sample_values=[])

    if (head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8\xff")
            or head.startswith(b"GIF8") or head[:4] == b"RIFF"
            or head.startswith(b"<svg") or head.startswith(b"<?xml") and b"<svg" in head[:512]):
        # PNG, JPEG, GIF, WEBP (RIFF), SVG
        if head.startswith(b"\x89PNG") or head.startswith(b"\xff\xd8\xff") or head.startswith(b"GIF8"):
            return SniffResult(category="evidence_image", scores={}, top_keys=[], sample_values=[])
        if head[:4] == b"RIFF" and b"WEBP" in head[:16]:
            return SniffResult(category="evidence_image", scores={}, top_keys=[], sample_values=[])

    # --- Fast-path: presentation decks ---
    if ext in _SKIP_EXTS:
        return SniffResult(category="skip", scores={}, top_keys=[], sample_values=[])

    # --- Fast-path: PDF ---
    if head.startswith(b"%PDF") or ext == ".pdf":
        return SniffResult(category="vapt_pdf", scores={}, top_keys=[], sample_values=[])

    # --- Build context and score ---
    ctx = _build_context(path, ext, head)
    scores: dict[str, int] = {}
    for rule in RULES:
        try:
            scores[rule.category] = max(scores.get(rule.category, 0), rule.score_fn(ctx))
        except Exception:
            scores[rule.category] = scores.get(rule.category, 0)

    if not scores:
        category = "unknown"
    else:
        winner_cat = max(scores, key=lambda k: (scores[k], next(
            (r.priority for r in RULES if r.category == k), 0)))
        category = winner_cat if scores.get(winner_cat, 0) >= _SCORE_THRESHOLD else "unknown"

    top_keys = sorted(ctx.all_keys)[:20]
    sample_vals = ctx.str_values[:10]
    return SniffResult(category=category, scores=scores, top_keys=top_keys, sample_values=sample_vals)


def format_unknown_diagnostic(path: Path, result: SniffResult) -> str:
    """Return a human-readable diagnostic string for an unclassified file."""
    lines = [
        f"[sniffer] UNCLASSIFIED: {path.name}",
        f"  Extension    : {path.suffix or '(none)'}",
        f"  Size         : {_fmt_size(path)}",
        f"  Top keys     : {result.top_keys[:8]}",
        f"  Sample values: {result.sample_values[:5]}",
    ]
    if result.scores:
        top_scores = sorted(result.scores.items(), key=lambda x: -x[1])[:4]
        lines.append(f"  Near-miss    : " + ", ".join(f"{c}={s}" for c, s in top_scores))
    lines.append("  --> Note this file in your project or contact Aajimatics support to extend the sniffer.")
    return "\n".join(lines)


def _fmt_size(path: Path) -> str:
    try:
        b = path.stat().st_size
        if b < 1024:
            return f"{b} B"
        if b < 1024 ** 2:
            return f"{b/1024:.1f} KB"
        return f"{b/1024**2:.1f} MB"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(path: Path, ext: str, head_bytes: bytes) -> SniffContext:
    sample: Any = None
    xml_root: str | None = None
    all_keys: set[str] = set()
    str_values: list[str] = []

    try:
        if ext in (".json", ".jsonl"):
            sample, all_keys, str_values = _sample_json(path)
        elif ext in (".xml", ".nessus"):
            xml_root, all_keys = _sample_xml(path)
        elif ext == ".csv":
            sample, all_keys, str_values = _sample_csv(path)
        elif ext in (".xlsx", ".xls"):
            sample, all_keys, str_values = _sample_xlsx(path)
        elif ext == ".docx":
            str_values = _sample_docx(path)
            all_keys = set()
        elif ext in (".html", ".htm"):
            str_values = _sample_text(path)
            all_keys = set()
        else:
            # Try JSON first, then XML, then raw text
            try:
                sample, all_keys, str_values = _sample_json(path)
            except Exception:
                try:
                    xml_root, all_keys = _sample_xml(path)
                except Exception:
                    str_values = _sample_text(path)
    except Exception:
        pass

    return SniffContext(
        path=path, ext=ext, head_bytes=head_bytes,
        sample=sample, xml_root=xml_root,
        all_keys=all_keys, str_values=str_values,
    )


_LIST_WRAPPER_KEYS = {"findings", "vulnerabilities", "issues", "results", "alerts",
                      "checks", "controls", "hosts", "records", "data", "items"}


def _sample_json(path: Path) -> tuple[Any, set[str], list[str]]:
    raw = path.read_bytes()[:_MAX_SAMPLE_BYTES].decode("utf-8", errors="replace")

    # Try standard JSON first; fall back to JSONL (one object per line)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        parsed = []
        for ln in lines[:20]:
            try:
                parsed.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        data = parsed if parsed else []

    all_keys: set[str] = set()
    str_vals: list[str] = []

    # Unwrap common single-key wrappers - case-insensitive (handles "Findings", "FINDINGS" etc.)
    sample_list: list | None = None
    if isinstance(data, list):
        sample_list = data
    elif isinstance(data, dict):
        _collect(data, all_keys, str_vals)
        lower_data = {k.lower(): v for k, v in data.items()}
        for k in _LIST_WRAPPER_KEYS:
            v = lower_data.get(k)
            if isinstance(v, list) and v:
                sample_list = v
                break

    if sample_list:
        indices = {0, len(sample_list) // 2, len(sample_list) - 1}
        for i in indices:
            if i < len(sample_list):
                _collect(sample_list[i], all_keys, str_vals)
        return sample_list if not isinstance(data, dict) else data, all_keys, str_vals[:50]

    return data, all_keys, str_vals[:50]


def _sample_xml(path: Path) -> tuple[str | None, set[str]]:
    raw = path.read_bytes()[:_MAX_SAMPLE_BYTES].decode("utf-8", errors="replace")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # Try to parse just the header by truncating at a safe boundary
        truncated = raw[:raw.rfind("<", 0, len(raw) - 1)] + "</root>"
        try:
            root = ET.fromstring("<root>" + raw[:2000] + "</root>")
        except ET.ParseError:
            return None, set()

    tag = root.tag
    if "}" in tag:
        tag = tag.split("}", 1)[1]  # strip namespace

    all_keys: set[str] = {tag.lower()}
    # Collect child tag names and attribute names
    for child in list(root)[:10]:
        ctag = child.tag
        if "}" in ctag:
            ctag = ctag.split("}", 1)[1]
        all_keys.add(ctag.lower())
        all_keys.update(k.lower() for k in child.attrib)

    return tag, all_keys


def _sample_csv(path: Path) -> tuple[Any, set[str], list[str]]:
    text = path.read_bytes()[:_MAX_SAMPLE_BYTES].decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    rows = []
    for i, row in enumerate(reader):
        if i > 6:
            break
        rows.append(row)
    if not rows:
        return rows, set(), []
    headers = {h.strip().lower() for h in rows[0]}
    str_vals = [v for row in rows[1:4] for v in row if v.strip()]
    return rows, headers, str_vals[:30]


def _sample_xlsx(path: Path) -> tuple[Any, set[str], list[str]]:
    try:
        import openpyxl
        wb = openpyxl.load_workbook(path, data_only=True, read_only=True)
        ws = wb.active
        rows = []
        for i, row in enumerate(ws.iter_rows(values_only=True)):
            if i > 6:
                break
            rows.append([str(c) if c is not None else "" for c in row])
        wb.close()
        if not rows:
            return rows, set(), []
        headers = {h.strip().lower() for h in rows[0] if h.strip()}
        str_vals = [v for row in rows[1:4] for v in row if v.strip()]
        return rows, headers, str_vals[:30]
    except ImportError:
        return [], set(), []


def _sample_docx(path: Path) -> list[str]:
    try:
        import zipfile
        import xml.etree.ElementTree as ET2
        with zipfile.ZipFile(path) as z:
            with z.open("word/document.xml") as f:
                text_xml = f.read(8000).decode("utf-8", errors="replace")
        root = ET2.fromstring(text_xml)
        texts = [t for t in root.itertext()]
        return [t for t in texts if t.strip()][:20]
    except Exception:
        return []


def _sample_text(path: Path) -> list[str]:
    raw = path.read_bytes()[:_MAX_SAMPLE_BYTES].decode("utf-8", errors="replace")
    words = re.findall(r"[a-zA-Z0-9_\-\.@:/]+", raw)
    return words[:50]


def _collect(obj: Any, keys: set[str], vals: list[str], depth: int = 0) -> None:
    if depth > 4 or len(keys) > 200:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())
            _collect(v, keys, vals, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:3]:
            _collect(item, keys, vals, depth + 1)
    elif isinstance(obj, str) and len(obj) < 200:
        vals.append(obj)


# ---------------------------------------------------------------------------
# Built-in scoring rules
# ---------------------------------------------------------------------------

def _has_any(ctx_keys: set[str], *candidates: str) -> bool:
    return bool(ctx_keys.intersection(candidates))


def _val_contains(str_values: list[str], *substrings: str) -> bool:
    combined = " ".join(str_values).lower()
    return any(s.lower() in combined for s in substrings)


def _key_and(ctx_keys: set[str], group_a: set[str], group_b: set[str]) -> bool:
    return bool(ctx_keys & group_a) and bool(ctx_keys & group_b)


def _key_contains_any(ctx_keys: set[str], *patterns: str) -> bool:
    """Return True if any key in ctx_keys contains any of the patterns as a substring."""
    return any(any(p in k for p in patterns) for k in ctx_keys)


# ---- AWS CSPM ----
@register_rule("cspm_aws", priority=10)
def _score_aws(ctx: SniffContext) -> int:
    s = 0
    if _has_any(ctx.all_keys, "awsaccountid", "account_id", "aws_account_id", "accountid"):
        s += 40
    if _val_contains(ctx.str_values, "arn:aws:"):
        s += 30
    if _key_and(ctx.all_keys,
                {"checkid", "ruleid", "controlid", "check_id", "rule_id", "control_id"},
                {"status", "result", "passed", "failed"}):
        s += 20
    # Prowler / SecurityHub specific: ServiceName + Region are AWS-distinctive
    if _has_any(ctx.all_keys, "servicename", "service_name", "awsregion", "region"):
        if _key_and(ctx.all_keys,
                    {"checkid", "ruleid", "controlid", "check_id", "servicename", "service_name"},
                    {"status", "result", "passed", "failed", "severity"}):
            s += 25
    if _val_contains(ctx.str_values, "us-east", "us-west", "eu-west", "ap-southeast", "ap-northeast",
                     "us-east-1", "us-west-2", "eu-central", "ap-south"):
        s += 15
    if ctx.xml_root and any(k in ctx.xml_root.lower() for k in ("aws", "securityhub")):
        s += 30
    if _has_any(ctx.all_keys, "s3", "ec2", "iam", "cloudtrail", "vpc", "lambda", "rds", "eks"):
        s += 15
    return s


# ---- Azure CSPM ----
@register_rule("cspm_azure", priority=10)
def _score_azure(ctx: SniffContext) -> int:
    s = 0
    if _has_any(ctx.all_keys, "subscriptionid", "tenantid", "resourcegroup", "managementgroup",
                "subscription_id", "tenant_id", "resource_group"):
        s += 40
    if _val_contains(ctx.str_values, "azure.com", "microsoft.com", "microsoftonline.com"):
        s += 20
    if _val_contains(ctx.str_values, "/subscriptions/"):
        s += 30
    if _key_and(ctx.all_keys,
                {"checkid", "ruleid", "controlid", "check_id", "rule_id"},
                {"status", "result", "passed", "failed"}):
        s += 15
    if ctx.xml_root and "azure" in ctx.xml_root.lower():
        s += 30
    # Azure Defender / Defender for Cloud specific fields
    if _has_any(ctx.all_keys, "resourcedetails", "resource_details"):
        s += 25
    if _has_any(ctx.all_keys, "resourcedetails", "resource_details"):
        if _val_contains(ctx.str_values, "unhealthy", "healthy", "notapplicable"):
            s += 20
    # displayName pattern common in Azure
    if _has_any(ctx.all_keys, "displayname", "display_name"):
        if _has_any(ctx.all_keys, "status", "severity", "resourcedetails"):
            s += 15
    # ScoutSuite Azure: services dict with Azure-specific service names
    if _has_any(ctx.all_keys, "services"):
        if _has_any(ctx.all_keys, "storageaccounts", "keyvault", "activedirectory",
                    "virtualnetworks", "networksecuritygroups", "defender", "azuread"):
            s += 45
    return s


# ---- GCP CSPM ----
@register_rule("cspm_gcp", priority=10)
def _score_gcp(ctx: SniffContext) -> int:
    s = 0
    if _has_any(ctx.all_keys, "projectid", "organizationid", "project_id", "org_id",
                "folderid", "folder_id"):
        s += 30
    if _val_contains(ctx.str_values, "googleapis.com", ".gcp.com", "gcp."):
        s += 20
    if _val_contains(ctx.str_values, "organizations/", "projects/", "folders/"):
        s += 30
    if _key_and(ctx.all_keys,
                {"checkid", "ruleid", "findingclass", "category"},
                {"status", "state", "active", "muted"}):
        s += 15
    if ctx.xml_root and "gcp" in ctx.xml_root.lower():
        s += 30
    # GCP Security Command Center specific signals
    if _has_any(ctx.all_keys, "resourcename", "resource_name"):
        # resourceName is a strong GCP SCC indicator
        s += 20
        # GCP SCC state values
        if _val_contains(ctx.str_values, "active", "inactive", "muted"):
            s += 15
    # GCP SCC finding names start with organizations/ or projects/
    if _val_contains(ctx.str_values, "//") and _has_any(ctx.all_keys, "resourcename", "resource_name"):
        s += 15
    # ScoutSuite GCP: services dict + project_id metadata
    if _has_any(ctx.all_keys, "services"):
        if _has_any(ctx.all_keys, "project_id", "projectid"):
            s += 25
        if _has_any(ctx.all_keys, "cloudsql", "cloudstorage", "cloudkms", "cloudrun",
                    "gke", "bigquery", "cloudfunction", "pubsub"):
            s += 40
    return s


# ---- Vulnerability scanner (Nessus, Qualys, OpenVAS, Rapid7, Metasploit, Tenable, …) ----
@register_rule("vuln_scan", priority=8)
def _score_vuln(ctx: SniffContext) -> int:
    s = 0
    _KNOWN_XML_ROOTS = {
        "nessusclientdata", "nessusclientdata_v2", "hostedscandata", "scandata",
        "scanresults", "asset_data_report", "metasploitv5", "metasploitexpressv1",
        "nexposereport", "nexposerawdata", "report",
    }
    if ctx.xml_root:
        root_lower = ctx.xml_root.lower()
        if root_lower in _KNOWN_XML_ROOTS:
            s += 60
        elif any(k in root_lower for k in ("vuln", "scan", "report", "finding")):
            s += 30
    if _has_any(ctx.all_keys, "plugin_id", "plugin_name", "vuln_id", "vulnerability_id",
                "vulnerabilityid", "cve_id", "nvt_oid", "bugtraq_id"):
        s += 30
    if _has_any(ctx.all_keys, "cvss", "cvss_score", "cvss_base_score",
                "cvss3_base_score", "risk_score", "risk_factor", "cvssscore"):
        s += 20
    if _has_any(ctx.all_keys, "host", "ip", "ip_address", "hostname", "asset_id", "fqdn"):
        s += 15
    if _has_any(ctx.all_keys, "description", "recommendation", "solution", "remediation",
                "synopsis", "plugin_output"):
        s += 10
    # JSON list with severity + host is a strong signal for any scanner
    if isinstance(ctx.sample, list) and ctx.sample:
        if _key_and(ctx.all_keys, {"severity", "risk", "risk_factor"},
                    {"host", "ip", "hostname", "asset"}):
            s += 25
    # Code/container/dependency scanning (Snyk, Trivy, Grype, Syft, etc.)
    if _has_any(ctx.all_keys, "packagename", "package_name", "package", "pkgname",
                "packageversion", "package_version", "library", "module_name"):
        if _has_any(ctx.all_keys, "severity", "risk", "cvssscore", "cvss"):
            s += 25
    return s


# ---- Web application scanner (ZAP, Burp, Nikto, Acunetix, AppScan, w3af, …) ----
@register_rule("web_app_scan", priority=9)
def _score_webapp(ctx: SniffContext) -> int:
    s = 0
    _KNOWN_XML_ROOTS = {
        "owaspzapreport", "issues", "burpversion", "nikto-report", "scangroup",
        "niktoscan", "acunetix", "wvs", "acufinding",
    }
    if ctx.xml_root:
        root_lower = ctx.xml_root.lower()
        if root_lower in _KNOWN_XML_ROOTS:
            s += 60
        elif any(k in root_lower for k in ("zap", "burp", "web", "app", "scan")):
            s += 25
    if _key_and(ctx.all_keys,
                {"alert", "alertitem", "issue", "finding", "vulnerability"},
                {"riskcode", "risk", "severity", "confidence", "cweid"}):
        s += 25
    if _key_and(ctx.all_keys,
                {"url", "uri", "endpoint", "path", "parameter", "param"},
                {"severity", "risk", "riskcode"}):
        s += 20
    if _has_any(ctx.all_keys, "solution", "reference", "desc", "alert"):
        if _val_contains(ctx.str_values, "http://", "https://"):
            s += 15
    if _has_any(ctx.all_keys, "cweid", "wascid", "owasp"):
        s += 10
    return s


# ---- Network / port scanner (NMAP, Masscan, Zmap, …) ----
@register_rule("network_scan", priority=9)
def _score_network(ctx: SniffContext) -> int:
    s = 0
    _KNOWN_XML_ROOTS = {"nmaprun", "masscan", "zmap-output", "nmapscan"}
    if ctx.xml_root:
        root_lower = ctx.xml_root.lower()
        if root_lower in _KNOWN_XML_ROOTS:
            s += 70
        elif any(k in root_lower for k in ("nmap", "scan", "port")):
            s += 30
    if _key_and(ctx.all_keys,
                {"host", "hostname", "address", "addr", "ip"},
                {"port", "portid", "ports", "open_ports"}):
        s += 25
    if _has_any(ctx.all_keys, "state", "open", "closed", "filtered"):
        s += 15
    if _has_any(ctx.all_keys, "service", "servicename", "product", "version",
                "extrainfo", "banner", "cpe"):
        s += 15
    if _has_any(ctx.all_keys, "os", "osmatch", "osclass", "osfamily"):
        s += 10
    if _has_any(ctx.all_keys, "protocol", "proto"):
        s += 5
    # Zmap / internet-wide scanner: classification field alongside ip+port
    if _has_any(ctx.all_keys, "classification", "saddr", "daddr"):
        if _has_any(ctx.all_keys, "ip", "host", "addr"):
            s += 25
    return s


# ---- Attack surface / ASM / OSINT (Shodan, Censys, Amass, theHarvester, BBOT, …) ----
@register_rule("attack_surface", priority=7)
def _score_asm(ctx: SniffContext) -> int:
    s = 0
    if _key_and(ctx.all_keys,
                {"ip", "ip_str", "ip_address"},
                {"ports", "open_ports", "port", "data"}):
        s += 40
    if _key_and(ctx.all_keys,
                {"hostname", "hostnames", "fqdn"},
                {"technologies", "services", "banner", "http"}):
        s += 30
    if _has_any(ctx.all_keys, "asn", "isp", "country_code", "org"):
        s += 20
    if _key_and(ctx.all_keys,
                {"subdomain", "dns", "cname", "mx", "ns"},
                {"ip", "address", "value"}):
        s += 25
    if _has_any(ctx.all_keys, "shodan", "censys", "amass"):
        s += 20
    if _has_any(ctx.all_keys, "vulns", "cpe", "tags"):
        s += 10
    # Amass / theHarvester JSONL: name + addresses + sources pattern
    if _key_and(ctx.all_keys, {"name", "names"}, {"addresses", "address"}):
        if _has_any(ctx.all_keys, "sources", "source"):
            s += 40
    # Censys nested hits: ip + services nested deep
    if _has_any(ctx.all_keys, "hits", "result"):
        if _has_any(ctx.all_keys, "ip", "ip_str") and _has_any(ctx.all_keys, "services", "port"):
            s += 35
    # theHarvester: top-level flat dict with plural collection keys
    if _has_any(ctx.all_keys, "subdomains") and _has_any(ctx.all_keys, "ips"):
        s += 45
    elif _has_any(ctx.all_keys, "subdomains") and _has_any(ctx.all_keys, "hosts"):
        s += 35
    # BBOT: list of typed events with DNS_NAME / IP_ADDRESS / OPEN_TCP_PORT values
    if _val_contains(ctx.str_values, "dns_name", "ip_address", "open_tcp_port"):
        if _has_any(ctx.all_keys, "type", "module", "tags"):
            s += 45
    return s


# ---- Dark web credential dumps ----
@register_rule("darkweb", priority=10)
def _score_darkweb(ctx: SniffContext) -> int:
    s = 0
    # Use substring matching so "password_status", "passwd_hash" etc. all match
    has_email = _has_any(ctx.all_keys, "email") or _key_contains_any(ctx.all_keys, "email")
    if has_email:
        if _key_contains_any(ctx.all_keys, "password", "passwd", "pass"):
            s += 50
        if _key_contains_any(ctx.all_keys, "breach", "leak", "dump", "collection", "source_name"):
            s += 40
        if _key_contains_any(ctx.all_keys, "hash", "plaintext", "credential"):
            s += 30
        # "source_breach" pattern: any key containing both a source and breach concept
        if any("breach" in k or "leak" in k or "dump" in k for k in ctx.all_keys):
            s += 20
    if _has_any(ctx.all_keys, "stealer", "infostealer", "malware_family"):
        s += 20
    # CSV: email + password headers are very strong; use substring match on each header
    if isinstance(ctx.sample, list) and ctx.sample:
        headers = [str(h).lower().strip() for h in (ctx.sample[0] if ctx.sample else [])]
        has_email_col = any("email" in h for h in headers)
        has_pass_col = any("password" in h or "passwd" in h or h == "pass" for h in headers)
        if has_email_col and has_pass_col:
            s += 60
    return s


# ---- DMARC / email security ----
@register_rule("dmarc", priority=9)
def _score_dmarc(ctx: SniffContext) -> int:
    s = 0
    if _key_and(ctx.all_keys, {"dmarc"}, {"spf"}):
        s += 50
    if _has_any(ctx.all_keys, "dmarc_policy", "spf_result", "dkim_result",
                "dkim_selector", "bimi"):
        s += 50
    if _key_and(ctx.all_keys, {"dkim"}, {"dmarc"}):
        s += 30
    if _val_contains(ctx.str_values, "dmarc", "spf", "dkim"):
        s += 10
    return s


# ---- Questionnaire / assessment responses ----
@register_rule("questionnaire", priority=6)
def _score_questionnaire(ctx: SniffContext) -> int:
    s = 0
    if _key_and(ctx.all_keys,
                {"question", "question_id", "control_id", "question_text"},
                {"answer", "response", "value", "selected"}):
        s += 60
    if _key_and(ctx.all_keys,
                {"control_id", "question_id", "q_id"},
                {"answer", "response", "value"}):
        s += 40
    return s


# ---- Generic pre-normalised CIDA findings ----
@register_rule("generic_findings", priority=5)
def _score_generic(ctx: SniffContext) -> int:
    from models import Finding

    # Try bare list
    candidates: list[Any] = []
    if isinstance(ctx.sample, list) and ctx.sample:
        candidates.append(ctx.sample[0])
    # Try dict with wrapper key
    elif isinstance(ctx.sample, dict):
        for k in _LIST_WRAPPER_KEYS:
            v = ctx.sample.get(k)
            if isinstance(v, list) and v:
                candidates.append(v[0])
                break

    for item in candidates:
        if isinstance(item, dict):
            try:
                Finding.model_validate(item)
                return 80
            except Exception:
                pass
    return 0
