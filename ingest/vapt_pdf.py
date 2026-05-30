"""Custom VAPT / Blackbox PDF report parser.

Strategy:
1. Try pdfplumber text extraction.
2. Look for structured findings tables (Title | Severity | CVSS | CVE).
3. If unstructured, return a single placeholder finding flagging that LLM-assisted
   extraction is recommended - see `extract_with_llm` hook below.

This is intentionally simple; production should layer an LLM-assisted extractor
(OpenAI structured output, Pydantic schema) for arbitrary VAPT report formats.
"""
from __future__ import annotations

import re
from pathlib import Path

from models import Domain, Finding, Severity

_SEV_KEYWORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CVSS_RE = re.compile(r"CVSS\s*v?3?(?:\.\d+)?\s*[: ]\s*(\d+(?:\.\d+)?)", re.IGNORECASE)


def parse_vapt_pdf(pdf_path: str | Path) -> list[Finding]:
    try:
        import pdfplumber
    except ImportError:
        print("[warn] pdfplumber not installed; VAPT PDF parsing disabled.")
        return []

    pdf_path = Path(pdf_path)
    findings: list[Finding] = []
    text_chunks: list[str] = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            text_chunks.append(text)
            # Try table-based extraction
            for table in page.extract_tables() or []:
                if not table or len(table) < 2:
                    continue
                headers = [str(h).strip().lower() if h else "" for h in table[0]]
                if any("severity" in h for h in headers) or any("risk" in h for h in headers):
                    sev_idx = next((i for i, h in enumerate(headers) if "severity" in h or "risk" in h), None)
                    title_idx = next((i for i, h in enumerate(headers) if "title" in h or "finding" in h or "vulnerability" in h), 0)
                    for row in table[1:]:
                        if not row or len(row) <= max(sev_idx or 0, title_idx):
                            continue
                        title = str(row[title_idx] or "").strip()
                        if not title:
                            continue
                        sev_raw = str(row[sev_idx] or "").strip().lower() if sev_idx is not None else ""
                        sev = _SEV_KEYWORDS.get(sev_raw, Severity.MEDIUM)
                        findings.append(Finding(
                            source="vapt_pdf", asset="reported_in_vapt", title=title[:200],
                            severity=sev, domain=Domain.APPSEC, exposure="unknown",
                            evidence=str(pdf_path.name),
                        ))

    # If no structured findings, do regex-based fallback over full text
    if not findings:
        full = "\n".join(text_chunks)
        for cve_match in _CVE_RE.finditer(full):
            cve = cve_match.group(0).upper()
            window = full[max(0, cve_match.start() - 200): cve_match.end() + 200]
            cvss_m = _CVSS_RE.search(window)
            cvss = float(cvss_m.group(1)) if cvss_m else None
            sev = Severity.MEDIUM
            if cvss is not None:
                sev = Severity.CRITICAL if cvss >= 9 else Severity.HIGH if cvss >= 7 else Severity.MEDIUM if cvss >= 4 else Severity.LOW
            findings.append(Finding(
                source="vapt_pdf", asset="reported_in_vapt", title=f"{cve} referenced in VAPT report",
                severity=sev, domain=Domain.NETWORK, cve_id=cve, cvss_v3=cvss,
                evidence=str(pdf_path.name),
            ))

    return findings


def extract_with_llm(pdf_path: str | Path, provider: str = "openai", model: str | None = None) -> list[Finding]:
    """LLM-assisted extraction of findings from an unstructured VAPT PDF.

    Uses OpenAI (default) or Anthropic structured output to parse the PDF text
    into a list of Finding objects.

    Requires:
      - For provider='openai':    OPENAI_API_KEY env var, `openai` package installed
      - For provider='anthropic': ANTHROPIC_API_KEY env var, `anthropic` package installed
      - pdfplumber for PDF text extraction

    Costs roughly $0.05-0.30 per VAPT report depending on length.
    """
    import os

    try:
        import pdfplumber
    except ImportError as e:
        raise RuntimeError("pdfplumber required for VAPT PDF extraction") from e

    pdf_path = Path(pdf_path)
    with pdfplumber.open(pdf_path) as pdf:
        text = "\n\n".join((page.extract_text() or "") for page in pdf.pages)

    if len(text.strip()) < 100:
        return []

    # Truncate very long reports - keep first 60k chars (≈ 15k tokens) to stay
    # under typical context limits while covering most VAPT layouts.
    text = text[:60_000]

    system_prompt = (
        "You are a security-finding extractor. Given a VAPT/pentest report, extract every "
        "distinct vulnerability finding as a JSON array. Each item MUST have: "
        "title (string), severity (one of: critical, high, medium, low, info), "
        "domain (one of: governance, identity, asset_data, network, endpoint, appsec, "
        "cloud, third_party, detect_respond, resilience), asset (string), "
        "cve_id (string|null), cvss_v3 (number|null), exposure (one of: internet, internal, unknown), "
        "evidence (short string|null). Output ONLY the JSON array, no prose."
    )

    if provider == "openai":
        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError("Install with: pip install openai") from e
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY not set")
        client = OpenAI()
        resp = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text},
            ],
            response_format={"type": "json_object"},
            temperature=0.0,
        )
        content = resp.choices[0].message.content or "{}"
    elif provider == "anthropic":
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError("Install with: pip install anthropic") from e
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=model or "claude-3-5-sonnet-latest",
            max_tokens=8000,
            system=system_prompt + " Wrap the array in {\"findings\": [...]}.",
            messages=[{"role": "user", "content": text}],
        )
        content = resp.content[0].text  # type: ignore
    else:
        raise ValueError(f"Unknown provider: {provider}")

    import json
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Salvage: extract first JSON array we can find
        import re
        m = re.search(r"\[.*\]", content, re.DOTALL)
        if not m:
            return []
        data = {"findings": json.loads(m.group(0))}

    if isinstance(data, dict):
        items = data.get("findings", []) or []
    else:
        items = data

    out: list[Finding] = []
    for item in items:
        try:
            item.setdefault("source", "vapt_pdf_llm")
            item.setdefault("asset", "reported_in_vapt")
            out.append(Finding.model_validate(item))
        except Exception:
            continue
    return out
