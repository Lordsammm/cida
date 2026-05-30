"""Tests for the DMARC / SPF / DKIM / MTA-STS parser."""
from __future__ import annotations

import json

from ingest.dmarc import parse_dmarc_check
from models import Domain, Severity


def _write(tmp_path, payload) -> object:
    p = tmp_path / "dmarc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# DMARC findings
# ---------------------------------------------------------------------------

def test_dmarc_missing_raises_high(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com", "dmarc": {"present": False},
                           "spf": {"present": True}, "dkim": {"present": True},
                           "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    dmarc_f = next(f for f in findings if "DMARC" in f.title)
    assert dmarc_f.severity == Severity.HIGH
    assert dmarc_f.domain == Domain.DETECT_RESPOND
    assert dmarc_f.cwe_id == "CWE-290"


def test_dmarc_policy_none_is_medium(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com",
                           "dmarc": {"present": True, "policy": "none"},
                           "spf": {"present": True}, "dkim": {"present": True},
                           "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    dmarc_f = next(f for f in findings if "policy = none" in f.title)
    assert dmarc_f.severity == Severity.MEDIUM


def test_dmarc_reject_policy_no_finding(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com",
                           "dmarc": {"present": True, "policy": "reject", "pct": 100},
                           "spf": {"present": True}, "dkim": {"present": True},
                           "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    assert not any("DMARC" in f.title for f in findings)


# ---------------------------------------------------------------------------
# SPF findings
# ---------------------------------------------------------------------------

def test_spf_missing_raises_medium(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com",
                           "dmarc": {"present": True, "policy": "reject"},
                           "spf": {"present": False},
                           "dkim": {"present": True}, "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    spf_f = next(f for f in findings if "SPF" in f.title)
    assert spf_f.severity == Severity.MEDIUM


def test_spf_present_no_finding(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com",
                           "dmarc": {"present": True, "policy": "reject"},
                           "spf": {"present": True},
                           "dkim": {"present": True}, "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    assert not any("SPF" in f.title for f in findings)


# ---------------------------------------------------------------------------
# DKIM findings
# ---------------------------------------------------------------------------

def test_dkim_missing_raises_medium(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com",
                           "dmarc": {"present": True, "policy": "reject"},
                           "spf": {"present": True},
                           "dkim": {"present": False}, "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    dkim_f = next(f for f in findings if "DKIM" in f.title)
    assert dkim_f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# MTA-STS
# ---------------------------------------------------------------------------

def test_mta_sts_missing_raises_low(tmp_path):
    p = _write(tmp_path, {"domain": "acme.com",
                           "dmarc": {"present": True, "policy": "reject"},
                           "spf": {"present": True},
                           "dkim": {"present": True}, "mta_sts": {"present": False}})
    findings = parse_dmarc_check(p)
    mta_f = next(f for f in findings if "MTA-STS" in f.title)
    assert mta_f.severity == Severity.LOW


# ---------------------------------------------------------------------------
# Fully secure domain - zero findings
# ---------------------------------------------------------------------------

def test_fully_secure_domain_zero_findings(tmp_path):
    p = _write(tmp_path, {"domain": "secure.com",
                           "dmarc": {"present": True, "policy": "reject", "pct": 100},
                           "spf": {"present": True},
                           "dkim": {"present": True},
                           "mta_sts": {"present": True}})
    findings = parse_dmarc_check(p)
    assert findings == []


# ---------------------------------------------------------------------------
# Worst case - everything missing
# ---------------------------------------------------------------------------

def test_everything_missing(tmp_path):
    p = _write(tmp_path, {"domain": "broken.com",
                           "dmarc": {"present": False},
                           "spf": {"present": False},
                           "dkim": {"present": False},
                           "mta_sts": {"present": False}})
    findings = parse_dmarc_check(p)
    # At minimum: DMARC missing (HIGH) + SPF missing (MEDIUM) + DKIM missing (MEDIUM) + MTA-STS (LOW)
    assert len(findings) >= 4
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities


# ---------------------------------------------------------------------------
# Multiple domains in one file (list format)
# ---------------------------------------------------------------------------

def test_multiple_domains_in_list(tmp_path):
    payload = [
        {"domain": "acme.com", "dmarc": {"present": False}, "spf": {"present": True},
         "dkim": {"present": True}, "mta_sts": {"present": True}},
        {"domain": "sub.acme.com", "dmarc": {"present": True, "policy": "none"},
         "spf": {"present": False}, "dkim": {"present": False}, "mta_sts": {"present": False}},
    ]
    p = tmp_path / "dmarc_multi.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_dmarc_check(p)
    domains = {f.asset for f in findings}
    assert "acme.com" in domains
    assert "sub.acme.com" in domains


# ---------------------------------------------------------------------------
# Domain asset is set correctly
# ---------------------------------------------------------------------------

def test_asset_is_domain_name(tmp_path):
    p = _write(tmp_path, {"domain": "cornerstone.ng",
                           "dmarc": {"present": False}, "spf": {"present": False},
                           "dkim": {"present": False}, "mta_sts": {"present": False}})
    findings = parse_dmarc_check(p)
    assert all(f.asset == "cornerstone.ng" for f in findings)
