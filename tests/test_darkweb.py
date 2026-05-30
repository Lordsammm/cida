"""Tests for dark-web intelligence connector."""
from __future__ import annotations

import json

from ingest.darkweb import parse_darkweb
from models import Domain, Severity


def test_parse_credential_leak_csv(tmp_path):
    csv_text = (
        "email,source_breach,date,password_status,password_plaintext_exposed,severity\n"
        "alice@acme.com,LinkedIn 2021,2021-06-01,plaintext,true,\n"
        "ceo@acme.com,Adobe 2013,2013-10-01,hashed,false,\n"
        "old@acme.com,MySpace 2008,2008-01-01,unknown,false,\n"
    )
    p = tmp_path / "darkweb_credleak.csv"
    p.write_text(csv_text, encoding="utf-8")
    findings = parse_darkweb(p, org_email_domains=["acme.com"])
    assert len(findings) == 3
    # plaintext non-exec → HIGH
    alice = next(f for f in findings if "alice@" in f.title)
    assert alice.severity == Severity.HIGH
    assert alice.domain == Domain.IDENTITY
    # exec hashed → HIGH
    ceo = next(f for f in findings if "ceo@" in f.title)
    assert ceo.severity == Severity.HIGH
    # old unknown → LOW
    old = next(f for f in findings if "old@" in f.title)
    assert old.severity == Severity.LOW
    # org_match flag wired
    assert all(f.raw.get("org_match") is True for f in findings)


def test_parse_stealer_log(tmp_path):
    payload = [
        {
            "victim_email": "user@acme.com",
            "malware_family": "RedLine",
            "first_seen": "2025-12-01",
            "affected_domain": "acme.com",
            "credentials_count": 47,
            "machine_id": "HW-9999",
        },
        {
            "victim_email": "other@notacme.com",
            "malware_family": "Lumma",
            "first_seen": "2025-11-15",
            "affected_domain": "notacme.com",
            "credentials_count": 5,
            "machine_id": "HW-1234",
        },
    ]
    p = tmp_path / "darkweb_stealer.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_darkweb(p, org_email_domains=["acme.com"])
    assert len(findings) == 2
    org_match_f = next(f for f in findings if f.raw.get("org_match"))
    assert org_match_f.severity == Severity.CRITICAL
    assert org_match_f.domain == Domain.ENDPOINT
    other_f = next(f for f in findings if not f.raw.get("org_match"))
    assert other_f.severity == Severity.HIGH


def test_parse_breach_mention(tmp_path):
    payload = {
        "records": [
            {"mention_text": "Selling RDP access to internal data of acme.com", "source": "exploit_forum",
             "date": "2026-04-15", "keywords": "auction,exfil,internal data"},
            {"mention_text": "Ransomware victim list updated", "source": "telegram",
             "date": "2026-04-10", "keywords": "ransomware"},
            {"mention_text": "General discussion about banking sector", "source": "forum",
             "date": "2026-04-01", "keywords": ""},
        ]
    }
    p = tmp_path / "darkweb_mention.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_darkweb(p)
    assert len(findings) == 3
    crit_f = next(f for f in findings if "RDP access" in f.title)
    assert crit_f.severity == Severity.CRITICAL  # auction + exfil
    ransom_f = next(f for f in findings if "Ransomware" in f.title)
    assert ransom_f.severity == Severity.HIGH
    neutral_f = next(f for f in findings if "banking" in f.title)
    assert neutral_f.severity == Severity.MEDIUM


def test_dispatcher_picks_up_all_sources(tmp_path):
    """End-to-end: drop one file per source into a dir and confirm dispatcher
    routes them all."""
    from ingest.findings import load_findings_from_dir

    # AWS
    (tmp_path / "prowler.json").write_text(
        json.dumps([{"CheckID": "iam_x", "CheckTitle": "IAM finding", "ServiceName": "iam",
                     "Status": "FAIL", "Severity": "high", "ResourceArn": "arn:..."}]),
        encoding="utf-8",
    )
    # Azure
    (tmp_path / "azure_defender.json").write_text(
        json.dumps([{"id": "x", "name": "y", "properties": {"displayName": "x", "severity": "Medium",
                     "status": {"code": "Unhealthy"}, "resourceDetails": {"id": "/subs/x/y"}}}]),
        encoding="utf-8",
    )
    # GCP
    (tmp_path / "gcp_scc.json").write_text(
        json.dumps({"findings": [{"name": "n", "state": "ACTIVE", "category": "X",
                                  "severity": "MEDIUM", "resourceName": "//x/y"}]}),
        encoding="utf-8",
    )
    # Shodan
    (tmp_path / "shodan_asm.json").write_text(
        json.dumps([{"ip_str": "1.1.1.1", "port": 22, "product": "OpenSSH"}]),
        encoding="utf-8",
    )
    # Dark web
    (tmp_path / "darkweb_creds.csv").write_text(
        "email,source_breach,password_status\nalice@acme.com,Test,plaintext\n",
        encoding="utf-8",
    )

    findings = load_findings_from_dir(tmp_path, org_email_domains=["acme.com"])
    sources = {f.source for f in findings}
    assert "prowler" in sources
    assert "azure_defender" in sources
    assert "gcp_scc" in sources
    assert "shodan" in sources
    assert "darkweb_credentials" in sources
