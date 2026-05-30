"""Tests for attack-surface mapping connector (Shodan / Censys / Amass)."""
from __future__ import annotations

import json

from ingest.attack_surface import parse_attack_surface
from models import Domain, Severity


def test_parse_shodan(tmp_path):
    sample = [
        {
            "ip_str": "1.2.3.4",
            "port": 3306,
            "transport": "tcp",
            "product": "MySQL",
            "hostnames": ["db.acme.com"],
            "vulns": {"CVE-2024-1111": {"summary": "auth bypass"}},
            "ssl": {"cert": {"expired": True, "subject": {"CN": "db.acme.com"}}},
        },
        {
            "ip_str": "1.2.3.5",
            "port": 443,
            "transport": "tcp",
            "product": "nginx",
            "hostnames": ["www.acme.com"],
        },
    ]
    p = tmp_path / "shodan.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_attack_surface(p)
    # Expect: per-port (2) + CVE (1) + expired cert (1)
    assert len(findings) == 4
    # CVE finding present, with cve_id set
    cve_f = next(f for f in findings if f.cve_id == "CVE-2024-1111")
    assert cve_f.severity == Severity.CRITICAL
    # Exposed MySQL is HIGH and asset_data domain
    mysql_f = next(f for f in findings if "3306" in f.asset and f.cve_id is None)
    assert mysql_f.severity == Severity.HIGH
    assert mysql_f.domain == Domain.ASSET_DATA
    # Expired cert finding
    cert_f = next(f for f in findings if "Expired" in f.title)
    assert cert_f.severity == Severity.MEDIUM
    assert cert_f.domain == Domain.APPSEC


def test_parse_censys(tmp_path):
    sample = {
        "result": {
            "hits": [
                {
                    "ip": "10.0.0.1",
                    "autonomous_system": {"asn": 12345},
                    "services": [
                        {"port": 22, "service_name": "SSH", "software": [{"product": "OpenSSH"}], "banner": "SSH-2.0-OpenSSH_7.4"},
                        {"port": 80, "service_name": "HTTP", "software": [{"product": "nginx"}], "banner": ""},
                    ],
                }
            ]
        }
    }
    p = tmp_path / "censys.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_attack_surface(p)
    assert len(findings) == 2
    ssh_f = next(f for f in findings if "22" in f.asset)
    assert ssh_f.severity == Severity.MEDIUM
    assert ssh_f.domain == Domain.NETWORK
    http_f = next(f for f in findings if "80" in f.asset)
    assert http_f.domain == Domain.APPSEC


def test_parse_amass_jsonl(tmp_path):
    sample = (
        json.dumps({"name": "sub1.acme.com", "addresses": [{"ip": "1.2.3.4"}], "sources": ["cert"]}) + "\n"
        + json.dumps({"name": "sub2.acme.com", "addresses": [{"ip": "1.2.3.5"}], "sources": ["dns"]}) + "\n"
        + json.dumps({"name": "sub3.acme.com", "addresses": [], "sources": []}) + "\n"
    )
    p = tmp_path / "amass.jsonl"
    p.write_text(sample, encoding="utf-8")
    findings = parse_attack_surface(p)
    assert len(findings) == 3
    assert all(f.source == "amass" for f in findings)
    assert all(f.severity == Severity.LOW for f in findings)
    assert all(f.domain == Domain.ASSET_DATA for f in findings)
