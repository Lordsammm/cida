"""Tests for the Nessus CSV and XML parsers."""
from __future__ import annotations

from ingest.nessus import parse_nessus_csv, parse_nessus_xml, parse_nessus
from models import Domain, Severity


# ---------------------------------------------------------------------------
# CSV parser
# ---------------------------------------------------------------------------

def test_csv_skips_informational(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "11111,,0.0,None,10.0.0.1,tcp,0,Ping the remote host,Host is alive\n"
        "22222,,0.0,Informational,10.0.0.1,tcp,0,OS Detection,Linux detected\n"
    )
    p = tmp_path / "scan.csv"
    p.write_text(csv, encoding="utf-8")
    assert parse_nessus_csv(p) == []


def test_csv_severity_mapping(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "10001,CVE-2021-1234,9.8,Critical,192.168.1.5,tcp,443,Log4Shell,Remote code execution\n"
        "10002,,7.5,High,192.168.1.5,tcp,22,SSH Weak Cipher,Weak cipher detected\n"
        "10003,,5.3,Medium,192.168.1.6,tcp,80,Missing Header,CSP header absent\n"
        "10004,,3.1,Low,192.168.1.7,tcp,0,Self-signed Cert,Self-signed cert in use\n"
    )
    p = tmp_path / "nessus_export.csv"
    p.write_text(csv, encoding="utf-8")
    findings = parse_nessus_csv(p)
    assert len(findings) == 4
    assert findings[0].severity == Severity.CRITICAL
    assert findings[1].severity == Severity.HIGH
    assert findings[2].severity == Severity.MEDIUM
    assert findings[3].severity == Severity.LOW


def test_csv_cve_extracted(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "10001,CVE-2023-1234,9.8,Critical,10.0.0.1,tcp,80,Apache RCE,RCE via path traversal\n"
    )
    p = tmp_path / "scan.csv"
    p.write_text(csv, encoding="utf-8")
    findings = parse_nessus_csv(p)
    assert findings[0].cve_id == "CVE-2023-1234"
    assert findings[0].cvss_v3 == 9.8


def test_csv_first_cve_taken_when_multiple(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "10001,\"CVE-2021-44228,CVE-2021-45046\",9.8,Critical,10.0.0.1,tcp,80,Log4Shell,RCE\n"
    )
    p = tmp_path / "scan.csv"
    p.write_text(csv, encoding="utf-8")
    findings = parse_nessus_csv(p)
    assert findings[0].cve_id == "CVE-2021-44228"


def test_csv_asset_includes_port(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "10001,,7.5,High,10.10.10.10,tcp,8443,TLS Issue,Weak TLS config\n"
    )
    p = tmp_path / "scan.csv"
    p.write_text(csv, encoding="utf-8")
    findings = parse_nessus_csv(p)
    assert "10.10.10.10" in findings[0].asset
    assert "8443" in findings[0].asset


def test_csv_domain_mapping(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "1,,7.5,High,h,tcp,443,Web Application XSS,XSS detected\n"
        "2,,7.5,High,h,tcp,445,SMBv1 Enabled,Lateral movement risk\n"
        "3,,7.5,High,h,tcp,0,Windows Patch Missing,Unpatched kernel\n"
    )
    p = tmp_path / "scan.csv"
    p.write_text(csv, encoding="utf-8")
    findings = parse_nessus_csv(p)
    assert findings[0].domain == Domain.APPSEC
    assert findings[1].domain == Domain.NETWORK
    assert findings[2].domain == Domain.ENDPOINT


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

_NESSUS_XML = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="External Scan">
    <ReportHost name="172.16.0.10">
      <HostProperties>
        <tag name="host-ip">172.16.0.10</tag>
      </HostProperties>
      <ReportItem port="443" protocol="tcp" severity="4" pluginID="1" pluginName="SSL Critical Vuln">
        <risk_factor>Critical</risk_factor>
        <synopsis>Critical SSL vulnerability.</synopsis>
        <cve>CVE-2022-0778</cve>
        <cvss3_base_score>9.1</cvss3_base_score>
      </ReportItem>
      <ReportItem port="22" protocol="tcp" severity="2" pluginID="2" pluginName="SSH Weak Algorithm">
        <risk_factor>Medium</risk_factor>
        <synopsis>Weak SSH key exchange algorithm.</synopsis>
      </ReportItem>
      <ReportItem port="0" protocol="tcp" severity="0" pluginID="3" pluginName="Ping">
        <risk_factor>None</risk_factor>
      </ReportItem>
    </ReportHost>
    <ReportHost name="172.16.0.11">
      <ReportItem port="3389" protocol="tcp" severity="3" pluginID="4" pluginName="RDP Exposed">
        <risk_factor>High</risk_factor>
        <synopsis>RDP exposed to internet.</synopsis>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""


def test_xml_skips_informational(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus_xml(p)
    titles = [f.title for f in findings]
    assert "Ping" not in titles


def test_xml_finding_count(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus_xml(p)
    assert len(findings) == 3  # Critical + Medium + High; Ping (Info) skipped


def test_xml_severity_mapping(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus_xml(p)
    sev_map = {f.title: f.severity for f in findings}
    assert sev_map["SSL Critical Vuln"] == Severity.CRITICAL
    assert sev_map["SSH Weak Algorithm"] == Severity.MEDIUM
    assert sev_map["RDP Exposed"] == Severity.HIGH


def test_xml_cve_and_cvss(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus_xml(p)
    ssl_f = next(f for f in findings if f.title == "SSL Critical Vuln")
    assert ssl_f.cve_id == "CVE-2022-0778"
    assert ssl_f.cvss_v3 == 9.1


def test_xml_asset_includes_host_and_port(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus_xml(p)
    ssl_f = next(f for f in findings if f.title == "SSL Critical Vuln")
    assert "172.16.0.10" in ssl_f.asset
    assert "443" in ssl_f.asset


def test_xml_source_is_nessus(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus_xml(p)
    assert all(f.source == "nessus" for f in findings)


# ---------------------------------------------------------------------------
# Dispatcher - parse_nessus routes by extension
# ---------------------------------------------------------------------------

def test_dispatcher_routes_nessus_extension(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus(p)
    assert len(findings) == 3


def test_dispatcher_routes_xml_extension(tmp_path):
    p = tmp_path / "scan_results.xml"
    p.write_text(_NESSUS_XML, encoding="utf-8")
    findings = parse_nessus(p)
    assert len(findings) == 3


def test_dispatcher_routes_csv_extension(tmp_path):
    csv = (
        "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        "10001,,9.8,Critical,10.0.0.1,tcp,443,RCE Vuln,Critical RCE\n"
    )
    p = tmp_path / "export.csv"
    p.write_text(csv, encoding="utf-8")
    findings = parse_nessus(p)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
