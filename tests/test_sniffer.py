"""Comprehensive tests for the content-based sniffer.

Validates sniff() across every category, multiple tool format variations per
category, arbitrary filenames (the whole point of content-based detection),
the unknown path, evidence images, edge cases, and diagnostic output.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ingest.sniffer import sniff, format_unknown_diagnostic, SniffResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json(tmp_path: Path, name: str, payload) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _xml(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _csv(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# AWS CSPM
# ---------------------------------------------------------------------------

class TestCspmAws:
    def test_prowler_v3(self, tmp_path):
        p = _json(tmp_path, "cloud_audit.json", [
            {"CheckID": "iam_user_no_mfa", "ServiceName": "iam",
             "Status": "FAIL", "Severity": "high",
             "ResourceArn": "arn:aws:iam::123:user/alice", "Region": "us-east-1"},
        ])
        assert sniff(p).category == "cspm_aws"

    def test_securityhub_asff(self, tmp_path):
        p = _json(tmp_path, "export_april.json", {
            "Findings": [{
                "Title": "S3 bucket publicly accessible",
                "Severity": {"Label": "HIGH"},
                "Resources": [{"Id": "arn:aws:s3:::my-bucket", "Region": "us-east-1"}],
                "RecordState": "ACTIVE",
            }]
        })
        assert sniff(p).category == "cspm_aws"

    def test_scoutsuite_aws(self, tmp_path):
        p = _json(tmp_path, "assessment_results.json", {
            "account_id": "123456789012",
            "services": {
                "iam": {"findings": {"rule-mfa": {"description": "MFA disabled", "level": "danger",
                                                   "items": ["iam.users.alice"]}}},
                "s3": {"findings": {}},
            }
        })
        assert sniff(p).category == "cspm_aws"

    def test_arbitrary_filename(self, tmp_path):
        """Prowler content in a completely generic filename - the key test."""
        p = _json(tmp_path, "monday_export_final_v3.json", [
            {"CheckID": "ec2_sg_open", "ServiceName": "ec2",
             "Status": "FAIL", "Severity": "critical",
             "ResourceArn": "arn:aws:ec2:us-east-1:123:security-group/sg-1"},
        ])
        assert sniff(p).category == "cspm_aws"


# ---------------------------------------------------------------------------
# Azure CSPM
# ---------------------------------------------------------------------------

class TestCspmAzure:
    def test_azure_defender(self, tmp_path):
        p = _json(tmp_path, "cloud_assessment_q2.json", [{
            "id": "/subscriptions/abc/assessments/x",
            "name": "x",
            "properties": {
                "displayName": "Storage should disable public network access",
                "status": {"code": "Unhealthy"},
                "severity": "High",
                "resourceDetails": {"id": "/subscriptions/abc/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/s"},
            },
        }])
        assert sniff(p).category == "cspm_azure"

    def test_scoutsuite_azure(self, tmp_path):
        p = _json(tmp_path, "security_review.json", {
            "services": {
                "storageaccounts": {
                    "findings": {
                        "rule-pub-blob": {
                            "description": "Publicly accessible blob container",
                            "level": "danger",
                            "items": ["storageaccounts.subscriptions.sub1.accounts.acc1.public"],
                        }
                    }
                }
            }
        })
        assert sniff(p).category == "cspm_azure"

    def test_subscription_uri_in_values(self, tmp_path):
        p = _json(tmp_path, "azure_export.json", [{
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
            "displayName": "VM has no endpoint protection",
            "status": {"code": "Unhealthy"},
            "severity": "Medium",
            "resourceDetails": {"id": "/subscriptions/abc/r"},
        }])
        assert sniff(p).category == "cspm_azure"


# ---------------------------------------------------------------------------
# GCP CSPM
# ---------------------------------------------------------------------------

class TestCspmGcp:
    def test_gcp_scc(self, tmp_path):
        p = _json(tmp_path, "pentest_output.json", {
            "findings": [{
                "name": "organizations/123/sources/456/findings/f1",
                "state": "ACTIVE",
                "category": "PUBLIC_BUCKET_ACL",
                "severity": "HIGH",
                "resourceName": "//cloudresourcemanager.googleapis.com/projects/my-project",
            }]
        })
        assert sniff(p).category == "cspm_gcp"

    def test_scoutsuite_gcp(self, tmp_path):
        p = _json(tmp_path, "gcp_scan.json", {
            "services": {
                "iam": {
                    "findings": {
                        "rule-owner": {
                            "description": "User has primitive owner role",
                            "level": "warning",
                            "items": ["iam.bindings.user-alice"],
                        }
                    }
                }
            },
            "last_run": {"ruleset_about": {"forescout_version": "scoutsuite-5"}},
            "metadata": {"project_id": "my-gcp-project"},
        })
        assert sniff(p).category == "cspm_gcp"

    def test_arbitrary_filename(self, tmp_path):
        p = _json(tmp_path, "infrastructure_review_2026.json", {
            "findings": [{
                "name": "organizations/o/sources/s/findings/f2",
                "state": "ACTIVE",
                "category": "SERVICE_ACCOUNT_OWNER_ROLE",
                "severity": "CRITICAL",
                "resourceName": "//iam.googleapis.com/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com",
            }]
        })
        assert sniff(p).category == "cspm_gcp"


# ---------------------------------------------------------------------------
# Vulnerability scanner
# ---------------------------------------------------------------------------

class TestVulnScan:
    def test_nessus_xml(self, tmp_path):
        xml = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Scan">
    <ReportHost name="10.0.0.1">
      <ReportItem port="443" severity="3" pluginID="56984" pluginName="SSL Certificate Cannot Be Trusted">
        <risk_factor>High</risk_factor>
        <synopsis>The SSL certificate cannot be trusted.</synopsis>
        <cve>CVE-2021-1234</cve>
        <cvss3_base_score>7.4</cvss3_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        p = _xml(tmp_path, "network_scan_results.xml", xml)
        assert sniff(p).category == "vuln_scan"

    def test_nessus_csv_headers(self, tmp_path):
        csv = "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis\n"
        csv += "56984,CVE-2021-1234,7.4,High,10.0.0.1,tcp,443,SSL Cert Untrusted,Cert cannot be trusted\n"
        p = _csv(tmp_path, "client_vulnerability_report.csv", csv)
        assert sniff(p).category == "vuln_scan"

    def test_qualys_xml(self, tmp_path):
        xml = """<?xml version="1.0"?>
<ASSET_DATA_REPORT>
  <HOST_LIST>
    <HOST>
      <IP>192.168.1.10</IP>
      <VULN_INFO_LIST>
        <VULN_INFO>
          <QID>38170</QID>
          <SEVERITY>4</SEVERITY>
          <TITLE>OpenSSL Vulnerability</TITLE>
          <CVE_ID_LIST><CVE_ID><ID>CVE-2023-0465</ID></CVE_ID></CVE_ID_LIST>
        </VULN_INFO>
      </VULN_INFO_LIST>
    </HOST>
  </HOST_LIST>
</ASSET_DATA_REPORT>"""
        p = _xml(tmp_path, "assessment_export.xml", xml)
        assert sniff(p).category == "vuln_scan"

    def test_generic_vuln_json(self, tmp_path):
        p = _json(tmp_path, "scanner_output.json", [
            {"hostname": "web.acme.com", "cvss_score": 8.5,
             "severity": "high", "vulnerability_id": "V-001",
             "description": "Unpatched Apache version", "solution": "Upgrade to 2.4.57"},
        ])
        assert sniff(p).category == "vuln_scan"

    def test_metasploit_xml(self, tmp_path):
        """Metasploit XML export - root MetasploitV5."""
        xml = """<?xml version="1.0"?>
<MetasploitV5>
  <generated time="2026-04-01T00:00:00Z" project="acme-pentest"/>
  <hosts>
    <host>
      <address>192.168.1.50</address>
      <name>dc01.acme.local</name>
      <os-name>Windows Server 2019</os-name>
    </host>
  </hosts>
  <vulns>
    <vuln>
      <title>MS17-010 EternalBlue SMB RCE</title>
      <refs>CVE-2017-0144</refs>
      <risk_factor>critical</risk_factor>
    </vuln>
  </vulns>
</MetasploitV5>"""
        p = _xml(tmp_path, "pentest_export_acme.xml", xml)
        assert sniff(p).category == "vuln_scan"

    def test_openvas_greenbone_xml(self, tmp_path):
        """OpenVAS / Greenbone Security Manager XML - root 'report'."""
        xml = """<?xml version="1.0"?>
<report id="a1b2c3" extension="xml" format_id="a994b278" type="scan">
  <results max="5" start="1">
    <result id="r001">
      <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
        <type>vt</type>
        <name>SSL/TLS: Server Certificate Expired</name>
        <cvss_base>7.5</cvss_base>
        <severity>7.5</severity>
        <cve>CVE-2023-4450</cve>
      </nvt>
      <host>10.0.0.5</host>
      <severity>7.5</severity>
      <description>The SSL/TLS certificate has expired.</description>
    </result>
  </results>
</report>"""
        p = _xml(tmp_path, "openvas_scan_march2026.xml", xml)
        assert sniff(p).category == "vuln_scan"

    def test_nexpose_xml(self, tmp_path):
        """Rapid7 Nexpose XML - root NexposeReport."""
        xml = """<?xml version="1.0"?>
<NexposeReport version="2.0">
  <nodes>
    <node address="192.168.1.100" status="alive" hardware-address="00:11:22:33:44:55">
      <tests>
        <test id="ssl-cert-expired" status="vulnerable-exploited" key="443/tcp">
          <Paragraph>The SSL certificate has expired.</Paragraph>
        </test>
      </tests>
      <endpoints>
        <endpoint port="443" protocol="tcp" status="open">
          <services>
            <service name="HTTPS">
              <vulnerabilities>
                <vulnerability id="ssl-cert-expired" severity="5" title="SSL Certificate Expired"/>
              </vulnerabilities>
            </service>
          </services>
        </endpoint>
      </endpoints>
    </node>
  </nodes>
</NexposeReport>"""
        p = _xml(tmp_path, "infrastructure_assessment_2026.xml", xml)
        assert sniff(p).category == "vuln_scan"

    def test_tenable_io_json(self, tmp_path):
        """Tenable.io API export - nested asset/plugin structure."""
        p = _json(tmp_path, "cloud_scan_export.json", {
            "vulnerabilities": [
                {
                    "asset": {"uuid": "abc-123", "ipv4": "10.0.0.1", "hostname": "web01.acme.com"},
                    "plugin": {
                        "id": 19506, "name": "Nessus Scan Information",
                        "cvss3_base_score": 7.5, "risk_factor": "High",
                        "description": "This plugin displays information about the Nessus scan.",
                    },
                    "port": {"port": 443, "protocol": "TCP"},
                    "severity": "high", "severity_id": 3,
                }
            ]
        })
        assert sniff(p).category == "vuln_scan"

    def test_snyk_json(self, tmp_path):
        """Snyk dependency/code scan JSON output - packageName + cvsScore."""
        p = _json(tmp_path, "dependency_check_report.json", {
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-567746",
                    "packageName": "lodash", "version": "4.17.15",
                    "severity": "high", "cvssScore": 7.2,
                    "title": "Prototype Pollution",
                    "description": "Prototype pollution via lodash's defaultsDeep.",
                    "fixedIn": ["4.17.21"],
                    "references": [{"title": "CVE-2020-8203", "url": "https://nvd.nist.gov/..."}],
                }
            ],
            "ok": False,
            "dependencyCount": 45,
        })
        assert sniff(p).category == "vuln_scan"

    def test_trivy_json(self, tmp_path):
        """Trivy container/OS scanning JSON - Results array with Vulnerabilities nested."""
        p = _json(tmp_path, "container_scan.json", {
            "Results": [
                {
                    "Target": "acme-app:latest (ubuntu 22.04)",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.2-0ubuntu1.8",
                            "Severity": "HIGH",
                            "CVSS": {"nvd": {"V3Score": 8.1}},
                            "Description": "OpenSSL buffer overflow...",
                        }
                    ],
                }
            ]
        })
        assert sniff(p).category == "vuln_scan"

    def test_arbitrary_nessus_xml_filename(self, tmp_path):
        xml = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Scan">
    <ReportHost name="172.16.0.5">
      <ReportItem port="22" severity="2" pluginID="10881" pluginName="SSH Protocol Version 1 Enabled">
        <risk_factor>Medium</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        p = _xml(tmp_path, "client_external_assessment_april_2026.xml", xml)
        assert sniff(p).category == "vuln_scan"


# ---------------------------------------------------------------------------
# Web application scanner
# ---------------------------------------------------------------------------

class TestWebAppScan:
    def test_owasp_zap_xml(self, tmp_path):
        xml = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0">
  <site name="https://acme.com" host="acme.com" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>10038</pluginid>
        <alert>Content Security Policy Header Not Set</alert>
        <riskcode>2</riskcode>
        <confidence>3</confidence>
        <riskdesc>Medium (High)</riskdesc>
        <cweid>693</cweid>
        <uri>https://acme.com/</uri>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
        p = _xml(tmp_path, "web_security_report.xml", xml)
        assert sniff(p).category == "web_app_scan"

    def test_burp_suite_xml(self, tmp_path):
        xml = """<?xml version="1.0"?>
<issues burpVersion="2023.11.1.3" exportTime="Mon Jan 01 2024">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>2097408</type>
    <name>SQL injection</name>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <url>https://acme.com/login?id=1</url>
    <issueBackground>SQL injection vulnerability detected.</issueBackground>
  </issue>
</issues>"""
        p = _xml(tmp_path, "burp_scan_acme_2026.xml", xml)
        assert sniff(p).category == "web_app_scan"

    def test_nikto_xml(self, tmp_path):
        """Nikto web scanner XML output - root niktoscan."""
        xml = """<?xml version="1.0"?>
<niktoscan>
  <scandetails targetip="10.0.0.1" targethostname="portal.acme.com"
               targetport="443" targetbanner="nginx/1.18.0" starttime="2026-04-01">
    <item id="600100" osvdbid="0" method="GET">
      <description>HTTP TRACE method is active, suggesting XST could be possible.</description>
      <uri>/</uri>
      <namelink>https://portal.acme.com/</namelink>
    </item>
    <item id="600575" osvdbid="0" method="GET">
      <description>Uncommon header 'x-powered-by' found, with contents: PHP/7.4.3</description>
      <uri>/</uri>
    </item>
  </scandetails>
</niktoscan>"""
        p = _xml(tmp_path, "web_assessment_april26.xml", xml)
        assert sniff(p).category == "web_app_scan"

    def test_acunetix_xml(self, tmp_path):
        """Acunetix WVS XML report - root ScanGroup."""
        xml = """<?xml version="1.0"?>
<ScanGroup>
  <Scan>
    <Name>acme.com</Name>
    <StartURL>https://portal.acme.com</StartURL>
    <StartTime>2026/04/01 09:00:00</StartTime>
    <ReportItems>
      <ReportItem id="1">
        <Name>SQL Injection</Name>
        <Severity>high</Severity>
        <CWE>CWE-89</CWE>
        <CVSS>8.0</CVSS>
        <Description>SQL injection vulnerability found in login form.</Description>
        <Recommendation>Use parameterized queries.</Recommendation>
        <Affects>/login.php?id=1</Affects>
      </ReportItem>
    </ReportItems>
  </Scan>
</ScanGroup>"""
        p = _xml(tmp_path, "pentest_web_findings.xml", xml)
        assert sniff(p).category == "web_app_scan"

    def test_w3af_xml(self, tmp_path):
        """w3af XML output - root w3af-run with vulnerability items."""
        xml = """<?xml version="1.0"?>
<w3af-run start="1700000000" startstr="Mon Jan  1 00:00:00 2026" version="1.7.6">
  <vulnerability id="1" method="GET" name="Cross site scripting vulnerability"
                 plugin="xss" severity="High" url="https://acme.com/search">
    <description>A cross-site scripting vulnerability was found at the search form.</description>
    <http-request>GET /search?q=test HTTP/1.1</http-request>
  </vulnerability>
</w3af-run>"""
        p = _xml(tmp_path, "web_vuln_scan_q1.xml", xml)
        assert sniff(p).category == "web_app_scan"

    def test_generic_web_json(self, tmp_path):
        p = _json(tmp_path, "appscan_export.json", [
            {"url": "https://portal.acme.com/login", "severity": "high",
             "cweid": "CWE-89", "alert": "SQL Injection",
             "solution": "Use parameterised queries", "confidence": "high"},
        ])
        assert sniff(p).category == "web_app_scan"


# ---------------------------------------------------------------------------
# Network scanner
# ---------------------------------------------------------------------------

class TestNetworkScan:
    def test_masscan_json(self, tmp_path):
        """Masscan JSON output: ip + ports list with port/proto/status."""
        p = _json(tmp_path, "port_scan_results.json", [
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "10.0.0.2", "ports": [
                {"port": 443, "proto": "tcp", "status": "open",
                 "service": {"name": "https", "banner": "nginx"}},
            ]},
        ])
        assert sniff(p).category == "network_scan"

    def test_zmap_json(self, tmp_path):
        """Zmap JSON list output: ip + port + classification."""
        p = _json(tmp_path, "internet_scan.json", [
            {"ip": "1.2.3.4", "port": 22, "classification": "rst",
             "success": True, "protocol": "tcp"},
            {"ip": "1.2.3.5", "port": 22, "classification": "syn-ack",
             "success": True, "protocol": "tcp"},
        ])
        assert sniff(p).category == "network_scan"

    def test_nmap_xml(self, tmp_path):
        xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1700000000">
  <host starttime="1700000000" endtime="1700000001">
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        p = _xml(tmp_path, "network_discovery_results.xml", xml)
        assert sniff(p).category == "network_scan"

    def test_nmap_json_output(self, tmp_path):
        p = _json(tmp_path, "nmap_output.json", [
            {"host": "192.168.1.1", "port": 22, "state": "open",
             "service": "ssh", "protocol": "tcp", "product": "OpenSSH"},
            {"host": "192.168.1.2", "port": 3389, "state": "open",
             "service": "rdp", "protocol": "tcp"},
        ])
        assert sniff(p).category == "network_scan"

    def test_masscan_xml(self, tmp_path):
        xml = """<?xml version="1.0"?>
<masscan scanner="masscan" version="1.3.2" start="1700000000">
  <host endtime="1700000001">
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
</masscan>"""
        p = _xml(tmp_path, "external_scan.xml", xml)
        assert sniff(p).category == "network_scan"


# ---------------------------------------------------------------------------
# Attack surface / ASM / OSINT
# ---------------------------------------------------------------------------

class TestAttackSurface:
    def test_shodan_json(self, tmp_path):
        p = _json(tmp_path, "asm_export.json", [
            {"ip_str": "1.2.3.4", "port": 3306, "product": "MySQL",
             "hostnames": ["db.acme.com"], "asn": "AS12345", "isp": "MTN"},
            {"ip_str": "1.2.3.5", "port": 443, "product": "nginx",
             "hostnames": ["www.acme.com"]},
        ])
        assert sniff(p).category == "attack_surface"

    def test_censys_json(self, tmp_path):
        p = _json(tmp_path, "internet_exposure.json", {
            "result": {"hits": [
                {"ip": "10.0.0.1", "autonomous_system": {"asn": 12345},
                 "services": [
                     {"port": 22, "service_name": "SSH", "banner": "SSH-2.0-OpenSSH_7.4"},
                     {"port": 80, "service_name": "HTTP"},
                 ]},
            ]}
        })
        assert sniff(p).category == "attack_surface"

    def test_amass_jsonl(self, tmp_path):
        lines = "\n".join([
            json.dumps({"name": "sub1.acme.com", "addresses": [{"ip": "1.2.3.4"}], "sources": ["cert"]}),
            json.dumps({"name": "sub2.acme.com", "addresses": [{"ip": "1.2.3.5"}], "sources": ["dns"]}),
        ])
        p = tmp_path / "subdomain_discovery.jsonl"
        p.write_text(lines, encoding="utf-8")
        assert sniff(p).category == "attack_surface"

    def test_theharvester_json(self, tmp_path):
        """theHarvester JSON output - flat dict with plural collection keys."""
        p = _json(tmp_path, "osint_recon_acme.json", {
            "asns": ["AS6453 TATA COMMUNICATIONS"],
            "emails": ["admin@acme.com", "hr@acme.com", "it-support@acme.com"],
            "hosts": ["mail.acme.com", "vpn.acme.com", "portal.acme.com"],
            "interesting_urls": [],
            "ips": ["105.24.1.1", "105.24.1.2", "196.207.1.10"],
            "shodan": [],
            "subdomains": ["mail.acme.com", "vpn.acme.com", "portal.acme.com", "www.acme.com"],
            "trello_urls": [],
        })
        assert sniff(p).category == "attack_surface"

    def test_bbot_json(self, tmp_path):
        """BBOT (Black-box OSINT Tool) event list - type + data + tags structure."""
        p = _json(tmp_path, "recon_export.json", [
            {"type": "DNS_NAME", "data": "mail.acme.com",
             "tags": ["subdomain", "passive"], "module": "certspotter",
             "source": "acme.com"},
            {"type": "IP_ADDRESS", "data": "105.24.1.1",
             "tags": ["ipv4", "internal"], "module": "ipneighbor",
             "source": "mail.acme.com"},
            {"type": "OPEN_TCP_PORT", "data": "105.24.1.1:443",
             "tags": ["port-443", "tls"], "module": "nmap",
             "source": "105.24.1.1"},
        ])
        assert sniff(p).category == "attack_surface"



# ---------------------------------------------------------------------------
# Dark web
# ---------------------------------------------------------------------------

class TestDarkweb:
    def test_credential_csv_compound_headers(self, tmp_path):
        """source_breach and password_status are compound key names - must match via substring."""
        csv = "email,source_breach,password_status\nalice@acme.com,LinkedIn2021,plaintext\n"
        p = _csv(tmp_path, "credential_export.csv", csv)
        assert sniff(p).category == "darkweb"

    def test_credential_csv_simple_headers(self, tmp_path):
        csv = "email,password,breach\nuser@co.com,secret123,Adobe2013\n"
        p = _csv(tmp_path, "data_export.csv", csv)
        assert sniff(p).category == "darkweb"

    def test_stealer_log_json(self, tmp_path):
        p = _json(tmp_path, "threat_intel.json", [
            {"victim_email": "user@acme.com", "malware_family": "RedLine",
             "first_seen": "2025-12-01", "credentials_count": 47},
        ])
        assert sniff(p).category == "darkweb"

    def test_breach_mention_json(self, tmp_path):
        p = _json(tmp_path, "osint_report.json", {
            "records": [
                {"mention_text": "Selling RDP access to acme.com data",
                 "source": "exploit_forum", "date": "2026-04-15",
                 "email": "victim@acme.com", "breach": "acme-2026"},
            ]
        })
        assert sniff(p).category == "darkweb"


# ---------------------------------------------------------------------------
# DMARC / email security
# ---------------------------------------------------------------------------

class TestDmarc:
    def test_checkdmarc_json(self, tmp_path):
        p = _json(tmp_path, "email_security_check.json", {
            "domain": "acme.com",
            "dmarc": {"present": True, "policy": "reject", "pct": 100},
            "spf": {"present": True, "policy": "v=spf1 include:_spf.google.com -all"},
            "dkim": {"present": True},
            "mta_sts": {"present": False},
        })
        assert sniff(p).category == "dmarc"

    def test_hardenize_style(self, tmp_path):
        p = _json(tmp_path, "domain_report.json", [
            {"domain": "acme.com", "dmarc_policy": "none", "spf_result": "pass",
             "dkim_result": "fail", "bimi": False},
        ])
        assert sniff(p).category == "dmarc"


# ---------------------------------------------------------------------------
# Evidence images - by extension and by magic bytes
# ---------------------------------------------------------------------------

class TestEvidenceImage:
    @pytest.mark.parametrize("ext", [".png", ".jpg", ".jpeg", ".svg",
                                      ".webp", ".gif", ".bmp", ".ico",
                                      ".heic", ".avif", ".tiff"])
    def test_image_by_extension(self, tmp_path, ext):
        p = tmp_path / f"screenshot{ext}"
        p.write_bytes(b"\x00" * 64)
        assert sniff(p).category == "evidence_image"

    def test_png_magic_bytes_wrong_extension(self, tmp_path):
        """A PNG renamed to .dat is still detected as evidence_image."""
        p = tmp_path / "capture.dat"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert sniff(p).category == "evidence_image"

    def test_jpeg_magic_bytes_wrong_extension(self, tmp_path):
        p = tmp_path / "export.bin"
        p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
        assert sniff(p).category == "evidence_image"

    def test_gif_magic_bytes(self, tmp_path):
        p = tmp_path / "animation.tmp"
        p.write_bytes(b"GIF89a" + b"\x00" * 100)
        assert sniff(p).category == "evidence_image"


# ---------------------------------------------------------------------------
# PDF and skip
# ---------------------------------------------------------------------------

class TestFastPath:
    def test_pdf_by_extension(self, tmp_path):
        p = tmp_path / "vapt_report.pdf"
        p.write_bytes(b"%PDF-1.7\n%content")
        assert sniff(p).category == "vapt_pdf"

    def test_pdf_by_magic_bytes(self, tmp_path):
        p = tmp_path / "report.bin"
        p.write_bytes(b"%PDF-1.4\n" + b"\x00" * 100)
        assert sniff(p).category == "vapt_pdf"

    def test_pptx_skipped(self, tmp_path):
        p = tmp_path / "deck.pptx"
        p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)  # ZIP magic (OOXML)
        assert sniff(p).category == "skip"

    def test_ppt_skipped(self, tmp_path):
        p = tmp_path / "old_slides.ppt"
        p.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
        assert sniff(p).category == "skip"


# ---------------------------------------------------------------------------
# Unknown - unclassifiable files surface a diagnostic, never silently dropped
# ---------------------------------------------------------------------------

class TestUnknown:
    def test_random_json_is_unknown(self, tmp_path):
        p = _json(tmp_path, "mystery.json", [
            {"foo": "bar", "baz": 42, "qux": "quux"},
        ])
        result = sniff(p)
        assert result.category == "unknown"

    def test_unknown_diagnostic_contains_filename(self, tmp_path):
        p = _json(tmp_path, "mystery_export_2026.json", {"alpha": 1, "beta": 2})
        result = sniff(p)
        diag = format_unknown_diagnostic(p, result)
        assert "UNCLASSIFIED" in diag
        assert "mystery_export_2026.json" in diag

    def test_unknown_diagnostic_contains_near_miss_scores(self, tmp_path):
        """Near-miss scores must appear so operator knows how close it got."""
        p = _json(tmp_path, "borderline.json", [
            {"hostname": "acme.com", "severity": "high"},  # partial signals, below threshold
        ])
        result = sniff(p)
        # even if unknown, diagnostic should show scores
        diag = format_unknown_diagnostic(p, result)
        assert "Near-miss" in diag or "Extension" in diag


# ---------------------------------------------------------------------------
# Edge cases - must not crash
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_bytes(b"")
        result = sniff(p)
        assert result.category in ("unknown", "skip", "evidence_image", "vapt_pdf")

    def test_malformed_json(self, tmp_path):
        p = tmp_path / "truncated.json"
        p.write_text('{"findings": [{"title": "oops"', encoding="utf-8")
        result = sniff(p)
        assert isinstance(result, SniffResult)  # must not raise

    def test_binary_named_json(self, tmp_path):
        p = tmp_path / "data.json"
        p.write_bytes(bytes(range(256)))
        result = sniff(p)
        assert isinstance(result, SniffResult)

    def test_single_byte_file(self, tmp_path):
        p = tmp_path / "tiny.json"
        p.write_bytes(b"{")
        result = sniff(p)
        assert isinstance(result, SniffResult)


# ---------------------------------------------------------------------------
# Arbitrary filename - the core value proposition
# ---------------------------------------------------------------------------

class TestArbitraryFilenames:
    """Files with completely generic names must still be classified by content."""

    def test_aws_in_generic_name(self, tmp_path):
        p = _json(tmp_path, "client_deliverable_final_v2.json", [
            {"CheckID": "s3_public_acl", "ServiceName": "s3",
             "Status": "FAIL", "Severity": "critical",
             "ResourceArn": "arn:aws:s3:::leaked-bucket"},
        ])
        assert sniff(p).category == "cspm_aws"

    def test_nessus_xml_in_generic_name(self, tmp_path):
        xml = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Scan">
    <ReportHost name="10.0.0.1">
      <ReportItem port="80" severity="3" pluginID="1" pluginName="Web Server Outdated">
        <risk_factor>High</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        p = _xml(tmp_path, "security_assessment_client_q1_2026.xml", xml)
        assert sniff(p).category == "vuln_scan"

    def test_shodan_in_generic_name(self, tmp_path):
        p = _json(tmp_path, "data.json", [
            {"ip_str": "5.6.7.8", "port": 8080, "product": "Apache Tomcat",
             "hostnames": ["app.company.com"], "asn": "AS9999"},
        ])
        assert sniff(p).category == "attack_surface"

    def test_darkweb_csv_in_generic_name(self, tmp_path):
        csv = "email,source_breach,password_status\nbob@corp.ng,Dropbox2012,hashed\n"
        p = _csv(tmp_path, "results_june2026.csv", csv)
        assert sniff(p).category == "darkweb"

    def test_zap_xml_in_generic_name(self, tmp_path):
        xml = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0">
  <site name="https://portal.corp.com">
    <alerts>
      <alertitem>
        <pluginid>10202</pluginid>
        <alert>Absence of Anti-CSRF Tokens</alert>
        <riskcode>2</riskcode>
        <cweid>352</cweid>
        <uri>https://portal.corp.com/transfer</uri>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""
        p = _xml(tmp_path, "report.xml", xml)
        assert sniff(p).category == "web_app_scan"
