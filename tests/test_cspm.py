"""Tests for AWS / Azure / GCP CSPM connectors."""
from __future__ import annotations

import json

from cida.ingest.cspm_aws import parse_aws_cspm
from cida.ingest.cspm_azure import parse_azure_cspm
from cida.ingest.cspm_gcp import parse_gcp_cspm
from cida.models import Domain, Severity


# ---------- AWS ----------

def test_parse_prowler_json(tmp_path):
    sample = [
        {
            "CheckID": "iam_user_no_mfa",
            "CheckTitle": "IAM user has MFA disabled",
            "ServiceName": "iam",
            "Status": "FAIL",
            "Severity": "high",
            "ResourceArn": "arn:aws:iam::123456789012:user/alice",
            "Region": "us-east-1",
            "AccountId": "123456789012",
            "Description": "User alice has no MFA configured. Publicly accessible console.",
        },
        {
            "CheckID": "s3_public_acl",
            "CheckTitle": "S3 bucket publicly accessible",
            "ServiceName": "s3",
            "Status": "FAIL",
            "Severity": "critical",
            "ResourceArn": "arn:aws:s3:::public-bucket",
            "Region": "us-east-1",
            "Description": "Bucket has public ACL grant. Internet exposed.",
        },
        {
            "CheckID": "ec2_sg_open",
            "CheckTitle": "Security group open to world",
            "ServiceName": "ec2",
            "Status": "PASS",  # should be skipped
            "Severity": "medium",
            "ResourceId": "sg-123",
        },
    ]
    p = tmp_path / "prowler.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_aws_cspm(p)
    assert len(findings) == 2
    iam_f = next(f for f in findings if "iam" in f.title.lower())
    assert iam_f.domain == Domain.IDENTITY
    assert iam_f.severity == Severity.HIGH
    s3_f = next(f for f in findings if "s3" in f.title.lower())
    assert s3_f.domain == Domain.ASSET_DATA
    assert s3_f.severity == Severity.CRITICAL
    assert s3_f.exposure == "internet"


def test_parse_aws_security_hub_asff(tmp_path):
    sample = {
        "Findings": [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "arn:aws:securityhub:us-east-1:...:finding/abc",
                "Title": "RDS instance is publicly accessible",
                "Description": "An RDS instance is exposed to the internet.",
                "Severity": {"Label": "HIGH"},
                "Resources": [
                    {"Type": "AwsRdsDbInstance", "Id": "arn:aws:rds:us-east-1:...:db:prod", "Region": "us-east-1"}
                ],
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
        ]
    }
    p = tmp_path / "securityhub.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_aws_cspm(p)
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "security_hub"
    assert f.severity == Severity.HIGH
    assert f.exposure == "internet"
    assert f.domain == Domain.ASSET_DATA  # rds → data


# ---------- Azure ----------

def test_parse_azure_defender(tmp_path):
    sample = [
        {
            "id": "/subscriptions/abc/.../assessments/x",
            "name": "x",
            "properties": {
                "displayName": "Storage account should have public network access disabled",
                "status": {"code": "Unhealthy", "cause": "PublicAccessEnabled"},
                "severity": "High",
                "resourceDetails": {"id": "/subscriptions/abc/resourceGroups/r/providers/Microsoft.Storage/storageAccounts/s"},
                "description": "Public storage detected.",
            },
        },
        {
            "id": "/subscriptions/abc/.../assessments/y",
            "name": "y",
            "properties": {
                "displayName": "All good check",
                "status": {"code": "Healthy"},
                "severity": "Low",
                "resourceDetails": {"id": "/subscriptions/abc/r/providers/Microsoft.X/resources/z"},
            },
        },
    ]
    p = tmp_path / "azure_defender.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_azure_cspm(p)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].domain == Domain.ASSET_DATA  # storage
    assert findings[0].exposure == "internet"


def test_parse_scoutsuite_azure(tmp_path):
    sample = {
        "services": {
            "storageaccounts": {
                "findings": {
                    "rule-pub-blob": {
                        "description": "Publicly accessible blob container",
                        "level": "danger",
                        "items": [
                            "storageaccounts.subscriptions.sub1.accounts.acc1.blob_containers.public",
                        ],
                        "rationale": "Public blobs leak data.",
                    }
                }
            }
        }
    }
    p = tmp_path / "scoutsuite_azure.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_azure_cspm(p)
    assert len(findings) == 1
    assert findings[0].source == "scoutsuite_azure"
    assert findings[0].severity == Severity.HIGH  # danger → HIGH
    assert findings[0].exposure == "internet"


# ---------- GCP ----------

def test_parse_gcp_scc(tmp_path):
    sample = {
        "findings": [
            {
                "name": "organizations/o/sources/s/findings/f1",
                "resourceName": "//cloudresourcemanager.googleapis.com/projects/proj-1",
                "state": "ACTIVE",
                "category": "PUBLIC_BUCKET_ACL",
                "severity": "HIGH",
                "findingClass": "MISCONFIGURATION",
                "description": "Bucket is publicly readable by allUsers.",
            },
            {
                "name": "organizations/o/sources/s/findings/f2",
                "resourceName": "//iam.googleapis.com/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com",
                "state": "ACTIVE",
                "category": "SERVICE_ACCOUNT_OWNER_ROLE",
                "severity": "CRITICAL",
                "description": "Service account has overly privileged owner role.",
            },
            {
                "name": "organizations/o/sources/s/findings/f3",
                "state": "INACTIVE",
                "severity": "LOW",
                "category": "OLD",
            },
        ]
    }
    p = tmp_path / "gcp_scc.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_gcp_cspm(p)
    assert len(findings) == 2
    assert any(f.domain == Domain.ASSET_DATA for f in findings)  # bucket
    assert any(f.domain == Domain.IDENTITY for f in findings)    # service account
    pub_f = next(f for f in findings if f.title == "PUBLIC_BUCKET_ACL")
    assert pub_f.exposure == "internet"
    assert pub_f.severity == Severity.HIGH


def test_parse_scoutsuite_gcp(tmp_path):
    sample = {
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
        }
    }
    p = tmp_path / "scoutsuite_gcp.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = parse_gcp_cspm(p)
    assert len(findings) == 1
    assert findings[0].domain == Domain.IDENTITY
    assert findings[0].severity == Severity.MEDIUM
