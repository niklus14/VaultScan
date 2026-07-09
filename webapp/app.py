#!/usr/bin/env python3
"""
VaultScan — Web Dashboard Backend

Flask API that wraps the Cloud-Misconfig-Scanner engine and the existing
scanner.py into a web-friendly interface. Supports simulated scans (Moto)
and real AWS scanning.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

from flask import Flask, render_template, jsonify, request

# ---------------------------------------------------------------------------
# Make sure both the cms package AND the parent Vaultscan directory are on
# the import path so we can import from both the CMS library and our own
# scanner helpers.
# ---------------------------------------------------------------------------
CMS_ROOT = os.path.join(os.path.dirname(__file__), "..", "Cloud-Misconfig-Scanner")
VAULTSCAN_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(CMS_ROOT))
sys.path.insert(0, os.path.abspath(VAULTSCAN_ROOT))

from cms.providers.aws_s3 import AwsS3Scanner
from cms.providers.azure_blob import AzureBlobScanner
from cms.providers.gcp_storage import GcpStorageScanner
from cms.core.models import ScanResult, Finding, Resource

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# In-memory scan history (persists for the lifetime of the server process)
scan_history: list[dict] = []

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def finding_to_dict(f: Finding) -> dict:
    """Serialize a Finding dataclass to a JSON-safe dict."""
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity,
        "description": f.description,
        "remediation": f.remediation,
        "resource_type": _resource_type(f.resource),
        "resource": f.resource.name,
        "provider": f.resource.provider,
        "service": f.resource.service,
        "account": f.resource.account,
        "region": f.resource.region or "global",
        "evidence": f.evidence,
        "compliance": _compliance_for(f.rule_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _resource_type(r: Resource) -> str:
    """Human-readable resource type label."""
    mapping = {
        ("aws", "s3"): "S3 Bucket",
        ("azure", "blob"): "Blob Container",
        ("gcp", "storage"): "GCS Bucket",
    }
    return mapping.get((r.provider, r.service), f"{r.provider}/{r.service}")


def _compliance_for(rule_id: str) -> list[str]:
    """Map rule IDs to compliance frameworks."""
    mapping = {
        "AWS-S3-ACCOUNT-BPA": ["CIS AWS 2.1.5", "NIST 800-53 AC-3"],
        "AWS-S3-BUCKET-BPA": ["CIS AWS 2.1.5", "NIST 800-53 AC-3", "SOC2 CC6.1"],
        "AWS-S3-ENCRYPTION": ["CIS AWS 2.1.1", "GDPR Art.32", "HIPAA §164.312"],
        "AWS-S3-VERSIONING": ["CIS AWS 2.1.3", "SOC2 CC6.1", "NIST 800-53 CP-9"],
        "AWS-S3-PUBLIC-ACL": ["CIS AWS 2.1.5", "GDPR Art.32", "HIPAA §164.312", "NIST 800-53 AC-3"],
        "AWS-S3-PUBLIC-POLICY": ["CIS AWS 2.1.5", "GDPR Art.32", "PCI-DSS 1.2.1"],
        "AWS-S3-NO-LOGGING": ["CIS AWS 2.1.2", "SOC2 CC7.2", "NIST 800-53 AU-2"],
        "AWS-S3-NO-MFA-DELETE": ["CIS AWS 2.1.3", "NIST 800-53 IA-2"],
        "AZURE-BLOB-PUBLIC": ["CIS Azure 3.7", "GDPR Art.32"],
        "AZURE-BLOB-NO-ENCRYPTION": ["CIS Azure 3.2", "GDPR Art.32", "HIPAA §164.312"],
        "GCP-STORAGE-PUBLIC": ["CIS GCP 5.1", "GDPR Art.32"],
        "GCP-STORAGE-NO-ENCRYPTION": ["CIS GCP 5.3", "GDPR Art.32", "HIPAA §164.312"],
    }
    return mapping.get(rule_id, ["CIS Benchmark"])


def _run_moto_demo_scan() -> ScanResult:
    """
    Run a rich simulated scan using Moto.

    Creates deliberately vulnerable AWS resources in-memory and scans them
    with the real scanner logic, so findings have realistic evidence and
    resource names instead of 'simulated-bucket'.
    """
    import boto3 as _boto3
    from moto import mock_aws

    result = ScanResult()

    @mock_aws
    def _inner():
        s3 = _boto3.client("s3", region_name="us-east-1")
        iam = _boto3.client("iam", region_name="us-east-1")

        # ── Create vulnerable S3 buckets ────────────────────────────
        # 1. Public bucket (ACL)
        s3.create_bucket(Bucket="prod-customer-data")
        s3.put_bucket_acl(Bucket="prod-customer-data", ACL="public-read")

        # 2. Unencrypted bucket
        s3.create_bucket(Bucket="staging-logs-2026")

        # 3. Another public bucket
        s3.create_bucket(Bucket="marketing-assets")
        s3.put_bucket_acl(Bucket="marketing-assets", ACL="public-read-write")

        # 4. Bucket with public policy
        s3.create_bucket(Bucket="shared-reports")
        s3.put_bucket_policy(
            Bucket="shared-reports",
            Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::shared-reports/*"
                }]
            })
        )

        # 5. Internal bucket (fewer issues)
        s3.create_bucket(Bucket="internal-backups")

        # ── Create vulnerable IAM users ─────────────────────────────
        iam.create_user(UserName="admin-jenkins")
        iam.put_user_policy(
            UserName="admin-jenkins",
            PolicyName="FullAdmin",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            })
        )

        iam.create_user(UserName="dev-intern")
        iam.create_user(UserName="svc-monitoring")

        # ── Run the CMS AWS S3 scanner against Moto ─────────────────
        scanner = AwsS3Scanner(simulated=False, region="us-east-1")
        scan_result = scanner.scan()

        # ── Also add IAM findings from the demo scanner ──────────────
        for user_name in ["admin-jenkins", "dev-intern", "svc-monitoring"]:
            # Check admin policy
            try:
                for pname in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
                    pol = iam.get_user_policy(UserName=user_name, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for st in stmts:
                        if st.get("Effect") == "Allow" and st.get("Action") == "*" and st.get("Resource") == "*":
                            scan_result.add(Finding(
                                rule_id="IAM-ADMIN-POLICY",
                                title="IAM User Has Overly Permissive Inline Policy",
                                severity="HIGH",
                                description=f"User '{user_name}' has an inline policy granting Action:* on Resource:*. "
                                           "This is effectively full administrator access and violates the Principle of Least Privilege.",
                                remediation=f"aws iam delete-user-policy --user-name {user_name} --policy-name {pname}",
                                resource=Resource(
                                    provider="aws", service="iam",
                                    account="123456789012", region="global",
                                    name=user_name
                                ),
                                evidence={"policy_name": pname, "effect": "Allow", "action": "*", "resource": "*"},
                            ))
            except Exception:
                pass

            # Check MFA
            try:
                mfa = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                if not mfa:
                    scan_result.add(Finding(
                        rule_id="IAM-NO-MFA",
                        title="IAM User Has No MFA Device Configured",
                        severity="HIGH",
                        description=f"User '{user_name}' has no Multi-Factor Authentication (MFA) device. "
                                   "Without MFA, a stolen password is enough for an attacker to fully compromise this account.",
                        remediation=f"Go to IAM → Users → {user_name} → Security credentials → Assign MFA device",
                        resource=Resource(
                            provider="aws", service="iam",
                            account="123456789012", region="global",
                            name=user_name
                        ),
                        evidence={"mfa_devices": 0},
                    ))
            except Exception:
                pass

        for f in scan_result.findings:
            result.add(f)

    _inner()
    return result


def _run_cms_scan(provider: str, mode: str, profile: str = None, region: str = "us-east-1") -> ScanResult:
    """Run a scan using the CMS scanner library."""
    if mode == "simulated":
        if provider == "aws":
            return _run_moto_demo_scan()
        elif provider == "azure":
            scanner = AzureBlobScanner()
            return scanner.scan()
        elif provider == "gcp":
            scanner = GcpStorageScanner()
            return scanner.scan()
        elif provider == "all":
            merged = _run_moto_demo_scan()
            for f in AzureBlobScanner().scan().findings:
                merged.add(f)
            for f in GcpStorageScanner().scan().findings:
                merged.add(f)
            return merged
    else:
        # Real mode
        if provider == "aws":
            scanner = AwsS3Scanner(profile=profile, region=region, simulated=False)
            return scanner.scan()
        elif provider == "azure":
            scanner = AzureBlobScanner()
            return scanner.scan()
        elif provider == "gcp":
            scanner = GcpStorageScanner()
            return scanner.scan()

    return ScanResult()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run a scan and return findings."""
    data = request.get_json(force=True) or {}
    provider = data.get("provider", "aws")
    mode = data.get("mode", "simulated")
    profile = data.get("profile")
    region = data.get("region", "us-east-1")

    try:
        result = _run_cms_scan(provider, mode, profile, region)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    findings_list = [finding_to_dict(f) for f in result.findings]

    # Build summary
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings_list:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    scan_record = {
        "scan_id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider,
        "mode": mode,
        "region": region,
        "total_findings": len(findings_list),
        "summary": summary,
        "findings": findings_list,
    }

    scan_history.insert(0, scan_record)

    return jsonify(scan_record)


@app.route("/api/history")
def api_history():
    """Return scan history (without full findings to keep it light)."""
    light_history = []
    for s in scan_history:
        light_history.append({
            "scan_id": s["scan_id"],
            "timestamp": s["timestamp"],
            "provider": s["provider"],
            "mode": s["mode"],
            "total_findings": s["total_findings"],
            "summary": s["summary"],
        })
    return jsonify({"scans": light_history})


@app.route("/api/scan/<scan_id>")
def api_scan_detail(scan_id):
    """Return full findings for a specific scan."""
    for s in scan_history:
        if s["scan_id"] == scan_id:
            return jsonify(s)
    return jsonify({"error": "Scan not found"}), 404


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  🛡️  VaultScan — Cloud Security Dashboard")
    print("  📡  http://localhost:5000")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
