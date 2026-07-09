#!/usr/bin/env python3
"""
VaultScan — Moto Simulation Demo

This demonstrates a working scan using Moto (no Docker / LocalStack required).
It creates vulnerable resources in memory and runs checks against them.

Run:
    python demo_with_moto.py
"""

import boto3
import json
from datetime import datetime
from botocore.config import Config
from moto import mock_aws

# Reuse logic from scanner (simplified for demo)
findings = []

def add_finding(severity, resource_type, resource_name, title, description, remediation, compliance):
    findings.append({
        "severity": severity,
        "resource_type": resource_type,
        "resource": resource_name,
        "title": title,
        "description": description,
        "remediation": remediation,
        "compliance": compliance,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


def check_s3(s3):
    print("🔍 Scanning S3 (Moto)...")
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        # Public ACL check (simplified)
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                if g.get("Grantee", {}).get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    add_finding("CRITICAL", "S3 Bucket", name,
                                "S3 Bucket is Publicly Readable",
                                "Anyone on the internet can access this bucket.",
                                "aws s3api put-bucket-acl ... --acl private",
                                ["CIS AWS 2.1.5"])
        except Exception:
            pass

        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                add_finding("MEDIUM", "S3 Bucket", name,
                            "S3 Bucket Versioning Not Enabled",
                            "No recovery from accidental deletes/overwrites.",
                            "Enable versioning",
                            ["CIS AWS 2.1.3"])
        except Exception:
            pass


def check_iam(iam):
    print("🔍 Scanning IAM (Moto)...")
    for user in iam.list_users().get("Users", []):
        uname = user["UserName"]
        # Admin policy (attached)
        try:
            policies = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
            for p in policies:
                if "AdministratorAccess" in p.get("PolicyName", ""):
                    add_finding("HIGH", "IAM User", uname,
                                "IAM User Has Full Administrator Access",
                                "Violates least privilege.",
                                "Detach AdministratorAccess policy",
                                ["CIS AWS 1.16"])
        except Exception:
            pass

        # Broad inline policy (demo case)
        try:
            for pname in iam.list_user_policies(UserName=uname).get("PolicyNames", []):
                pol = iam.get_user_policy(UserName=uname, PolicyName=pname)
                doc = pol.get("PolicyDocument", {})
                stmts = doc.get("Statement", [])
                if isinstance(stmts, dict): stmts = [stmts]
                for st in stmts:
                    if st.get("Effect") == "Allow" and st.get("Action") == "*" and st.get("Resource") == "*":
                        add_finding("HIGH", "IAM User", uname,
                                    "IAM User Has Overly Permissive Inline Policy",
                                    "Action:* Resource:* is full admin.",
                                    f"Remove policy {pname}",
                                    ["CIS AWS 1.16"])
        except Exception:
            pass

        # No MFA (always true in this simple demo)
        try:
            if not iam.list_mfa_devices(UserName=uname).get("MFADevices"):
                add_finding("HIGH", "IAM User", uname,
                            "IAM User Has No MFA Device Configured",
                            "Stolen password = full compromise.",
                            "Assign MFA device",
                            ["CIS AWS 1.10"])
        except Exception:
            pass


def main():
    print("🚀 VAULTSCAN MOTO DEMO MODE\n")

    @mock_aws
    def run_demo():
        # Setup clients inside Moto
        s3 = boto3.client("s3", region_name="us-east-1",
                          aws_access_key_id="test", aws_secret_access_key="test")
        iam = boto3.client("iam", region_name="us-east-1",
                           aws_access_key_id="test", aws_secret_access_key="test")

        # Create vulnerable resources
        s3.create_bucket(Bucket="demo-public-bucket")
        s3.put_bucket_acl(Bucket="demo-public-bucket", ACL="public-read")

        iam.create_user(UserName="demo-admin-user")
        iam.put_user_policy(
            UserName="demo-admin-user",
            PolicyName="FullAdminDemo",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            })
        )
        iam.create_user(UserName="demo-dev-user")

        # Run checks
        check_s3(s3)
        check_iam(iam)

        # Report
        print("\n=== FINDINGS ===")
        for f in findings:
            print(f"[{f['severity']}] {f['title']} — {f['resource']}")
        print(f"\nTotal findings: {len(findings)}")
        print("✅ Demo complete. This is how VaultScan works against a simulated cloud.")

    run_demo()


if __name__ == "__main__":
    main()
