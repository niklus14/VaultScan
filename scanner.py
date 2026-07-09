#!/usr/bin/env python3
"""
██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║███████║██║   ██║██║     ██║   ███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
              Cloud Misconfiguration Scanner — by Team VaultScan
"""

import argparse
import boto3
import json
import os
import sys
from datetime import datetime, timezone
from botocore.config import Config

# ─── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_ENDPOINT = "http://localhost:4566"
DEFAULT_REGION = "us-east-1"

# Global scan configuration (set at startup)
SCAN_CONFIG = {
    "mode": "localstack",   # localstack | aws | simulate
    "endpoint": None,
    "region": DEFAULT_REGION,
    "profile": None,
}


def get_client(service):
    """
    Smart client factory.
    
    Modes:
    - localstack: Connects to LocalStack (test creds + endpoint)
    - aws:        Connects to real AWS (uses real credentials / profile)
    - simulate:   Inside Moto context (no endpoint, no fake creds)
    """
    cfg = Config(region_name=SCAN_CONFIG["region"])
    mode = SCAN_CONFIG["mode"]

    if mode == "aws":
        # Real AWS — let boto3 resolve credentials normally
        # Supports: env vars, ~/.aws/credentials, IAM roles, etc.
        kwargs = {"region_name": SCAN_CONFIG["region"], "config": cfg}
        if SCAN_CONFIG["profile"]:
            session = boto3.Session(profile_name=SCAN_CONFIG["profile"])
            return session.client(service, **kwargs)
        return boto3.client(service, **kwargs)

    elif mode == "localstack":
        # LocalStack simulation
        kwargs = {
            "endpoint_url": SCAN_CONFIG["endpoint"] or DEFAULT_ENDPOINT,
            "aws_access_key_id": "test",
            "aws_secret_access_key": "test",
            "region_name": SCAN_CONFIG["region"],
            "config": cfg,
        }
        return boto3.client(service, **kwargs)

    else:
        # simulate (Moto) — just use normal boto3 inside the mock context
        return boto3.client(service, region_name=SCAN_CONFIG["region"], config=cfg)


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

# ─── Finding storage ──────────────────────────────────────────────────────────
findings = []

def add_finding(severity, resource_type, resource_name, title, description, remediation, compliance):
    findings.append({
        "severity":      severity,
        "resource_type": resource_type,
        "resource":      resource_name,
        "title":         title,
        "description":   description,
        "remediation":   remediation,
        "compliance":    compliance,
        "timestamp":     utcnow_iso(),
    })

# ─── S3 Checks ────────────────────────────────────────────────────────────────
def check_s3():
    print("\n🔍 Scanning S3 buckets...")
    s3 = get_client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    print(f"   Found {len(buckets)} bucket(s): {[b['Name'] for b in buckets]}")

    for bucket in buckets:
        name = bucket["Name"]

        # CHECK 1 — Public ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    add_finding(
                        severity      = "CRITICAL",
                        resource_type = "S3 Bucket",
                        resource_name = name,
                        title         = "S3 Bucket is Publicly Readable",
                        description   = (
                            f"Bucket '{name}' has a public-read ACL. Anyone on the internet "
                            "can list and download all files without authentication. "
                            "This is how the 2019 Capital One breach exposed 100M+ records."
                        ),
                        remediation   = f"aws s3api put-bucket-acl --bucket {name} --acl private",
                        compliance    = ["CIS AWS 2.1.5", "GDPR Art.32", "HIPAA §164.312"],
                    )
        except Exception:
            pass

        # CHECK 2 — Versioning disabled
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "")
            if status != "Enabled":
                add_finding(
                    severity      = "MEDIUM",
                    resource_type = "S3 Bucket",
                    resource_name = name,
                    title         = "S3 Bucket Versioning Not Enabled",
                    description   = (
                        f"Bucket '{name}' does not have versioning enabled. "
                        "Without versioning, accidentally deleted or overwritten files "
                        "cannot be recovered. This violates data resilience best practices."
                    ),
                    remediation   = f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                    compliance    = ["CIS AWS 2.1.3", "SOC2 CC6.1"],
                )
        except Exception:
            pass

        # CHECK 3 — Public Access Block not configured
        try:
            block = s3.get_public_access_block(Bucket=name)
            cfg = block.get("PublicAccessBlockConfiguration", {})
            if not all([
                cfg.get("BlockPublicAcls"),
                cfg.get("IgnorePublicAcls"),
                cfg.get("BlockPublicPolicy"),
                cfg.get("RestrictPublicBuckets"),
            ]):
                add_finding(
                    severity      = "HIGH",
                    resource_type = "S3 Bucket",
                    resource_name = name,
                    title         = "S3 Public Access Block Not Fully Enabled",
                    description   = (
                        f"Bucket '{name}' does not have all Public Access Block settings enabled. "
                        "This allows future policies or ACLs to make the bucket public."
                    ),
                    remediation   = (
                        f"aws s3api put-public-access-block --bucket {name} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                    compliance    = ["CIS AWS 2.1.5", "NIST 800-53 AC-3"],
                )
        except Exception:
            pass

# ─── IAM Checks ───────────────────────────────────────────────────────────────
def check_iam():
    print("\n🔍 Scanning IAM users...")
    iam = get_client("iam")
    users = iam.list_users().get("Users", [])
    print(f"   Found {len(users)} user(s): {[u['UserName'] for u in users]}")

    for user in users:
        uname = user["UserName"]

        # CHECK 4 — Admin / AdministratorAccess policy attached (or broad inline policy)
        try:
            # Attached managed policies
            policies = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
            for policy in policies:
                if "AdministratorAccess" in policy.get("PolicyName", ""):
                    add_finding(
                        severity      = "HIGH",
                        resource_type = "IAM User",
                        resource_name = uname,
                        title         = "IAM User Has Full Administrator Access",
                        description   = (
                            f"User '{uname}' has the AdministratorAccess policy attached, "
                            "granting unrestricted access to ALL AWS services and resources. "
                            "This violates the Principle of Least Privilege. If this account "
                            "is compromised, the attacker gains full control of the cloud account."
                        ),
                        remediation   = (
                            f"aws iam detach-user-policy --user-name {uname} "
                            "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
                            f"Then assign a scoped, role-specific policy instead."
                        ),
                        compliance    = ["CIS AWS 1.16", "NIST 800-53 AC-6", "SOC2 CC6.3"],
                    )

            # Also check inline policies for *:* (common in demos and bad real configs)
            inline_policies = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
            for pname in inline_policies:
                try:
                    pol = iam.get_user_policy(UserName=uname, PolicyName=pname)
                    doc = pol.get("PolicyDocument", {})
                    # Very naive broad check
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow" and stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                            add_finding(
                                severity      = "HIGH",
                                resource_type = "IAM User",
                                resource_name = uname,
                                title         = "IAM User Has Overly Permissive Inline Policy",
                                description   = (
                                    f"User '{uname}' has an inline policy granting Action:* on Resource:*. "
                                    "This is effectively full administrator access."
                                ),
                                remediation   = f"aws iam delete-user-policy --user-name {uname} --policy-name {pname}",
                                compliance    = ["CIS AWS 1.16", "NIST 800-53 AC-6"],
                            )
                except Exception:
                    pass
        except Exception:
            pass

        # CHECK 5 — MFA not enabled
        try:
            mfa_devices = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa_devices:
                add_finding(
                    severity      = "HIGH",
                    resource_type = "IAM User",
                    resource_name = uname,
                    title         = "IAM User Has No MFA Device Configured",
                    description   = (
                        f"User '{uname}' has no Multi-Factor Authentication (MFA) device. "
                        "Without MFA, a stolen password is enough for an attacker to fully "
                        "compromise this account. AWS recommends MFA for all human users."
                    ),
                    remediation   = (
                        f"1. Go to IAM → Users → {uname} → Security credentials\n"
                        "2. Click 'Assign MFA device' and follow the steps.\n"
                        "Or enforce via SCP: Deny all actions if MFA is not present."
                    ),
                    compliance    = ["CIS AWS 1.10", "NIST 800-53 IA-2", "HIPAA §164.312(d)"],
                )
        except Exception:
            pass

# ─── Print Results ────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "LOW":      "\033[92m",   # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"

def print_results():
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    print("\n")
    print("=" * 72)
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    print(f"{BOLD}  VAULTSCAN RESULTS — {now_str} UTC{RESET}")
    print("=" * 72)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in sorted_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n  📊 Summary: {len(findings)} finding(s) total")
    for sev, count in counts.items():
        if count:
            color = SEVERITY_COLOR[sev]
            bar = "█" * count
            print(f"     {color}{sev:<10}{RESET}  {bar}  ({count})")

    if not findings:
        print(f"\n  {BOLD}✅ No misconfigurations found! Your environment looks secure.{RESET}")
        return

    print(f"\n{'─' * 72}")
    for i, f in enumerate(sorted_findings, 1):
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"\n  [{i}] {color}{BOLD}[{f['severity']}]{RESET}  {BOLD}{f['title']}{RESET}")
        print(f"       Resource : {f['resource_type']} → {f['resource']}")
        print(f"       Details  : {f['description']}")
        print(f"       Fix      : {f['remediation']}")
        print(f"       Compliance: {', '.join(f['compliance'])}")
        print(f"{'─' * 72}")

    # Save JSON report
    report_path = "vaultscan_report.json"
    with open(report_path, "w") as fp:
        json.dump({
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings),
            "summary": counts,
            "findings": sorted_findings,
        }, fp, indent=2)
    print(f"\n  💾 Full report saved → {report_path}")
    print("=" * 72 + "\n")

# ─── Main / CLI ───────────────────────────────────────────────────────────────
def run_scan(mode="localstack", endpoint=None, profile=None, region=DEFAULT_REGION):
    """Run the full scan against the chosen target."""
    SCAN_CONFIG["mode"] = mode
    SCAN_CONFIG["endpoint"] = endpoint
    SCAN_CONFIG["profile"] = profile
    SCAN_CONFIG["region"] = region

    print(__doc__)

    if mode == "simulate":
        print("  🧪 SIMULATION MODE (Moto in-memory empty cloud)")
    elif mode == "localstack":
        print(f"  🐳 LOCALSTACK MODE → {endpoint or DEFAULT_ENDPOINT}")
    elif mode == "aws":
        prof = f" (profile: {profile})" if profile else ""
        print(f"  ☁️  REAL AWS MODE{prof}  region={region}")
        print("     Using your real AWS credentials (from env or ~/.aws/credentials)")

    check_s3()
    check_iam()
    print_results()


def main():
    parser = argparse.ArgumentParser(
        description="VaultScan — Cloud Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fully simulated empty cloud (best for testing)
  python scanner.py --simulate

  # LocalStack (Docker simulation)
  python scanner.py --localstack

  # Real AWS using default credentials
  python scanner.py --aws

  # Real AWS with specific profile + region
  python scanner.py --aws --profile prod-readonly --region eu-west-1
        """
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--simulate", action="store_true",
                       help="Moto in-memory simulation (empty controllable cloud, no Docker)")
    group.add_argument("--localstack", action="store_true",
                       help="LocalStack (default)")
    group.add_argument("--aws", action="store_true",
                       help="Connect to real AWS")

    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                        help="LocalStack endpoint (only for --localstack)")
    parser.add_argument("--profile", help="AWS profile name (for --aws)")
    parser.add_argument("--region", default=DEFAULT_REGION, help="AWS region")

    args = parser.parse_args()

    if args.simulate:
        try:
            from moto import mock_aws
        except ImportError:
            print("ERROR: moto not installed. pip install 'moto[s3,iam]'")
            sys.exit(1)

        @mock_aws
        def _run_in_mock():
            run_scan(mode="simulate", region=args.region)

        _run_in_mock()

    elif args.aws:
        run_scan(mode="aws", profile=args.profile, region=args.region)

    else:
        # default to localstack
        run_scan(mode="localstack", endpoint=args.endpoint, region=args.region)


if __name__ == "__main__":
    main()
