#!/usr/bin/env python3
"""
VaultScan Demo Bootstrap

Creates a deliberately vulnerable AWS-like environment for testing VaultScan.

Usage:
    python scripts/bootstrap_demo.py                 # uses LocalStack (default)
    python scripts/bootstrap_demo.py --backend moto  # pure Python, no Docker needed
    python scripts/bootstrap_demo.py --backend localstack --endpoint http://localhost:4566

After running, execute: python scanner.py
"""

import argparse
import sys
from datetime import datetime

try:
    import boto3
except ImportError:
    print("boto3 required. pip install boto3")
    sys.exit(1)


def get_clients(backend="localstack", endpoint=None, region="us-east-1"):
    if backend == "moto":
        # Caller must have already entered moto context
        from moto import mock_aws
        # This function assumes the mock is active in the calling scope
        pass

    config = {
        "region_name": region,
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test",
    }

    if backend == "localstack":
        if not endpoint:
            endpoint = "http://localhost:4566"
        config["endpoint_url"] = endpoint

    s3 = boto3.client("s3", **config)
    iam = boto3.client("iam", **config)
    return s3, iam


def create_vulnerable_s3(s3):
    print("\n[BOOTSTRAP] Creating S3 buckets with misconfigurations...")

    buckets = [
        ("vaultscan-public-leak", {"public": True, "versioning": False}),
        ("vaultscan-private-safe", {"public": False, "versioning": True}),
        ("vaultscan-no-versioning", {"public": False, "versioning": False}),
        ("vaultscan-no-encryption", {"public": False, "versioning": True, "encrypt": False}),
    ]

    for name, cfg in buckets:
        try:
            s3.create_bucket(Bucket=name)
            print(f"  + Created bucket: {name}")
        except Exception as e:
            if "BucketAlreadyOwnedByYou" not in str(e) and "BucketAlreadyExists" not in str(e):
                print(f"  ! {name}: {e}")

        # Public ACL
        if cfg.get("public"):
            try:
                s3.put_bucket_acl(Bucket=name, ACL="public-read")
                print(f"    → Public-read ACL set (CRITICAL)")
            except Exception:
                pass

        # Versioning
        status = "Enabled" if cfg.get("versioning") else "Suspended"
        try:
            s3.put_bucket_versioning(
                Bucket=name,
                VersioningConfiguration={"Status": status}
            )
            if not cfg.get("versioning"):
                print(f"    → Versioning disabled (MEDIUM)")
        except Exception:
            pass

        # Public Access Block — leave disabled or partial on the leaky one
        if cfg.get("public"):
            try:
                s3.put_public_access_block(
                    Bucket=name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                )
            except Exception:
                pass


def create_vulnerable_iam(iam):
    print("\n[BOOTSTRAP] Creating IAM users with misconfigurations...")

    users = [
        ("over-privileged-dev", True, False),   # has admin, no MFA
        ("no-mfa-user", False, False),          # no admin, no MFA
        ("safe-user", False, True),             # will have MFA simulated (still flags in basic scanner)
    ]

    for uname, is_admin, has_mfa in users:
        try:
            iam.create_user(UserName=uname)
            print(f"  + Created user: {uname}")
        except Exception as e:
            if "EntityAlreadyExists" not in str(e):
                print(f"  ! {uname}: {e}")

        if is_admin:
            try:
                iam.attach_user_policy(
                    UserName=uname,
                    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
                )
                print(f"    → Attached AdministratorAccess (HIGH)")
            except Exception:
                pass

        # Note: In real + LocalStack/Moto, listing MFA devices will be empty for all.
        # The scanner currently treats "no devices" as a finding.
        # For true MFA simulation you would call iam.enable_mfa_device but it is complex.


def bootstrap_localstack(endpoint="http://localhost:4566"):
    print("=== VaultScan Demo Bootstrap (LocalStack) ===")
    s3, iam = get_clients(backend="localstack", endpoint=endpoint)
    create_vulnerable_s3(s3)
    create_vulnerable_iam(iam)
    print("\n✅ Bootstrap complete. Now run: python scanner.py")


def bootstrap_moto():
    print("=== VaultScan Demo Bootstrap (Moto — in-memory) ===")
    from moto import mock_aws

    @mock_aws
    def _inner():
        # Inside the mock context we create real boto3 clients that are faked
        s3 = boto3.client("s3", region_name="us-east-1",
                          aws_access_key_id="test", aws_secret_access_key="test")
        iam = boto3.client("iam", region_name="us-east-1",
                           aws_access_key_id="test", aws_secret_access_key="test")

        # We can't easily inject these clients into the global scanner without changes.
        # Instead we demonstrate the pattern + print a message.
        print("  Moto mock active.")
        create_vulnerable_s3(s3)
        create_vulnerable_iam(iam)
        print("\n✅ In-memory vulnerable environment created.")
        print("   To scan it, you need to integrate the moto context into scanner.py")
        print("   (see docs/CLOUD_SECURITY_CHECKS.md for guidance).")
        print("   Example next step: run a small test script that imports scanner logic.")

    _inner()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["localstack", "moto"], default="localstack")
    parser.add_argument("--endpoint", default="http://localhost:4566")
    args = parser.parse_args()

    if args.backend == "moto":
        bootstrap_moto()
    else:
        bootstrap_localstack(args.endpoint)


if __name__ == "__main__":
    main()
