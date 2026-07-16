#!/usr/bin/env bash
# VaultScan Fixing options — run with credentials for the LAB account
# (same account as Role ARN arn:aws:iam::ACCOUNT:role/...)
set -euo pipefail

# --- IAM-TRUST-WILDCARD on demo-test-vulnerable-ec2-role: remove Principal * from trust ---
cat > /tmp/vaultscan-trust-demo-test-vulnerable-ec2-role.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
aws iam update-assume-role-policy --role-name demo-test-vulnerable-ec2-role --policy-document file:///tmp/vaultscan-trust-demo-test-vulnerable-ec2-role.json

# --- IAM-PRIVESC-NO-BOUNDARY on demo-scanner-user: list then detach dangerous managed policy ---
aws iam list-attached-user-policies --user-name demo-scanner-user
aws iam list-attached-role-policies --role-name demo-scanner-user
# aws iam detach-user-policy --user-name demo-scanner-user --policy-arn <PolicyArn>

# --- IAM-ROLE-ADMIN: detach AdministratorAccess from role demo-test-vulnerable-ec2-role ---
aws iam detach-role-policy --role-name demo-test-vulnerable-ec2-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# --- IAM-ROLE-ADMIN: detach AdministratorAccess from role CrossAccountAdminExecutionRole ---
aws iam detach-role-policy --role-name CrossAccountAdminExecutionRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# --- IAM-ADMIN-POLICY: detach AdministratorAccess from user demo-scanner-user ---
aws iam detach-user-policy --user-name demo-scanner-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# if that fails (entity is a role), use:
# aws iam detach-role-policy --role-name demo-scanner-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# --- IAM-NO-MFA: MFA cannot be fully automated ---
# Console: IAM → Users → demo-scanner-user → Security credentials → Assign MFA device
# Or create virtual MFA and enable:
# aws iam create-virtual-mfa-device --virtual-mfa-device-name demo-scanner-user-mfa --outfile /tmp/qr.png --bootstrap-method QRCodePNG
# aws iam enable-mfa-device --user-name demo-scanner-user --serial-number arn:aws:iam::ACCOUNT_ID:mfa/demo-scanner-user-mfa --authentication-code1 <code1> --authentication-code2 <code2>

# --- IAM-CLOUDTRAIL-DESTROY on demo-scanner-user: list then detach dangerous managed policy ---
aws iam list-attached-user-policies --user-name demo-scanner-user
aws iam list-attached-role-policies --role-name demo-scanner-user
# aws iam detach-user-policy --user-name demo-scanner-user --policy-arn <PolicyArn>

# --- IAM-IMAGE-LEAK on demo-scanner-user: list then detach dangerous managed policy ---
aws iam list-attached-user-policies --user-name demo-scanner-user
aws iam list-attached-role-policies --role-name demo-scanner-user
# aws iam detach-user-policy --user-name demo-scanner-user --policy-arn <PolicyArn>
