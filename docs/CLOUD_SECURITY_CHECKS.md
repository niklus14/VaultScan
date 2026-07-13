# VaultScan — Cloud Configuration Checks Reference

This document defines **what** VaultScan should look for when scanning cloud environments. It serves as the "source of truth" for the rule set.

VaultScan is a **Cloud Security Posture Management (CSPM)** tool. The goal is to detect dangerous **misconfigurations** before attackers do.

---

## Core Philosophy

- **Assume breach**: Every overly permissive setting is an invitation.
- **Least privilege** everywhere.
- **Encrypt by default**, log by default, block public by default.
- Map every finding to real compliance frameworks (CIS, NIST, GDPR, HIPAA, SOC 2).

---

## 1. Storage (S3 — Highest Impact)

S3 misconfigurations are the #1 cause of major data breaches.

| Check | Severity | Description | CIS Ref | Remediation Example |
|-------|----------|-------------|---------|---------------------|
| Public ACL / Public-read | **CRITICAL** | Bucket allows `AllUsers` or `AuthenticatedUsers` read/write | 2.1.5, 2.1.8 | `aws s3api put-bucket-acl --acl private` |
| Block Public Access incomplete | **HIGH** | Not all 4 public block settings are `true` | 2.1.5 | `put-public-access-block` with all 4 flags |
| No encryption at rest | **HIGH** | No default bucket encryption (SSE-S3 or KMS) | 2.1.1 | Enable `AES256` or `aws:kms` |
| Versioning disabled | **MEDIUM** | No versioning → data loss on delete/overwrite | 2.1.3 | Enable versioning |
| MFA Delete not enabled | **MEDIUM** | No extra factor to change/delete versions | 2.1.3 | Enable MFA delete (requires versioning) |
| No server access logging | **MEDIUM** | No audit trail of who accessed what | 2.1.6? | Enable bucket logging to another bucket |
| No object lock / retention | **LOW** | No WORM protection for compliance data | — | Enable Object Lock |
| Bucket policy allows `*` principal without condition | **HIGH** | Overly broad policy | — | Tighten principal + add conditions (e.g. `aws:SecureTransport`) |

**Key boto3 calls**:
- `list_buckets`
- `get_bucket_acl`
- `get_bucket_versioning`
- `get_public_access_block`
- `get_bucket_encryption`
- `get_bucket_policy`

---

## 2. Identity & Access Management (IAM)

Over-privileged identities are the easiest path to full account takeover.

| Check | Severity | Description | CIS Ref | Notes |
|-------|----------|-------------|---------|-------|
| AdministratorAccess attached to user/role | **HIGH** | Full admin on a human or long-lived credential | 1.16 | Never attach to users; use roles + break-glass |
| No MFA on IAM users (console users) | **HIGH** | Password-only = single factor compromise | 1.10 | Enforce for all humans |
| Access keys > 90 days old | **MEDIUM** | Long-lived keys increase blast radius | 1.12 | Rotate or move to roles |
| Inline policies too broad (`*` on actions/resources) | **HIGH** | Harder to audit than managed policies | 1.15, 1.17 | Prefer managed + scoped |
| Unused IAM users/roles | **LOW** | Attack surface | — | Clean up |
| Root account uses access keys | **CRITICAL** | Never do this | 1.1 | Delete root keys |
| No password policy (or weak) | **MEDIUM** | — | 1.5–1.9 | Enforce length, complexity, rotation |

**Key calls**:
- `list_users`, `list_roles`
- `list_attached_user_policies` + `list_user_policies`
- `list_mfa_devices`
- `list_access_keys`

---

## 3. Compute & Networking (EC2, Security Groups, etc.)

| Check | Severity | Description | CIS / Best Practice |
|-------|----------|-------------|---------------------|
| Security Group allows 0.0.0.0/0 on SSH (22) or RDP (3389) | **CRITICAL** | Direct internet admin access | CIS 4.1, 4.2 |
| Security Group allows 0.0.0.0/0 on high ports or all traffic | **HIGH** | Broad exposure | — |
| EC2 instance has public IP + sensitive role | **HIGH** | Easy target | — |
| IMDSv1 enabled (not v2 only) | **HIGH** | SSRF credential theft possible | CIS 5.x |
| EBS volumes unencrypted | **HIGH** | Data at rest exposed if snapshot leaked | 2.2.1 |
| No VPC Flow Logs | **MEDIUM** | No network visibility | — |
| Default VPC in use for production | **LOW** | Poor segmentation | — |

**Key calls**:
- `describe_security_groups`
- `describe_instances`
- `describe_volumes`
- `describe_flow_logs`

---

## 4. Databases (RDS, DynamoDB, etc.)

| Check | Severity | Description |
|-------|----------|-------------|
| RDS publicly accessible = true | **CRITICAL** | Database open to internet |
| RDS storage not encrypted | **HIGH** | |
| No automated backups / short retention | **MEDIUM** | |
| No Multi-AZ for prod DBs | **MEDIUM** | Availability |
| Default master username (admin/root) | **MEDIUM** | |
| Security group allows DB port from 0.0.0.0/0 | **CRITICAL** | |

---

## 5. Validation-lab services (Steps 4–10)

| Check | Rule ID | Severity | Description |
|-------|---------|----------|-------------|
| KMS key policy Principal `*` | `KMS-PUBLIC-POLICY` | **CRITICAL** | CMK usable by anonymous/external principals |
| IAM allows CloudTrail stop/delete/update | `IAM-CLOUDTRAIL-DESTROY` | **HIGH** | Audit trail can be blinded |
| Role trust Principal `*` / AWS `*` | `IAM-TRUST-WILDCARD` | **CRITICAL** | Anyone may AssumeRole if they know the ARN |
| SQS queue policy Principal `*` | `SQS-PUBLIC-POLICY` | **CRITICAL** | Public send/receive on messaging |
| IAM allows ModifyImage/SnapshotAttribute | `IAM-IMAGE-LEAK` | **HIGH** | AMIs/snapshots can be made public |
| CreateUser/AttachUserPolicy without Permissions Boundary | `IAM-PRIVESC-NO-BOUNDARY` | **CRITICAL** | Self-admin privilege escalation |
| Secrets Manager public or root-broad policy | `SM-PUBLIC-POLICY` / `SM-OVERBROAD-POLICY` | **CRITICAL** / **HIGH** | Secrets readable or fully controlled too widely |

**Key calls**: `kms:ListKeys` / `GetKeyPolicy`, `sqs:ListQueues` / `GetQueueAttributes`, `secretsmanager:ListSecrets` / `GetResourcePolicy`, `iam:GetRole` (trust), `GetPolicyVersion`.

---

## 6. Other High-Value Services

- **Lambda**: 
  - Function URL or API Gateway public without auth
  - Env vars containing secrets (instead of Secrets Manager)
  - Over-permissive execution role
- **Secrets Manager / SSM Parameter Store**: Secrets marked "not secret" or no rotation
- **CloudTrail**: Not enabled, or not logging to protected bucket, or no log file validation
- **KMS**: Keys with overly broad key policies (`*` principal)
- **SQS / SNS**: Policies allowing cross-account or public publish/subscribe

---

## Recommended Implementation Roadmap (Shaping the Idea)

### Phase 1 — MVP (Current)
- S3 + IAM basic checks (done)
- LocalStack / Moto support
- JSON + colored CLI report

### Phase 2 — Core Breadth (Next)
- Add EC2 / Security Groups
- Add RDS
- Add basic encryption + logging checks across services
- Improve public access block + policy evaluation (use `get_bucket_policy` + parse)
- Rule engine (YAML) so non-devs can add checks

### Phase 3 — Professional
- Multi-cloud (Azure, GCP)
- IaC scanning (Terraform HCL)
- Attack path graph
- Web dashboard + compliance scores
- CI/CD gate (GitHub Action)

---

## How to Use This Document

1. When adding a new check:
   - Pick severity based on exploitability + blast radius.
   - Add exact boto3 code path + error handling.
   - Add remediation command that works with real AWS CLI.
   - Reference CIS / NIST IDs.
   - Add unit test using Moto.

2. For demo:
   - Use the bootstrap script in `scripts/`
   - Or Moto-based simulation (no external deps)

---

## Authoritative References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services) (free PDF)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [AWS Config Managed Rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [AWS Security Hub Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)

---

## LocalStack vs Moto for Simulation

**LocalStack** (what you tried):
- Pros: Very close to real AWS APIs, good for broad service coverage.
- Cons: Docker required, heavier, newer versions often want auth token for full experience. Use community image tag `3.8` or pin a known version + `SERVICES=...`.

**Moto** (recommended for development & demos):
- Pros: Pure Python, zero external services, lightning fast, perfect for tests + presentations, works in CI without Docker.
- Cons: Not 100% parity on every obscure API (but excellent for S3, IAM, EC2, RDS, Lambda).
- Usage: `with mock_aws(): ...` then create resources and run your scanner logic.

**Recommendation**:
- Use **Moto** as the primary "simulation mode" (`vaultscan --simulate` or auto).
- Keep LocalStack support for advanced/integration testing.
- Provide a one-command bootstrap for both.

Example future usage:
```bash
python scripts/bootstrap_demo.py --backend moto   # or localstack
python scanner.py --simulate
```

---

*Last updated: 2026-07-04 — Team VaultScan*
