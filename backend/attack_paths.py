"""
Deterministic attack-path chains from VaultScan findings.

Maps how misconfigurations combine into higher-impact outcomes
(data exposure, account takeover, database breach).
"""
from __future__ import annotations

from typing import Any


def _rule(f: dict[str, Any]) -> str:
    return str(f.get("rule_id") or "").upper()


def _sev(f: dict[str, Any]) -> str:
    return str(f.get("severity") or "LOW").upper()


def _node(f: dict[str, Any], role: str) -> dict[str, Any]:
    return {
        "role": role,
        "rule_id": f.get("rule_id"),
        "severity": f.get("severity"),
        "service": f.get("service"),
        "resource": f.get("resource") or f.get("id"),
        "title": f.get("title") or f.get("description") or "Finding",
        "remediation": f.get("remediation") or "",
    }


def build_attack_paths(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return ranked attack path objects for the UI."""
    if not findings:
        return []

    by_rule: dict[str, list[dict]] = {}
    for f in findings:
        rid = _rule(f)
        if not rid:
            # derive coarse buckets from title/service
            title = str(f.get("title") or "").lower()
            svc = str(f.get("service") or "").upper()
            if "public" in title and svc == "S3":
                rid = "S3-PUBLIC"
            elif "encrypt" in title and svc == "S3":
                rid = "S3-NO-ENCRYPTION"
            elif "mfa" in title:
                rid = "IAM-NO-MFA"
            elif "administrator" in title or "permissive" in title:
                rid = "IAM-ADMIN"
            elif "0.0.0.0" in title or "world" in title or "ssh" in title:
                rid = "SG-OPEN"
            elif svc == "RDS" and "public" in title:
                rid = "RDS-PUBLIC"
            else:
                rid = f"{svc}-OTHER"
        by_rule.setdefault(rid, []).append(f)

    def any_rules(*prefixes: str) -> list[dict]:
        out: list[dict] = []
        for rid, items in by_rule.items():
            if any(rid.startswith(p) or p in rid for p in prefixes):
                out.extend(items)
        return out

    paths: list[dict[str, Any]] = []

    # Path 1: Public S3 (+ optional no encryption) → data exposure
    s3_public = any_rules("S3-PUBLIC-ACL", "S3-PUBLIC-POLICY", "S3-PUBLIC")
    s3_enc = any_rules("S3-NO-ENCRYPTION")
    if s3_public:
        steps = [_node(s3_public[0], "entry")]
        if s3_enc:
            steps.append(_node(s3_enc[0], "amplify"))
        paths.append(
            {
                "id": "path-s3-data-exposure",
                "name": "Public storage → data exposure",
                "outcome": "Sensitive objects readable from the internet",
                "severity": "CRITICAL",
                "likelihood": "High — scanners continuously probe public buckets",
                "impact": "Data breach, regulatory fines, customer trust loss",
                "steps": steps,
                "break_chain": [
                    "Block public ACLs/policies and enable all Public Access Block flags",
                    "Enable default encryption (SSE-S3 or KMS)",
                    "Review bucket policies for Principal *",
                ],
            }
        )

    # Path 2: Open admin port + weak identity → account takeover
    sg_open = any_rules("SG-OPEN-22", "SG-OPEN-3389", "SG-OPEN-ALL", "SG-OPEN")
    iam_weak = any_rules(
        "IAM-ADMIN-POLICY",
        "IAM-INLINE-STAR",
        "IAM-ROLE-ADMIN",
        "IAM-NO-MFA",
        "IAM-ADMIN",
    )
    if sg_open and iam_weak:
        paths.append(
            {
                "id": "path-admin-takeover",
                "name": "Internet admin access + weak IAM → account takeover",
                "outcome": "Attacker gains foothold then escalates to full account control",
                "severity": "CRITICAL",
                "likelihood": "High when SSH/RDP is world-open and identities lack MFA/least privilege",
                "impact": "Full AWS account compromise, lateral movement, ransomware staging",
                "steps": [
                    _node(sg_open[0], "entry"),
                    _node(iam_weak[0], "escalate"),
                ],
                "break_chain": [
                    "Revoke 0.0.0.0/0 on ports 22/3389; use VPN/bastion/SSM",
                    "Detach AdministratorAccess; enforce MFA on all human users",
                    "Prefer short-lived roles over long-lived keys",
                ],
            }
        )
    elif sg_open:
        paths.append(
            {
                "id": "path-open-admin",
                "name": "Internet-exposed admin surface",
                "outcome": "Brute-force / exploit path to compute",
                "severity": "CRITICAL" if _sev(sg_open[0]) == "CRITICAL" else "HIGH",
                "likelihood": "High — port scans hit open SSH/RDP continuously",
                "impact": "Host compromise, credential theft via instance role",
                "steps": [_node(sg_open[0], "entry")],
                "break_chain": [
                    "Restrict security group sources to known CIDRs or remove public admin ports",
                    "Require IMDSv2 on instances",
                ],
            }
        )

    # Path 3: Public RDS (+ open DB port) → database breach
    rds_pub = any_rules("RDS-PUBLIC")
    db_sg = any_rules("SG-OPEN-3306", "SG-OPEN-5432", "SG-OPEN-1433", "SG-OPEN-27017")
    if rds_pub:
        steps = [_node(rds_pub[0], "entry")]
        if db_sg:
            steps.append(_node(db_sg[0], "amplify"))
        rds_enc = any_rules("RDS-NO-ENCRYPTION")
        if rds_enc:
            steps.append(_node(rds_enc[0], "amplify"))
        paths.append(
            {
                "id": "path-rds-breach",
                "name": "Exposed database → data breach",
                "outcome": "Database reachable or recoverable data at risk",
                "severity": "CRITICAL",
                "likelihood": "High if publicly accessible or DB ports open to the world",
                "impact": "Customer data leak, compliance failure (GDPR/HIPAA)",
                "steps": steps,
                "break_chain": [
                    "Set publicly_accessible=false on RDS",
                    "Lock security groups to app subnets only",
                    "Enable storage encryption and automated backups",
                ],
            }
        )

    # Path 4: Identity-only weak posture (if no network path)
    if iam_weak and not any(p["id"] == "path-admin-takeover" for p in paths):
        paths.append(
            {
                "id": "path-identity-weakness",
                "name": "Over-privileged / unprotected identity",
                "outcome": "Stolen credentials become full control",
                "severity": "HIGH",
                "likelihood": "Medium–High — phishing and key leaks are common",
                "impact": "Privilege abuse, resource destruction, data exfil",
                "steps": [_node(iam_weak[0], "entry")],
                "break_chain": [
                    "Remove wildcard admin policies",
                    "Enforce MFA",
                    "Rotate access keys older than 90 days",
                ],
            }
        )

    # Path 5: IMDSv1 + compute exposure
    imds = any_rules("EC2-IMDSV1")
    if imds and sg_open:
        paths.append(
            {
                "id": "path-imds-ssrf",
                "name": "Open network + IMDSv1 → role credential theft",
                "outcome": "SSRF-style metadata access steals instance role keys",
                "severity": "HIGH",
                "likelihood": "Medium when web apps are exposed and IMDSv1 allowed",
                "impact": "Lateral privilege via instance profile",
                "steps": [
                    _node(sg_open[0], "entry"),
                    _node(imds[0], "escalate"),
                ],
                "break_chain": [
                    "Require IMDSv2 (HttpTokens=required)",
                    "Tighten security groups and app input validation",
                ],
            }
        )

    # Path 6: Wildcard role trust + admin → internet assume-role takeover
    trust_star = any_rules("IAM-TRUST-WILDCARD")
    role_admin = any_rules("IAM-ROLE-ADMIN")
    if trust_star:
        steps = [_node(trust_star[0], "entry")]
        if role_admin:
            steps.append(_node(role_admin[0], "impact"))
        paths.append(
            {
                "id": "path-trust-wildcard-takeover",
                "name": "Public role trust → account takeover",
                "outcome": "Anyone who knows the role ARN can assume it and inherit privileges",
                "severity": "CRITICAL",
                "likelihood": "High when trust Principal is * and role is powerful",
                "impact": "Full account control if role has admin rights",
                "steps": steps,
                "break_chain": [
                    "Replace trust Principal * with specific account/user ARNs",
                    "Detach AdministratorAccess; use least-privilege policies",
                ],
            }
        )

    # Path 7: KMS public key policy → crypto abuse / data decrypt
    kms_pub = any_rules("KMS-PUBLIC-POLICY")
    if kms_pub:
        paths.append(
            {
                "id": "path-kms-exposure",
                "name": "Exposed KMS key → data decryption",
                "outcome": "Attackers use your CMK to decrypt intercepted ciphertext",
                "severity": "CRITICAL",
                "likelihood": "Medium–High when key policy Principal is *",
                "impact": "Confidential data disclosure across S3/EBS/RDS/Secrets",
                "steps": [_node(kms_pub[0], "entry")],
                "break_chain": [
                    "Remove Principal * from the key policy",
                    "Grant kms:Decrypt only to specific application roles",
                ],
            }
        )

    # Path 8: Public SQS → message inject / steal
    sqs_pub = any_rules("SQS-PUBLIC-POLICY")
    if sqs_pub:
        paths.append(
            {
                "id": "path-sqs-public",
                "name": "Public SQS → pipeline poison / data theft",
                "outcome": "Unauthenticated send/receive on messaging backbone",
                "severity": "CRITICAL",
                "likelihood": "High once queue URL/ARN is discovered",
                "impact": "Business logic abuse, credential/message exfil",
                "steps": [_node(sqs_pub[0], "entry")],
                "break_chain": [
                    "Remove Principal * from the queue policy",
                    "Allow only producer/consumer role ARNs",
                ],
            }
        )

    # Path 9: Priv-esc without boundary
    privesc = any_rules("IAM-PRIVESC-NO-BOUNDARY")
    if privesc:
        paths.append(
            {
                "id": "path-iam-privesc",
                "name": "IAM create/attach without boundary → self-admin",
                "outcome": "Restricted identity elevates to AdministratorAccess",
                "severity": "CRITICAL",
                "likelihood": "High if the identity is compromised or overly trusted",
                "impact": "Total account takeover via policy attachment",
                "steps": [_node(privesc[0], "escalate")],
                "break_chain": [
                    "Require iam:PermissionsBoundary on CreateUser/AttachUserPolicy",
                    "Remove iam:AttachUserPolicy from non-break-glass roles",
                ],
            }
        )

    # Path 10: Broad secrets policy
    sm = any_rules("SM-PUBLIC-POLICY", "SM-OVERBROAD-POLICY")
    if sm:
        paths.append(
            {
                "id": "path-secrets-exposure",
                "name": "Weak Secrets Manager policy → credential theft",
                "outcome": "Secrets readable or mutable by overly broad principals",
                "severity": "HIGH",
                "likelihood": "Medium when resource policies are root-wide or public",
                "impact": "API keys, DB passwords, and tokens stolen",
                "steps": [_node(sm[0], "entry")],
                "break_chain": [
                    "Scope secret policy to a single application role",
                    "Remove PutSecretValue/DeleteSecret from broad grants",
                ],
            }
        )

    # Sort critical first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    paths.sort(key=lambda p: order.get(p.get("severity", "LOW"), 9))
    return paths
