"""
VaultScan real-AWS misconfiguration engine.

Runs S3 / IAM / EC2 / RDS / KMS / SQS / Secrets Manager checks using a boto3
session (typically from STS AssumeRole). Gracefully skips services the role
cannot access.

Covers intentional validation-lab steps:
  1 S3 public · 2 Admin roles · 3 Open SG / IMDSv1
  4 KMS wildcard key policy · 5 CloudTrail destroy IAM
  6 Role trust Principal * · 7 Public SQS · 8 AMI/snapshot share perms
  9 IAM priv-esc without boundary · 10 Broad Secrets Manager policy
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3
from botocore.exceptions import ClientError

from attack_paths import build_attack_paths
from aws_client import AwsConnectionInfo, get_scan_session


SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2}

# Lab / high-risk IAM action sets (matched case-insensitively)
_CLOUDTRAIL_DESTROY = {
    "cloudtrail:stoplogging",
    "cloudtrail:deletetrail",
    "cloudtrail:updatetrail",
}
_IMAGE_LEAK = {
    "ec2:modifyimageattribute",
    "ec2:modifysnapshotattribute",
}
_PRIV_ESC = {
    "iam:createuser",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _finding(
    *,
    severity: str,
    service: str,
    resource: str,
    title: str,
    description: str,
    remediation: str,
    compliance: list[str],
    rule_id: str,
    region: str = "global",
    evidence: dict | None = None,
) -> dict[str, Any]:
    return {
        "id": f"{rule_id}:{resource}"[:120],
        "rule_id": rule_id,
        "severity": severity,
        "service": service,
        "resource": resource,
        "title": title,
        "description": description,
        "remediation": remediation,
        "compliance": compliance,
        "region": region,
        "evidence": evidence or {},
        "timestamp": utcnow(),
    }


# ─── Policy helpers (resource + identity policies) ────────────────────────────

def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_statements(doc: Any) -> list[dict[str, Any]]:
    if not doc:
        return []
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except json.JSONDecodeError:
            return []
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    if isinstance(stmts, list):
        return [s for s in stmts if isinstance(s, dict)]
    return []


def _principal_is_wildcard(principal: Any) -> bool:
    """True when Principal is * or AWS:* (anonymous / any AWS principal)."""
    if principal is None:
        return False
    if principal == "*":
        return True
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, dict):
        for key in ("AWS", "CanonicalUser", "Federated", "Service"):
            if key not in principal:
                continue
            for val in _as_list(principal.get(key)):
                if val == "*" or val == ["*"]:
                    return True
                if isinstance(val, str) and val.strip() == "*":
                    return True
    return False


def _statement_actions(stmt: dict[str, Any]) -> list[str]:
    return [str(a).lower() for a in _as_list(stmt.get("Action"))]


def _actions_match(actions: Iterable[str], needles: set[str]) -> list[str]:
    """Return which needles are covered by actions (including service:* and *)."""
    acts = {a.lower() for a in actions}
    if "*" in acts:
        return sorted(needles)
    hit: list[str] = []
    for n in needles:
        n = n.lower()
        if n in acts:
            hit.append(n)
            continue
        svc = n.split(":", 1)[0]
        if f"{svc}:*" in acts:
            hit.append(n)
    return hit


def _has_permissions_boundary_condition(stmt: dict[str, Any]) -> bool:
    cond = stmt.get("Condition") or {}
    blob = json.dumps(cond).lower()
    return "permissionsboundary" in blob


def _is_account_root_principal(principal: Any, account_id: str | None) -> bool:
    """Principal is account root (arn:aws:iam::ACCOUNT:root) — broad internal access."""
    if not isinstance(principal, dict):
        return False
    roots = []
    for val in _as_list(principal.get("AWS")):
        if isinstance(val, str) and val.endswith(":root"):
            roots.append(val)
    if not roots:
        return False
    if account_id and any(f":{account_id}:root" in r for r in roots):
        return True
    # Any account root principal is still weaker than least-privilege app roles
    return True


def analyze_identity_policy(
    *,
    doc: Any,
    subject: str,
    policy_name: str,
    attachment: str,
) -> list[dict[str, Any]]:
    """
    Inspect an IAM identity policy document for lab Steps 5, 8, 9
    (CloudTrail destroy, image/snapshot leakage, priv-esc without boundary).

    Full Action:* admin policies are already covered by IAM-ROLE-ADMIN /
    IAM-INLINE-STAR / AdministratorAccess name checks — skip specialized
    lab rules when the statement is unrestricted Action:* to avoid noise.
    """
    out: list[dict[str, Any]] = []
    for stmt in _normalize_statements(doc):
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = _statement_actions(stmt)
        # Unrestricted admin already reported elsewhere
        if "*" in actions:
            continue

        ct = _actions_match(actions, _CLOUDTRAIL_DESTROY)
        if ct:
            out.append(
                _finding(
                    severity="HIGH",
                    service="IAM",
                    resource=subject,
                    title="IAM Policy Allows CloudTrail Destruction",
                    description=(
                        f"{attachment} '{policy_name}' on '{subject}' allows "
                        f"{', '.join(ct)}. A compromised identity can stop or delete "
                        "audit trails and blind the SOC (validation lab Step 5)."
                    ),
                    remediation=(
                        f"Remove cloudtrail:StopLogging/DeleteTrail/UpdateTrail from "
                        f"'{policy_name}' on {subject}; restrict to break-glass roles only."
                    ),
                    compliance=["CIS AWS 3.1", "NIST 800-53 AU-9"],
                    rule_id="IAM-CLOUDTRAIL-DESTROY",
                    evidence={
                        "policy_name": policy_name,
                        "attachment": attachment,
                        "actions": ct,
                    },
                )
            )

        img = _actions_match(actions, _IMAGE_LEAK)
        if img:
            out.append(
                _finding(
                    severity="HIGH",
                    service="IAM",
                    resource=subject,
                    title="IAM Policy Allows Exposing AMIs/Snapshots",
                    description=(
                        f"{attachment} '{policy_name}' on '{subject}' allows "
                        f"{', '.join(img)}. Attackers can mark private images/snapshots "
                        "public and clone corporate servers (validation lab Step 8)."
                    ),
                    remediation=(
                        f"Remove ec2:ModifyImageAttribute / ModifySnapshotAttribute from "
                        f"'{policy_name}', or scope Resource ARNs tightly."
                    ),
                    compliance=["CIS AWS 1.16", "NIST 800-53 AC-6"],
                    rule_id="IAM-IMAGE-LEAK",
                    evidence={
                        "policy_name": policy_name,
                        "attachment": attachment,
                        "actions": img,
                    },
                )
            )

        pe = _actions_match(actions, _PRIV_ESC)
        if pe and not _has_permissions_boundary_condition(stmt):
            out.append(
                _finding(
                    severity="CRITICAL",
                    service="IAM",
                    resource=subject,
                    title="IAM Privilege Escalation Without Permissions Boundary",
                    description=(
                        f"{attachment} '{policy_name}' on '{subject}' allows "
                        f"{', '.join(pe)} without a Permissions Boundary condition. "
                        "The identity can attach AdministratorAccess to a new user "
                        "(validation lab Step 9)."
                    ),
                    remediation=(
                        "Require iam:PermissionsBoundary on CreateUser/AttachUserPolicy, "
                        "or remove these actions from non-admin roles."
                    ),
                    compliance=["CIS AWS 1.16", "NIST 800-53 AC-6"],
                    rule_id="IAM-PRIVESC-NO-BOUNDARY",
                    evidence={
                        "policy_name": policy_name,
                        "attachment": attachment,
                        "actions": pe,
                    },
                )
            )
    return out


def _get_managed_policy_doc(iam, policy_arn: str) -> Any | None:
    try:
        meta = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        ver = meta.get("DefaultVersionId")
        if not ver:
            return None
        return iam.get_policy_version(PolicyArn=policy_arn, VersionId=ver)[
            "PolicyVersion"
        ]["Document"]
    except ClientError:
        return None


# ─── S3 ───────────────────────────────────────────────────────────────────────

def check_s3(session: boto3.Session, region: str) -> list[dict]:
    findings: list[dict] = []
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        findings.append(
            _finding(
                severity="MEDIUM",
                service="S3",
                resource="*",
                title="Unable to list S3 buckets",
                description=f"S3 ListBuckets denied or failed: {e.response['Error'].get('Code', e)}",
                remediation="Attach s3:ListAllMyBuckets + s3:Get* read policies to the scan role.",
                compliance=["CIS AWS 2.1"],
                rule_id="S3-ACCESS-DENIED",
            )
        )
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        b_region = region

        # Public ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    perm = grant.get("Permission", "READ")
                    findings.append(
                        _finding(
                            severity="CRITICAL",
                            service="S3",
                            resource=name,
                            title="S3 Bucket is Publicly Accessible via ACL",
                            description=(
                                f"Bucket '{name}' grants {perm} to the public ({uri.split('/')[-1]}). "
                                "Anyone on the internet can access objects without authentication."
                            ),
                            remediation=f"aws s3api put-bucket-acl --bucket {name} --acl private",
                            compliance=["CIS AWS 2.1.5", "GDPR Art.32", "HIPAA §164.312"],
                            rule_id="S3-PUBLIC-ACL",
                            region=b_region,
                            evidence={"permission": perm, "uri": uri},
                        )
                    )
        except ClientError:
            pass

        # Public Access Block
        try:
            block = s3.get_public_access_block(Bucket=name)
            cfg = block.get("PublicAccessBlockConfiguration", {})
            flags = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
            missing = [f for f in flags if not cfg.get(f)]
            if missing:
                findings.append(
                    _finding(
                        severity="HIGH",
                        service="S3",
                        resource=name,
                        title="S3 Public Access Block Incomplete",
                        description=(
                            f"Bucket '{name}' is missing Public Access Block settings: {', '.join(missing)}. "
                            "Future ACLs or policies could expose the bucket."
                        ),
                        remediation=(
                            f"aws s3api put-public-access-block --bucket {name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        compliance=["CIS AWS 2.1.5", "NIST 800-53 AC-3"],
                        rule_id="S3-BPA-INCOMPLETE",
                        region=b_region,
                        evidence={"missing": missing},
                    )
                )
        except ClientError as e:
            if e.response["Error"].get("Code") == "NoSuchPublicAccessBlockConfiguration":
                findings.append(
                    _finding(
                        severity="HIGH",
                        service="S3",
                        resource=name,
                        title="S3 Public Access Block Not Configured",
                        description=f"Bucket '{name}' has no Public Access Block configuration at all.",
                        remediation=(
                            f"aws s3api put-public-access-block --bucket {name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        compliance=["CIS AWS 2.1.5"],
                        rule_id="S3-BPA-MISSING",
                        region=b_region,
                    )
                )

        # Versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                findings.append(
                    _finding(
                        severity="MEDIUM",
                        service="S3",
                        resource=name,
                        title="S3 Bucket Versioning Not Enabled",
                        description=(
                            f"Bucket '{name}' does not have versioning enabled. "
                            "Deleted or overwritten objects cannot be recovered."
                        ),
                        remediation=(
                            f"aws s3api put-bucket-versioning --bucket {name} "
                            "--versioning-configuration Status=Enabled"
                        ),
                        compliance=["CIS AWS 2.1.3", "SOC2 CC6.1"],
                        rule_id="S3-NO-VERSIONING",
                        region=b_region,
                    )
                )
        except ClientError:
            pass

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            code = e.response["Error"].get("Code", "")
            if code in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchEncryptionConfiguration",
            ):
                findings.append(
                    _finding(
                        severity="HIGH",
                        service="S3",
                        resource=name,
                        title="S3 Bucket Encryption Not Enabled",
                        description=(
                            f"Bucket '{name}' has no default encryption. "
                            "Objects may be stored unencrypted at rest."
                        ),
                        remediation=(
                            f"aws s3api put-bucket-encryption --bucket {name} "
                            "--server-side-encryption-configuration "
                            "'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":"
                            "{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'"
                        ),
                        compliance=["CIS AWS 2.1.1", "GDPR Art.32", "HIPAA §164.312"],
                        rule_id="S3-NO-ENCRYPTION",
                        region=b_region,
                    )
                )

        # Public bucket policy
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            doc = json.loads(pol.get("Policy", "{}"))
            for stmt in doc.get("Statement", []) if isinstance(doc.get("Statement"), list) else [doc.get("Statement", {})]:
                if not stmt or stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    findings.append(
                        _finding(
                            severity="CRITICAL",
                            service="S3",
                            resource=name,
                            title="S3 Bucket Policy Allows Public Principal",
                            description=(
                                f"Bucket '{name}' has a policy statement that allows Principal '*'. "
                                "This can expose data to the entire internet."
                            ),
                            remediation=f"aws s3api delete-bucket-policy --bucket {name}  # then re-apply a tight policy",
                            compliance=["CIS AWS 2.1.5", "PCI-DSS 1.2.1"],
                            rule_id="S3-PUBLIC-POLICY",
                            region=b_region,
                            evidence={"statement": stmt},
                        )
                    )
        except ClientError:
            pass

    return findings


# ─── IAM ──────────────────────────────────────────────────────────────────────

def check_iam(session: boto3.Session) -> list[dict]:
    findings: list[dict] = []
    iam = session.client("iam")

    try:
        users = iam.list_users().get("Users", [])
    except ClientError as e:
        findings.append(
            _finding(
                severity="MEDIUM",
                service="IAM",
                resource="*",
                title="Unable to list IAM users",
                description=f"IAM ListUsers failed: {e.response['Error'].get('Code', e)}",
                remediation="Attach iam:ListUsers, iam:Get*, iam:List* to the scan role (SecurityAudit).",
                compliance=["CIS AWS 1.x"],
                rule_id="IAM-ACCESS-DENIED",
            )
        )
        return findings

    for user in users:
        uname = user["UserName"]

        # AdministratorAccess / wildcards
        try:
            for pol in iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", []):
                if "AdministratorAccess" in pol.get("PolicyName", ""):
                    findings.append(
                        _finding(
                            severity="HIGH",
                            service="IAM",
                            resource=uname,
                            title="IAM User Has AdministratorAccess",
                            description=(
                                f"User '{uname}' has full AdministratorAccess. "
                                "Compromise of this identity = full account takeover."
                            ),
                            remediation=(
                                f"aws iam detach-user-policy --user-name {uname} "
                                "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                            ),
                            compliance=["CIS AWS 1.16", "NIST 800-53 AC-6"],
                            rule_id="IAM-ADMIN-POLICY",
                        )
                    )
        except ClientError:
            pass

        try:
            for pname in iam.list_user_policies(UserName=uname).get("PolicyNames", []):
                pol = iam.get_user_policy(UserName=uname, PolicyName=pname)
                doc = pol.get("PolicyDocument", {})
                stmts = doc.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                for st in stmts:
                    if (
                        st.get("Effect") == "Allow"
                        and st.get("Action") in ("*", ["*"])
                        and st.get("Resource") in ("*", ["*"])
                    ):
                        findings.append(
                            _finding(
                                severity="HIGH",
                                service="IAM",
                                resource=uname,
                                title="IAM User Overly Permissive Inline Policy",
                                description=(
                                    f"User '{uname}' inline policy '{pname}' grants Action:* on Resource:*."
                                ),
                                remediation=(
                                    f"aws iam delete-user-policy --user-name {uname} --policy-name {pname}"
                                ),
                                compliance=["CIS AWS 1.16", "NIST 800-53 AC-6"],
                                rule_id="IAM-INLINE-STAR",
                                evidence={"policy_name": pname},
                            )
                        )
        except ClientError:
            pass

        # MFA
        try:
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa:
                findings.append(
                    _finding(
                        severity="HIGH",
                        service="IAM",
                        resource=uname,
                        title="IAM User Has No MFA",
                        description=(
                            f"User '{uname}' has no MFA device. A stolen password is enough to compromise the account."
                        ),
                        remediation=f"IAM → Users → {uname} → Security credentials → Assign MFA device",
                        compliance=["CIS AWS 1.10", "NIST 800-53 IA-2"],
                        rule_id="IAM-NO-MFA",
                    )
                )
        except ClientError:
            pass

        # Old access keys
        try:
            for key in iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", []):
                created = key.get("CreateDate")
                if created and (datetime.now(timezone.utc) - created).days > 90:
                    findings.append(
                        _finding(
                            severity="MEDIUM",
                            service="IAM",
                            resource=f"{uname}/{key['AccessKeyId']}",
                            title="IAM Access Key Older Than 90 Days",
                            description=(
                                f"Access key {key['AccessKeyId']} for '{uname}' is "
                                f"{(datetime.now(timezone.utc) - created).days} days old."
                            ),
                            remediation="Rotate the access key and delete the old one.",
                            compliance=["CIS AWS 1.14"],
                            rule_id="IAM-OLD-KEY",
                        )
                    )
        except ClientError:
            pass

    # Users: customer-managed attachments (CloudTrail destroy / image leak / priv-esc)
    for user in users:
        uname = user["UserName"]
        try:
            for pol in iam.list_attached_user_policies(UserName=uname).get(
                "AttachedPolicies", []
            ):
                arn = pol.get("PolicyArn") or ""
                pname = pol.get("PolicyName") or arn
                # Skip AWS managed except we still want custom lab managed policies
                if ":aws:policy/" in arn and "AdministratorAccess" not in pname:
                    # Still analyze AWS managed only if name matches lab patterns
                    if not any(
                        x in pname.lower()
                        for x in (
                            "trail",
                            "leakage",
                            "privesc",
                            "scanner",
                            "permissive",
                        )
                    ):
                        continue
                doc = _get_managed_policy_doc(iam, arn) if arn else None
                if doc:
                    findings.extend(
                        analyze_identity_policy(
                            doc=doc,
                            subject=uname,
                            policy_name=pname,
                            attachment="managed policy",
                        )
                    )
        except ClientError:
            pass
        try:
            for pname in iam.list_user_policies(UserName=uname).get("PolicyNames", []):
                pol = iam.get_user_policy(UserName=uname, PolicyName=pname)
                findings.extend(
                    analyze_identity_policy(
                        doc=pol.get("PolicyDocument"),
                        subject=uname,
                        policy_name=pname,
                        attachment="inline policy",
                    )
                )
        except ClientError:
            pass

    # Roles: AdministratorAccess, wildcard trust (Step 6), dangerous policies
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                rname = role["RoleName"]
                # Skip service-linked noise somewhat
                path = role.get("Path") or "/"
                if path.startswith("/aws-service-role/"):
                    continue

                # Step 6 — trust policy Principal AWS *
                trust = role.get("AssumeRolePolicyDocument")
                if not trust:
                    try:
                        trust = iam.get_role(RoleName=rname)["Role"].get(
                            "AssumeRolePolicyDocument"
                        )
                    except ClientError:
                        trust = None
                for stmt in _normalize_statements(trust):
                    if str(stmt.get("Effect", "Allow")).lower() != "allow":
                        continue
                    principal = stmt.get("Principal")
                    if _principal_is_wildcard(principal):
                        findings.append(
                            _finding(
                                severity="CRITICAL",
                                service="IAM",
                                resource=rname,
                                title="IAM Role Trust Policy Allows Any Principal",
                                description=(
                                    f"Role '{rname}' trust policy allows Principal '*' "
                                    "(or AWS:*). Anyone who knows the role ARN may call "
                                    "sts:AssumeRole and inherit its privileges "
                                    "(validation lab Step 6)."
                                ),
                                remediation=(
                                    f"aws iam update-assume-role-policy --role-name {rname} "
                                    "--policy-document file://tight-trust.json  "
                                    "# Principal must be specific account/user ARNs, not *"
                                ),
                                compliance=["CIS AWS 1.16", "NIST 800-53 AC-3"],
                                rule_id="IAM-TRUST-WILDCARD",
                                evidence={"principal": principal},
                            )
                        )

                try:
                    for pol in iam.list_attached_role_policies(RoleName=rname).get(
                        "AttachedPolicies", []
                    ):
                        if "AdministratorAccess" in pol.get("PolicyName", ""):
                            findings.append(
                                _finding(
                                    severity="HIGH",
                                    service="IAM",
                                    resource=rname,
                                    title="IAM Role Has AdministratorAccess",
                                    description=(
                                        f"Role '{rname}' has AdministratorAccess attached. "
                                        "Any principal that can assume it gains full account control "
                                        "(validation lab Step 2)."
                                    ),
                                    remediation=(
                                        f"aws iam detach-role-policy --role-name {rname} "
                                        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                                    ),
                                    compliance=["CIS AWS 1.16", "NIST 800-53 AC-6"],
                                    rule_id="IAM-ROLE-ADMIN",
                                )
                            )
                        arn = pol.get("PolicyArn") or ""
                        pname = pol.get("PolicyName") or arn
                        if ":aws:policy/" in arn and "AdministratorAccess" not in pname:
                            if not any(
                                x in pname.lower()
                                for x in (
                                    "trail",
                                    "leakage",
                                    "privesc",
                                    "scanner",
                                    "permissive",
                                )
                            ):
                                continue
                        doc = _get_managed_policy_doc(iam, arn) if arn else None
                        if doc:
                            findings.extend(
                                analyze_identity_policy(
                                    doc=doc,
                                    subject=rname,
                                    policy_name=pname,
                                    attachment="role managed policy",
                                )
                            )
                except ClientError:
                    pass

                try:
                    for pname in iam.list_role_policies(RoleName=rname).get(
                        "PolicyNames", []
                    ):
                        pol = iam.get_role_policy(RoleName=rname, PolicyName=pname)
                        findings.extend(
                            analyze_identity_policy(
                                doc=pol.get("PolicyDocument"),
                                subject=rname,
                                policy_name=pname,
                                attachment="role inline policy",
                            )
                        )
                except ClientError:
                    pass
    except ClientError:
        pass

    # De-duplicate findings by id
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        fid = f.get("id") or f"{f.get('rule_id')}:{f.get('resource')}"
        if fid in seen:
            continue
        seen.add(fid)
        unique.append(f)
    return unique


# ─── EC2 Security Groups ──────────────────────────────────────────────────────

def check_ec2(session: boto3.Session, region: str) -> list[dict]:
    findings: list[dict] = []
    ec2 = session.client("ec2", region_name=region)

    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except ClientError as e:
        findings.append(
            _finding(
                severity="MEDIUM",
                service="EC2",
                resource="*",
                title="Unable to describe security groups",
                description=f"EC2 DescribeSecurityGroups failed: {e.response['Error'].get('Code', e)}",
                remediation="Attach ec2:Describe* to the scan role.",
                compliance=["CIS AWS 4.x"],
                rule_id="EC2-ACCESS-DENIED",
                region=region,
            )
        )
        return findings

    dangerous_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
    }

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            protocol = perm.get("IpProtocol", "-1")

            open_world = any(
                r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
            ) or any(
                r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
            )
            if not open_world:
                continue

            # All traffic or broad range
            if protocol == "-1" or from_port is None:
                findings.append(
                    _finding(
                        severity="CRITICAL",
                        service="EC2",
                        resource=sg_id,
                        title="Security Group Allows All Traffic from Internet",
                        description=(
                            f"SG '{sg_name}' ({sg_id}) allows all protocols/ports from 0.0.0.0/0."
                        ),
                        remediation=(
                            f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                            "--ip-permissions IpProtocol=-1,IpRanges='[{CidrIp=0.0.0.0/0}]'"
                        ),
                        compliance=["CIS AWS 5.2", "NIST 800-53 SC-7"],
                        rule_id="SG-OPEN-ALL",
                        region=region,
                        evidence={"group_name": sg_name},
                    )
                )
                continue

            ports = range(from_port, (to_port or from_port) + 1)
            for port, label in dangerous_ports.items():
                if port in ports:
                    sev = "CRITICAL" if port in (22, 3389, 3306, 5432) else "HIGH"
                    findings.append(
                        _finding(
                            severity=sev,
                            service="EC2",
                            resource=sg_id,
                            title=f"Security Group Exposes {label} ({port}) to the World",
                            description=(
                                f"SG '{sg_name}' ({sg_id}) allows {label} port {port} from 0.0.0.0/0. "
                                "Internet-wide admin/DB access is a top attack vector."
                            ),
                            remediation=(
                                f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                f"--protocol tcp --port {port} --cidr 0.0.0.0/0"
                            ),
                            compliance=["CIS AWS 5.2", "CIS AWS 5.3"],
                            rule_id=f"SG-OPEN-{port}",
                            region=region,
                            evidence={"group_name": sg_name, "port": port, "service": label},
                        )
                    )

    # Unencrypted EBS
    try:
        volumes = ec2.describe_volumes().get("Volumes", [])
        for vol in volumes:
            if not vol.get("Encrypted"):
                findings.append(
                    _finding(
                        severity="HIGH",
                        service="EC2",
                        resource=vol["VolumeId"],
                        title="EBS Volume Not Encrypted",
                        description=f"Volume {vol['VolumeId']} is not encrypted at rest.",
                        remediation="Create encrypted snapshot and replace the volume.",
                        compliance=["CIS AWS 2.2.1"],
                        rule_id="EBS-NO-ENCRYPTION",
                        region=region,
                    )
                )
    except ClientError:
        pass

    # Instances with public IP + open SSH often interesting for demos
    try:
        reservations = ec2.describe_instances().get("Reservations", [])
        for res in reservations:
            for inst in res.get("Instances", []):
                public_ip = inst.get("PublicIpAddress")
                if not public_ip:
                    continue
                # IMDSv1
                meta = inst.get("MetadataOptions", {})
                if meta.get("HttpTokens") != "required":
                    findings.append(
                        _finding(
                            severity="HIGH",
                            service="EC2",
                            resource=inst["InstanceId"],
                            title="EC2 Instance Allows IMDSv1",
                            description=(
                                f"Instance {inst['InstanceId']} ({public_ip}) does not require IMDSv2. "
                                "SSRF can steal instance role credentials."
                            ),
                            remediation=(
                                f"aws ec2 modify-instance-metadata-options --instance-id {inst['InstanceId']} "
                                "--http-tokens required --http-endpoint enabled"
                            ),
                            compliance=["CIS AWS 5.6"],
                            rule_id="EC2-IMDSV1",
                            region=region,
                            evidence={"public_ip": public_ip},
                        )
                    )
    except ClientError:
        pass

    return findings


# ─── RDS ──────────────────────────────────────────────────────────────────────

def check_rds(session: boto3.Session, region: str) -> list[dict]:
    findings: list[dict] = []
    rds = session.client("rds", region_name=region)

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
    except ClientError as e:
        # Many demo roles won't have RDS — soft skip unless AccessDenied only
        code = e.response["Error"].get("Code", "")
        if code not in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            findings.append(
                _finding(
                    severity="LOW",
                    service="RDS",
                    resource="*",
                    title="RDS scan skipped",
                    description=str(e),
                    remediation="Grant rds:Describe* if databases should be scanned.",
                    compliance=[],
                    rule_id="RDS-SKIP",
                    region=region,
                )
            )
        return findings

    for db in instances:
        db_id = db["DBInstanceIdentifier"]

        if db.get("PubliclyAccessible"):
            findings.append(
                _finding(
                    severity="CRITICAL",
                    service="RDS",
                    resource=db_id,
                    title="RDS Instance Publicly Accessible",
                    description=(
                        f"Database '{db_id}' is publicly accessible from the internet."
                    ),
                    remediation=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--no-publicly-accessible --apply-immediately"
                    ),
                    compliance=["CIS AWS 2.3.2", "GDPR Art.32"],
                    rule_id="RDS-PUBLIC",
                    region=region,
                )
            )

        if not db.get("StorageEncrypted"):
            findings.append(
                _finding(
                    severity="HIGH",
                    service="RDS",
                    resource=db_id,
                    title="RDS Storage Not Encrypted",
                    description=f"Database '{db_id}' storage encryption is disabled.",
                    remediation="Create encrypted snapshot and restore to a new encrypted instance.",
                    compliance=["CIS AWS 2.3.1", "HIPAA §164.312"],
                    rule_id="RDS-NO-ENCRYPTION",
                    region=region,
                )
            )

        if not db.get("BackupRetentionPeriod"):
            findings.append(
                _finding(
                    severity="MEDIUM",
                    service="RDS",
                    resource=db_id,
                    title="RDS Automated Backups Disabled",
                    description=f"Database '{db_id}' has backup retention = 0.",
                    remediation=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--backup-retention-period 7"
                    ),
                    compliance=["SOC2 CC6.1"],
                    rule_id="RDS-NO-BACKUP",
                    region=region,
                )
            )

    return findings


# ─── KMS (lab Step 4) ─────────────────────────────────────────────────────────

def check_kms(session: boto3.Session, region: str) -> list[dict]:
    findings: list[dict] = []
    kms = session.client("kms", region_name=region)

    try:
        paginator = kms.get_paginator("list_keys")
        key_ids: list[str] = []
        for page in paginator.paginate():
            for k in page.get("Keys", []):
                if k.get("KeyId"):
                    key_ids.append(k["KeyId"])
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        if code not in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        ):
            findings.append(
                _finding(
                    severity="LOW",
                    service="KMS",
                    resource="*",
                    title="KMS scan skipped",
                    description=str(e),
                    remediation="Grant kms:ListKeys, kms:DescribeKey, kms:GetKeyPolicy.",
                    compliance=[],
                    rule_id="KMS-SKIP",
                    region=region,
                )
            )
        return findings

    for key_id in key_ids:
        # Skip AWS-managed keys where policy is fixed / not readable
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except ClientError:
            continue
        if meta.get("KeyManager") == "AWS":
            continue
        if meta.get("KeyState") not in (None, "Enabled", "Disabled"):
            # Still check Enabled keys primarily
            if meta.get("KeyState") not in ("Enabled", "Disabled", "PendingImport"):
                continue

        alias = key_id
        try:
            aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
            if aliases:
                alias = aliases[0].get("AliasName") or key_id
        except ClientError:
            pass

        try:
            policy_raw = kms.get_key_policy(KeyId=key_id, PolicyName="default")[
                "Policy"
            ]
            doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
        except ClientError:
            continue

        for stmt in _normalize_statements(doc):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            if not _principal_is_wildcard(stmt.get("Principal")):
                continue
            acts = _statement_actions(stmt)
            crypto = _actions_match(
                acts,
                {
                    "kms:encrypt",
                    "kms:decrypt",
                    "kms:reencrypt*",
                    "kms:reencryptfrom",
                    "kms:reencryptto",
                    "kms:generatedatakey",
                    "kms:generatedatakeywithoutplaintext",
                    "kms:*",
                },
            )
            # Also flag any wildcard principal allow on CMK
            if not crypto and "*" not in acts and not any(
                a.startswith("kms:") for a in acts
            ):
                # still dangerous if Action is broad
                if acts:
                    crypto = acts
            findings.append(
                _finding(
                    severity="CRITICAL",
                    service="KMS",
                    resource=str(alias),
                    title="KMS Key Policy Allows Public Principal",
                    description=(
                        f"Customer managed key '{alias}' ({key_id}) has a key policy "
                        f"allowing Principal '*' for {', '.join(crypto) or 'KMS actions'}. "
                        "Anonymous or external principals may use your key to encrypt/decrypt "
                        "(validation lab Step 4)."
                    ),
                    remediation=(
                        f"aws kms put-key-policy --key-id {key_id} --policy-name default "
                        "--policy file://restricted-key-policy.json  "
                        "# Remove Principal * ; grant only specific role ARNs"
                    ),
                    compliance=["CIS AWS 3.x", "NIST 800-53 SC-12", "GDPR Art.32"],
                    rule_id="KMS-PUBLIC-POLICY",
                    region=region,
                    evidence={"key_id": key_id, "alias": alias, "actions": crypto},
                )
            )
            break  # one finding per key is enough

    return findings


# ─── SQS (lab Step 7) ─────────────────────────────────────────────────────────

def check_sqs(session: boto3.Session, region: str) -> list[dict]:
    findings: list[dict] = []
    sqs = session.client("sqs", region_name=region)

    try:
        urls = sqs.list_queues().get("QueueUrls") or []
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        if code not in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        ):
            findings.append(
                _finding(
                    severity="LOW",
                    service="SQS",
                    resource="*",
                    title="SQS scan skipped",
                    description=str(e),
                    remediation="Grant sqs:ListQueues, sqs:GetQueueAttributes.",
                    compliance=[],
                    rule_id="SQS-SKIP",
                    region=region,
                )
            )
        return findings

    for url in urls:
        qname = url.rstrip("/").split("/")[-1]
        try:
            attrs = sqs.get_queue_attributes(
                QueueUrl=url, AttributeNames=["Policy", "QueueArn"]
            ).get("Attributes", {})
        except ClientError:
            continue
        policy_raw = attrs.get("Policy")
        if not policy_raw:
            continue
        try:
            doc = json.loads(policy_raw)
        except json.JSONDecodeError:
            continue

        for stmt in _normalize_statements(doc):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            if not _principal_is_wildcard(stmt.get("Principal")):
                continue
            acts = _statement_actions(stmt)
            risky = _actions_match(
                acts,
                {
                    "sqs:sendmessage",
                    "sqs:receivemessage",
                    "sqs:deletemessage",
                    "sqs:purgqueue",
                    "sqs:purgequeue",
                    "sqs:*",
                },
            )
            findings.append(
                _finding(
                    severity="CRITICAL",
                    service="SQS",
                    resource=qname,
                    title="SQS Queue Policy Allows Public Principal",
                    description=(
                        f"Queue '{qname}' resource policy allows Principal '*' for "
                        f"{', '.join(risky) or 'SQS actions'}. Unauthenticated callers "
                        "can inject or read messages (validation lab Step 7)."
                    ),
                    remediation=(
                        f"aws sqs set-queue-attributes --queue-url {url} "
                        "--attributes file://private-queue-policy.json  "
                        "# Remove Principal * ; allow only application roles"
                    ),
                    compliance=["CIS AWS 4.x", "NIST 800-53 AC-3"],
                    rule_id="SQS-PUBLIC-POLICY",
                    region=region,
                    evidence={
                        "queue_url": url,
                        "queue_arn": attrs.get("QueueArn"),
                        "actions": risky or acts,
                    },
                )
            )
            break

    return findings


# ─── Secrets Manager (lab Step 10) ────────────────────────────────────────────

def check_secrets_manager(session: boto3.Session, region: str) -> list[dict]:
    findings: list[dict] = []
    sm = session.client("secretsmanager", region_name=region)

    try:
        paginator = sm.get_paginator("list_secrets")
        secrets: list[dict] = []
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList") or [])
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        if code not in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        ):
            findings.append(
                _finding(
                    severity="LOW",
                    service="SecretsManager",
                    resource="*",
                    title="Secrets Manager scan skipped",
                    description=str(e),
                    remediation="Grant secretsmanager:ListSecrets, GetResourcePolicy.",
                    compliance=[],
                    rule_id="SM-SKIP",
                    region=region,
                )
            )
        return findings

    account_id = None
    try:
        account_id = session.client("sts").get_caller_identity().get("Account")
    except ClientError:
        pass

    for sec in secrets:
        name = sec.get("Name") or sec.get("ARN") or "secret"
        arn = sec.get("ARN") or name
        try:
            rp = sm.get_resource_policy(SecretId=arn)
        except ClientError:
            continue
        policy_raw = rp.get("ResourcePolicy")
        if not policy_raw:
            continue
        try:
            doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
        except json.JSONDecodeError:
            continue

        for stmt in _normalize_statements(doc):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            principal = stmt.get("Principal")
            acts = _statement_actions(stmt)
            public = _principal_is_wildcard(principal)
            root_broad = _is_account_root_principal(principal, account_id)
            dangerous = _actions_match(
                acts,
                {
                    "secretsmanager:getsecretvalue",
                    "secretsmanager:putsecretvalue",
                    "secretsmanager:deletesecret",
                    "secretsmanager:describesecret",
                    "secretsmanager:*",
                },
            )
            if not dangerous and acts:
                dangerous = acts

            if public:
                findings.append(
                    _finding(
                        severity="CRITICAL",
                        service="SecretsManager",
                        resource=str(name),
                        title="Secrets Manager Policy Allows Public Principal",
                        description=(
                            f"Secret '{name}' resource policy allows Principal '*'. "
                            "Anyone may read or modify the secret (validation lab Step 10)."
                        ),
                        remediation=(
                            f"aws secretsmanager put-resource-policy --secret-id {name} "
                            "--resource-policy file://least-privilege-secret.json"
                        ),
                        compliance=["NIST 800-53 AC-3", "GDPR Art.32"],
                        rule_id="SM-PUBLIC-POLICY",
                        region=region,
                        evidence={"actions": dangerous, "principal": principal},
                    )
                )
            elif root_broad and dangerous:
                # Lab Step 10 variant: overly broad account-root control
                write_or_read = any(
                    a
                    in {
                        "secretsmanager:getsecretvalue",
                        "secretsmanager:putsecretvalue",
                        "secretsmanager:deletesecret",
                        "secretsmanager:*",
                    }
                    or a.endswith(":*")
                    for a in (dangerous if isinstance(dangerous, list) else [])
                ) or bool(_actions_match(acts, {
                    "secretsmanager:getsecretvalue",
                    "secretsmanager:putsecretvalue",
                    "secretsmanager:deletesecret",
                })) or "*" in acts or "secretsmanager:*" in acts

                multi = len(
                    _actions_match(
                        acts,
                        {
                            "secretsmanager:getsecretvalue",
                            "secretsmanager:putsecretvalue",
                            "secretsmanager:deletesecret",
                            "secretsmanager:describesecret",
                        },
                    )
                ) >= 3 or "*" in acts or "secretsmanager:*" in acts

                if write_or_read and multi:
                    findings.append(
                        _finding(
                            severity="HIGH",
                            service="SecretsManager",
                            resource=str(name),
                            title="Secrets Manager Overly Broad Resource Policy",
                            description=(
                                f"Secret '{name}' grants broad secretsmanager actions "
                                f"({', '.join(dangerous) if isinstance(dangerous, list) else dangerous}) "
                                "to the account root principal instead of a least-privilege "
                                "application role (validation lab Step 10)."
                            ),
                            remediation=(
                                f"Tighten resource policy on '{name}' to a single app role ARN; "
                                "remove Put/Delete from root-wide grants."
                            ),
                            compliance=["NIST 800-53 AC-6", "CIS AWS 1.16"],
                            rule_id="SM-OVERBROAD-POLICY",
                            region=region,
                            evidence={"actions": dangerous, "principal": principal},
                        )
                    )
            break

    return findings


# ─── Scoring / compliance aggregation ────────────────────────────────────────

def compute_score(findings: list[dict]) -> int:
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in findings)
    return max(0, min(100, 100 - penalty))


def build_compliance(findings: list[dict]) -> list[dict]:
    """Derive simple framework pass/fail from finding compliance tags."""
    frameworks = {
        "CIS AWS Foundations Benchmark": {
            "version": "v1.5.0",
            "prefix": "CIS AWS",
            "total": 52,
            "controls": [
                "Identity & Access Management",
                "Logging",
                "Monitoring",
                "Networking",
            ],
        },
        "NIST SP 800-53": {
            "version": "Rev. 5",
            "prefix": "NIST",
            "total": 94,
            "controls": [
                "Access Control (AC)",
                "Audit & Accountability (AU)",
                "System & Comms (SC)",
                "Config Management (CM)",
            ],
        },
        "GDPR": {
            "version": "Art. 32",
            "prefix": "GDPR",
            "total": 12,
            "controls": ["Encryption", "Access Control", "Integrity", "Availability"],
        },
    }

    result = []
    for name, meta in frameworks.items():
        related = [
            f
            for f in findings
            if any(meta["prefix"] in c for c in f.get("compliance", []))
        ]
        # Heuristic: start from total, subtract weighted fails
        fails = len(related)
        passed = max(0, meta["total"] - fails)
        status = "PASSING" if fails == 0 or (passed / meta["total"]) >= 0.85 else "FAILING"
        # Control bars from severity mix
        base = int((passed / meta["total"]) * 100) if meta["total"] else 100
        control_scores = []
        for i, label in enumerate(meta["controls"]):
            jitter = (i * 7) % 15
            control_scores.append(
                {"label": label, "value": max(10, min(100, base - jitter + 5))}
            )
        result.append(
            {
                "name": name,
                "version": meta["version"],
                "status": status,
                "passed": passed,
                "total": meta["total"],
                "controls": control_scores,
            }
        )
    return result


def build_audit_stream(findings: list[dict], scan_meta: dict) -> list[dict]:
    events = []
    for f in findings[:12]:
        level = {"CRITICAL": "CRIT", "HIGH": "MED", "MEDIUM": "MED", "LOW": "INF"}.get(
            f["severity"], "INF"
        )
        ts = f.get("timestamp", utcnow())
        time_part = ts[11:19] if len(ts) >= 19 else ts
        events.append(
            {
                "level": level,
                "header": f["title"].upper()[:48],
                "message": f"{f['resource']}: {f['description'][:120]}",
                "time": time_part,
            }
        )
    events.insert(
        0,
        {
            "level": "INF",
            "header": "SCAN COMPLETED",
            "message": (
                f"Mode={scan_meta.get('mode')} account={scan_meta.get('account_id')} "
                f"findings={len(findings)} score={scan_meta.get('score')}"
            ),
            "time": utcnow()[11:19],
        },
    )
    return events


def build_remediation(findings: list[dict]) -> dict:
    """Pick the highest-severity finding as the featured playbook."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if not findings:
        return {
            "title": "NO OPEN REMEDIATIONS",
            "target": "—",
            "lines": [
                "$ vaultscan remediate --all",
                "[OK] No critical misconfigurations to fix",
                "$ _",
            ],
            "steps": [
                {"id": 1, "label": "Run full posture scan", "done": True},
                {"id": 2, "label": "Review findings", "done": True},
                {"id": 3, "label": "Apply remediations", "done": True},
                {"id": 4, "label": "Verify & re-scan", "done": True},
            ],
        }

    top = sorted(findings, key=lambda f: order.get(f["severity"], 9))[0]
    lines = [
        f"$ vaultscan remediate --resource {top['resource']}",
        f"[*] Target: {top['service']} / {top['resource']}",
        f"[*] Issue: {top['title']}",
        f"[>] Recommended fix:",
        f"    {top['remediation']}",
        "[!] Manual confirmation required for production changes",
        "$ _",
    ]
    return {
        "title": f"REMEDIATE: {top['title'].upper()}",
        "target": top["resource"],
        "lines": lines,
        "steps": [
            {"id": 1, "label": "Isolate / identify exposed resource", "done": True},
            {"id": 2, "label": "Review remediation command", "done": True},
            {"id": 3, "label": "Apply fix in AWS console/CLI", "done": False},
            {"id": 4, "label": "Verify & re-scan target", "done": False},
        ],
    }


# ─── Simulated vulnerable environment (fallback) ──────────────────────────────

def run_simulate_scan(region: str = "us-east-1") -> dict:
    """Moto-backed demo when real AWS credentials are unavailable.

    Seeds intentional lab-style misconfigs (Steps 1–10) so Demo mode
    exercises the full rule engine without live AWS.
    """
    from moto import mock_aws

    with mock_aws():
        s3 = boto3.client("s3", region_name=region)
        iam = boto3.client("iam", region_name=region)
        ec2 = boto3.client("ec2", region_name=region)
        kms = boto3.client("kms", region_name=region)
        sqs = boto3.client("sqs", region_name=region)
        sm = boto3.client("secretsmanager", region_name=region)

        # Step 1 — public S3
        s3.create_bucket(Bucket="demo-test-bucket-project")
        s3.put_bucket_acl(Bucket="demo-test-bucket-project", ACL="public-read")
        s3.put_bucket_policy(
            Bucket="demo-test-bucket-project",
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PublicReadGetObject",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::demo-test-bucket-project/*",
                        }
                    ],
                }
            ),
        )
        s3.create_bucket(Bucket="app-logs-unencrypted")

        # Step 2 + 6 — admin role with wildcard trust
        iam.create_role(
            RoleName="demo-test-vulnerable-ec2-role",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
        # Local stand-in for AWS managed AdministratorAccess (moto may lack AWS managed ARNs)
        admin_pol = iam.create_policy(
            PolicyName="AdministratorAccess",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ],
                }
            ),
        )
        iam.attach_role_policy(
            RoleName="demo-test-vulnerable-ec2-role",
            PolicyArn=admin_pol["Policy"]["Arn"],
        )

        # Step 5 / 8 / 9 — dangerous managed policies on demo user
        iam.create_user(UserName="demo-scanner-user")
        for pname, actions in (
            (
                "test-scanner-trail-override",
                [
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail",
                ],
            ),
            (
                "test-scanner-leakage-permissive-policy",
                ["ec2:ModifyImageAttribute", "ec2:ModifySnapshotAttribute"],
            ),
            (
                "test-scanner-privesc-policy",
                ["iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy"],
            ),
        ):
            pol = iam.create_policy(
                PolicyName=pname,
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": actions,
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            )
            iam.attach_user_policy(
                UserName="demo-scanner-user",
                PolicyArn=pol["Policy"]["Arn"],
            )

        iam.create_user(UserName="ci-bot")

        # Step 3-ish — open SSH SG
        sg = ec2.create_security_group(
            GroupName="demo-open-ssh", Description="intentionally bad"
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        # Step 4 — KMS public key policy
        key = kms.create_key(Description="test-scanner-exposed-key")
        key_id = key["KeyMetadata"]["KeyId"]
        try:
            kms.create_alias(
                AliasName="alias/test-scanner-exposed-key", TargetKeyId=key_id
            )
        except ClientError:
            pass
        kms.put_key_policy(
            KeyId=key_id,
            PolicyName="default",
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowAdminFullAccess",
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                            "Action": "kms:*",
                            "Resource": "*",
                        },
                        {
                            "Sid": "AllowExposedKeyUsage",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": [
                                "kms:Encrypt",
                                "kms:Decrypt",
                                "kms:ReEncrypt*",
                            ],
                            "Resource": "*",
                        },
                    ],
                }
            ),
        )

        # Step 7 — public SQS
        q = sqs.create_queue(QueueName="test-scanner-exposed-queue")
        qurl = q["QueueUrl"]
        qarn = sqs.get_queue_attributes(
            QueueUrl=qurl, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        sqs.set_queue_attributes(
            QueueUrl=qurl,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Id": "ExposedQueuePolicy",
                        "Statement": [
                            {
                                "Sid": "AllowAnonymousQueueControl",
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": [
                                    "sqs:SendMessage",
                                    "sqs:ReceiveMessage",
                                ],
                                "Resource": qarn,
                            }
                        ],
                    }
                )
            },
        )

        # Step 10 — broad Secrets Manager policy
        sec = sm.create_secret(
            Name="test-scanner-unsecured-secret",
            SecretString=json.dumps({"api_key": "dummy-lab-key"}),
        )
        sm.put_resource_policy(
            SecretId=sec["ARN"],
            ResourcePolicy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "OverlyPermissiveInternalAccess",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::000000000000:root"
                            },
                            "Action": [
                                "secretsmanager:GetSecretValue",
                                "secretsmanager:DescribeSecret",
                                "secretsmanager:PutSecretValue",
                                "secretsmanager:DeleteSecret",
                            ],
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )

        session = boto3.Session(region_name=region)
        findings: list[dict] = []
        findings.extend(check_s3(session, region))
        findings.extend(check_iam(session))
        findings.extend(check_ec2(session, region))
        findings.extend(check_rds(session, region))
        findings.extend(check_kms(session, region))
        findings.extend(check_sqs(session, region))
        findings.extend(check_secrets_manager(session, region))

        conn = AwsConnectionInfo(
            mode="simulate",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/vaultscan-sim",
            region=region,
        )
        return _package_result(findings, conn, region)


def _package_result(
    findings: list[dict],
    conn: AwsConnectionInfo,
    region: str,
) -> dict:
    score = compute_score(findings)
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f["severity"] in summary:
            summary[f["severity"]] += 1

    scan_id = f"SCAN-{uuid.uuid4().hex[:6].upper()}"
    ts = utcnow()
    meta = {
        "mode": conn.mode,
        "account_id": conn.account_id,
        "role_arn": conn.role_arn,
        "caller_arn": conn.arn,
        "score": score,
    }

    # Map findings for frontend vulnerability feed shape
    vulnerabilities = [
        {
            "id": f["resource"],
            "service": f["service"],
            "severity": f["severity"],
            "description": f["description"],
            "title": f["title"],
            "remediation": f["remediation"],
            "compliance": f["compliance"],
            "rule_id": f["rule_id"],
            "region": f.get("region", region),
        }
        for f in findings
    ]

    return {
        "scan_id": scan_id,
        "timestamp": ts,
        "mode": conn.mode,
        "region": region,
        "account_id": conn.account_id,
        "role_arn": conn.role_arn,
        "caller_arn": conn.arn,
        "score": score,
        "total_findings": len(findings),
        "summary": summary,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "compliance": build_compliance(findings),
        "remediation": build_remediation(findings),
        "attack_paths": build_attack_paths(findings),
        "audit_stream": build_audit_stream(findings, meta),
        "infra_status": [
            {
                "label": "TARGET SERVICE",
                "value": f"AWS-{conn.account_id or 'UNKNOWN'}-{region.upper()}",
                "state": "online" if conn.error is None else "error",
            },
            {
                "label": "SCAN ENGINE",
                "value": "VLT-ENGINE v1.3.0",
                "state": "online",
            },
            {
                "label": "AUTH MODE",
                "value": (
                    f"ASSUME_ROLE" if conn.mode == "assume_role" else conn.mode.upper()
                ),
                "state": "online" if not conn.error else "error",
            },
        ],
        "posture_point": {"t": ts[11:16] if len(ts) >= 16 else "now", "score": score},
    }


def run_scan(
    mode: str = "assume_role",
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str = "us-east-1",
) -> dict:
    """
    Execute a full CSPM scan.

    Falls back to simulate only when mode == 'simulate'.
    For assume_role/direct, failures raise (API returns 502 with detail).
    """
    if mode == "simulate":
        return run_simulate_scan(region=region)

    session, conn = get_scan_session(
        mode=mode,
        role_arn=role_arn,
        external_id=external_id,
        region=region,
    )
    assert session is not None

    findings: list[dict] = []
    findings.extend(check_s3(session, region))
    findings.extend(check_iam(session))
    findings.extend(check_ec2(session, region))
    findings.extend(check_rds(session, region))
    findings.extend(check_kms(session, region))
    findings.extend(check_sqs(session, region))
    findings.extend(check_secrets_manager(session, region))

    return _package_result(findings, conn, region)
