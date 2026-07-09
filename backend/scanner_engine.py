"""
VaultScan real-AWS misconfiguration engine.

Runs S3 / IAM / EC2 Security Group / RDS checks using a boto3 session
(typically from STS AssumeRole). Gracefully skips services the role cannot access.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from aws_client import AwsConnectionInfo, get_scan_session


SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2}


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

    # Roles with AdministratorAccess (common demo misconfig)
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                rname = role["RoleName"]
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
                                        "Any principal that can assume it gains full account control."
                                    ),
                                    remediation=(
                                        f"aws iam detach-role-policy --role-name {rname} "
                                        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                                    ),
                                    compliance=["CIS AWS 1.16", "NIST 800-53 AC-6"],
                                    rule_id="IAM-ROLE-ADMIN",
                                )
                            )
                except ClientError:
                    pass
    except ClientError:
        pass

    return findings


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
    """Moto-backed demo when real AWS credentials are unavailable."""
    from moto import mock_aws

    with mock_aws():
        s3 = boto3.client("s3", region_name=region)
        iam = boto3.client("iam", region_name=region)
        ec2 = boto3.client("ec2", region_name=region)

        s3.create_bucket(Bucket="vault-backups-public")
        s3.put_bucket_acl(Bucket="vault-backups-public", ACL="public-read")
        s3.create_bucket(Bucket="app-logs-unencrypted")

        iam.create_user(UserName="demo-admin")
        iam.put_user_policy(
            UserName="demo-admin",
            PolicyName="FullAdmin",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ],
                }
            ),
        )
        iam.create_user(UserName="ci-bot")

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

        session = boto3.Session(region_name=region)
        findings: list[dict] = []
        findings.extend(check_s3(session, region))
        findings.extend(check_iam(session))
        findings.extend(check_ec2(session, region))
        # RDS empty in moto demo is fine

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
        "audit_stream": build_audit_stream(findings, meta),
        "infra_status": [
            {
                "label": "TARGET SERVICE",
                "value": f"AWS-{conn.account_id or 'UNKNOWN'}-{region.upper()}",
                "state": "online" if conn.error is None else "error",
            },
            {
                "label": "SCAN ENGINE",
                "value": "VLT-ENGINE v1.0.0",
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

    return _package_result(findings, conn, region)
