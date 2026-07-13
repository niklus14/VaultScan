"""
VaultScan AI-assisted remediation engine.

- Plan: map findings → structured FixActions (registry + optional AI notes)
- Dry-run: preview without mutation
- Apply: allowlisted boto3 writes with pre-change snapshots
- Rollback ("make as before"): restore snapshot taken at apply time

Scanner credentials stay read-only by default. Apply uses the same session only
when allow_write_with_scan_creds=true OR auth_mode=simulate (demo path).
"""
from __future__ import annotations

import json
import threading
import uuid
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scan_persistence import _resolve_data_dir, _read_json, _write_json

Risk = Literal["safe", "elevated", "dangerous"]
ActionStatus = Literal[
    "planned",
    "dry_run_ok",
    "dry_run_fail",
    "applied",
    "failed",
    "skipped",
    "rolled_back",
    "rollback_failed",
]

_LOCK = threading.Lock()
_JOBS_PATH = _resolve_data_dir() / "remediation_jobs.json"
_FIXED_PATH = _resolve_data_dir() / "remediation_fixed.json"
_MAX_JOBS = 40


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_fixed() -> set[str]:
    """Finding ids suppressed after successful apply (persisted for serverless)."""
    raw = _read_json(_FIXED_PATH, {"ids": []})
    ids = raw.get("ids") or []
    return {str(x) for x in ids if x}


def _save_fixed(ids: set[str]) -> None:
    _write_json(_FIXED_PATH, {"ids": sorted(ids), "updated_at": utcnow()})


def get_simulate_fixed() -> set[str]:
    """All currently applied (not rolled back) finding suppressions."""
    return _load_fixed() | _applied_ids_from_jobs()


def _applied_ids_from_jobs() -> set[str]:
    """Derive fixed ids from jobs still in applied state (source of truth)."""
    out: set[str] = set()
    for job in list_jobs_unlocked():
        for act in job.get("actions") or []:
            if act.get("status") == "applied":
                fid = act.get("finding_id")
                if fid:
                    out.add(str(fid))
                # also rule:resource variants
                rid = act.get("rule_id")
                res = act.get("resource")
                if rid and res:
                    out.add(f"{rid}:{res}")
    return out


def list_jobs_unlocked() -> list[dict[str, Any]]:
    return deepcopy(_load_jobs().get("jobs") or [])


def mark_fixed(finding_id: str) -> None:
    ids = _load_fixed()
    ids.add(str(finding_id))
    _save_fixed(ids)


def unmark_fixed(finding_id: str) -> None:
    ids = _load_fixed()
    ids.discard(str(finding_id))
    _save_fixed(ids)


def clear_simulate_fixed() -> None:
    _save_fixed(set())


def finding_is_fixed(finding: dict[str, Any], fixed: set[str] | None = None) -> bool:
    """True if this finding should be hidden after a successful apply."""
    fixed = fixed if fixed is not None else get_simulate_fixed()
    if not fixed:
        return False
    fid = str(finding.get("id") or "")
    rid = str(finding.get("rule_id") or "")
    res = str(finding.get("resource") or "")
    candidates = {fid, res, rid}
    if rid and res:
        candidates.add(f"{rid}:{res}")
    if rid and fid:
        candidates.add(f"{rid}:{fid}")
    # Prefix match for SG-OPEN-* after demo apply of any open-port rule
    if rid.startswith("SG-OPEN-") and any(
        str(x).startswith("SG-OPEN-") for x in fixed
    ):
        return True
    return any(c and c in fixed for c in candidates)


@dataclass
class FixAction:
    action_id: str
    rule_id: str
    finding_id: str
    resource: str
    title: str
    risk: Risk
    summary: str
    auto_applicable: bool
    requires_confirm: bool
    cli_hint: str = ""
    steps: list[str] = field(default_factory=list)
    aws_calls: list[dict[str, Any]] = field(default_factory=list)
    snapshot: dict[str, Any] | None = None
    rollback_calls: list[dict[str, Any]] = field(default_factory=list)
    status: ActionStatus = "planned"
    preview: str | None = None
    error: str | None = None
    ai_notes: str | None = None
    region: str = "us-east-1"
    service: str = ""
    severity: str = "MEDIUM"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_jobs() -> dict[str, Any]:
    return _read_json(_JOBS_PATH, {"jobs": [], "latest_id": None})


def _save_jobs(raw: dict[str, Any]) -> None:
    jobs = raw.get("jobs") or []
    if len(jobs) > _MAX_JOBS:
        raw["jobs"] = jobs[:_MAX_JOBS]
    _write_json(_JOBS_PATH, raw)


def list_jobs() -> list[dict[str, Any]]:
    with _LOCK:
        return list_jobs_unlocked()


def get_job(job_id: str) -> dict[str, Any] | None:
    with _LOCK:
        for j in _load_jobs().get("jobs") or []:
            if j.get("job_id") == job_id:
                return deepcopy(j)
    return None


def _upsert_job(job: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        raw = _load_jobs()
        jobs = raw.get("jobs") or []
        found = False
        for i, j in enumerate(jobs):
            if j.get("job_id") == job["job_id"]:
                jobs[i] = job
                found = True
                break
        if not found:
            jobs.insert(0, job)
        raw["jobs"] = jobs
        raw["latest_id"] = job["job_id"]
        _save_jobs(raw)
        return deepcopy(job)


def _risk_for_rule(rule_id: str) -> Risk:
    rid = (rule_id or "").upper()
    safe = {
        "S3-BPA-INCOMPLETE",
        "S3-BPA-MISSING",
        "S3-NO-ENCRYPTION",
        "S3-NO-VERSIONING",
    }
    dangerous = {
        "IAM-ROLE-ADMIN",
        "IAM-ADMIN-POLICY",
        "IAM-TRUST-WILDCARD",
        "IAM-NO-MFA",
        "IAM-PRIVESC-NO-BOUNDARY",
        "EBS-NO-ENCRYPTION",
        "KMS-PUBLIC-POLICY",
        "SQS-PUBLIC-POLICY",
        "SM-PUBLIC-POLICY",
        "SM-OVERBROAD-POLICY",
    }
    if rid in safe:
        return "safe"
    if rid in dangerous or rid.startswith("IAM-"):
        return "dangerous"
    return "elevated"


def _auto_applicable(rule_id: str) -> bool:
    rid = (rule_id or "").upper()
    # Automatable (demo always; live AWS when write allowed)
    return rid in {
        "S3-BPA-INCOMPLETE",
        "S3-BPA-MISSING",
        "S3-PUBLIC-ACL",
        "S3-NO-ENCRYPTION",
        "S3-NO-VERSIONING",
        "S3-PUBLIC-POLICY",
        "SG-OPEN-22",
        "SG-OPEN-3389",
        "SG-OPEN-3306",
        "SG-OPEN-5432",
        "SG-OPEN-ALL",
        "EC2-IMDSV1",
        "IAM-ROLE-ADMIN",
        "IAM-ADMIN-POLICY",
        "IAM-CLOUDTRAIL-DESTROY",
        "IAM-IMAGE-LEAK",
        "IAM-PRIVESC-NO-BOUNDARY",
        "IAM-TRUST-WILDCARD",
        "KMS-PUBLIC-POLICY",
        "SQS-PUBLIC-POLICY",
        "SM-PUBLIC-POLICY",
        "SM-OVERBROAD-POLICY",
        "IAM-NO-MFA",  # demo suppress only; live = plan-only unless simulate
    } or rid.startswith("SG-OPEN-")


def build_action_from_finding(finding: dict[str, Any]) -> FixAction:
    rule_id = str(finding.get("rule_id") or "UNKNOWN")
    resource = str(finding.get("resource") or finding.get("id") or "*")
    finding_id = str(finding.get("id") or f"{rule_id}:{resource}")
    risk = _risk_for_rule(rule_id)
    auto = _auto_applicable(rule_id)
    title = str(finding.get("title") or finding.get("description") or rule_id)
    region = str(finding.get("region") or "us-east-1")
    service = str(finding.get("service") or "")
    severity = str(finding.get("severity") or "MEDIUM")
    cli = str(finding.get("remediation") or "")
    evidence = finding.get("evidence") or {}

    steps: list[str] = []
    aws_calls: list[dict[str, Any]] = []
    summary = f"Remediate {rule_id} on {resource}"

    rid = rule_id.upper()
    if rid in ("S3-BPA-INCOMPLETE", "S3-BPA-MISSING"):
        summary = f"Enable all S3 Block Public Access flags on bucket {resource}"
        steps = [
            "Snapshot current PublicAccessBlockConfiguration",
            "Put BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy/RestrictPublicBuckets = true",
        ]
        aws_calls = [
            {
                "service": "s3",
                "method": "put_public_access_block",
                "params": {
                    "Bucket": resource,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                },
            }
        ]
    elif rid == "S3-PUBLIC-ACL":
        summary = f"Set bucket ACL private on {resource}"
        steps = ["Snapshot ACL", "put_bucket_acl ACL=private"]
        aws_calls = [
            {
                "service": "s3",
                "method": "put_bucket_acl",
                "params": {"Bucket": resource, "ACL": "private"},
            }
        ]
    elif rid == "S3-NO-ENCRYPTION":
        summary = f"Enable default AES256 encryption on {resource}"
        steps = ["Snapshot encryption config", "put_bucket_encryption SSE-S3"]
        aws_calls = [
            {
                "service": "s3",
                "method": "put_bucket_encryption",
                "params": {
                    "Bucket": resource,
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                },
                                "BucketKeyEnabled": True,
                            }
                        ]
                    },
                },
            }
        ]
    elif rid == "S3-NO-VERSIONING":
        summary = f"Enable versioning on {resource}"
        steps = ["Snapshot versioning", "put_bucket_versioning Enabled"]
        aws_calls = [
            {
                "service": "s3",
                "method": "put_bucket_versioning",
                "params": {
                    "Bucket": resource,
                    "VersioningConfiguration": {"Status": "Enabled"},
                },
            }
        ]
    elif rid == "S3-PUBLIC-POLICY":
        summary = f"Remove public Principal * statements from bucket policy on {resource}"
        steps = [
            "Snapshot bucket policy",
            "Rewrite policy without Principal * allow statements (or delete policy if empty)",
        ]
        aws_calls = [
            {
                "service": "s3",
                "method": "strip_public_bucket_policy",
                "params": {"Bucket": resource},
            }
        ]
    elif rid.startswith("SG-OPEN-") or rid == "SG-OPEN-ALL":
        summary = f"Revoke world-open ingress on security group {resource}"
        steps = [
            "Snapshot security group ingress",
            "Revoke IpPermissions that allow 0.0.0.0/0 (targeted by evidence when possible)",
        ]
        aws_calls = [
            {
                "service": "ec2",
                "method": "revoke_open_ingress",
                "params": {
                    "GroupId": resource if resource.startswith("sg-") else resource,
                    "rule_id": rid,
                    "evidence": evidence,
                },
            }
        ]
    elif rid == "EC2-IMDSV1":
        instance_id = resource.split()[0] if resource else resource
        # resource may be "i-xxx (ip)"
        if "(" in instance_id:
            instance_id = instance_id.split("(")[0].strip()
        summary = f"Require IMDSv2 on instance {instance_id}"
        steps = ["Snapshot metadata options", "modify_instance_metadata_options HttpTokens=required"]
        aws_calls = [
            {
                "service": "ec2",
                "method": "modify_instance_metadata_options",
                "params": {
                    "InstanceId": instance_id,
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                },
            }
        ]
    elif rid in ("IAM-ROLE-ADMIN", "IAM-ADMIN-POLICY"):
        summary = f"Detach AdministratorAccess from {resource}"
        steps = [
            "Snapshot attached policies",
            "Detach arn:aws:iam::aws:policy/AdministratorAccess (or local AdministratorAccess)",
        ]
        entity = "role" if rid == "IAM-ROLE-ADMIN" else "user"
        aws_calls = [
            {
                "service": "iam",
                "method": "detach_admin",
                "params": {"entity": entity, "name": resource},
            }
        ]
    elif rid in (
        "IAM-CLOUDTRAIL-DESTROY",
        "IAM-IMAGE-LEAK",
        "IAM-PRIVESC-NO-BOUNDARY",
    ):
        summary = f"Detach dangerous managed policy attachment for {resource}"
        steps = [
            "Identify attached policy from evidence/policy_name",
            "Detach user/role policy when possible",
        ]
        pol_name = (evidence or {}).get("policy_name") or ""
        aws_calls = [
            {
                "service": "iam",
                "method": "detach_named_policy",
                "params": {
                    "name": resource,
                    "policy_name": pol_name,
                    "attachment": (evidence or {}).get("attachment") or "",
                },
            }
        ]
    elif rid in (
        "IAM-TRUST-WILDCARD",
        "KMS-PUBLIC-POLICY",
        "SQS-PUBLIC-POLICY",
        "SM-PUBLIC-POLICY",
        "SM-OVERBROAD-POLICY",
        "IAM-NO-MFA",
    ):
        # Structured apply: full for demo; live AWS uses best-effort handlers below
        summary = f"Remediate {rule_id} on {resource}"
        steps = [
            "Snapshot current configuration",
            "Apply least-privilege / non-public configuration",
            "Re-scan to verify",
        ]
        aws_calls = [
            {
                "service": "generic",
                "method": "demo_or_best_effort",
                "params": {"rule_id": rid, "resource": resource, "evidence": evidence},
            }
        ]
    else:
        summary = f"Manual / AI-assisted remediation for {rule_id}"
        steps = [
            "Review finding and CLI remediation",
            "Apply change carefully in AWS console or CLI",
            "Re-scan to verify",
        ]
        if cli:
            steps.insert(1, f"Suggested: {cli}")
        auto = False

    return FixAction(
        action_id=f"act-{uuid.uuid4().hex[:10]}",
        rule_id=rule_id,
        finding_id=finding_id,
        resource=resource,
        title=title,
        risk=risk,
        summary=summary,
        auto_applicable=auto and bool(aws_calls),
        requires_confirm=risk != "safe",
        cli_hint=cli,
        steps=steps,
        aws_calls=aws_calls,
        region=region,
        service=service,
        severity=severity,
    )


def plan_from_scan(
    scan: dict[str, Any] | None,
    *,
    finding_ids: list[str] | None = None,
    mode: Literal["all_safe", "selected", "all"] = "all_safe",
) -> dict[str, Any]:
    findings = list((scan or {}).get("findings") or [])
    if not findings:
        # vulnerabilities shape
        findings = list((scan or {}).get("vulnerabilities") or [])
        # normalize light shape
        normalized = []
        for v in findings:
            normalized.append(
                {
                    "id": v.get("id"),
                    "rule_id": v.get("rule_id"),
                    "resource": v.get("id") or v.get("resource"),
                    "title": v.get("title"),
                    "description": v.get("description"),
                    "remediation": v.get("remediation"),
                    "severity": v.get("severity"),
                    "service": v.get("service"),
                    "region": v.get("region") or (scan or {}).get("region") or "us-east-1",
                    "evidence": v.get("evidence") or {},
                    "compliance": v.get("compliance") or [],
                }
            )
        findings = normalized

    actions: list[FixAction] = []
    id_set = set(finding_ids or [])

    for f in findings:
        fid = str(f.get("id") or "")
        if mode == "selected" and id_set and fid not in id_set:
            # also match resource-based ids
            if str(f.get("resource") or "") not in id_set:
                continue
        action = build_action_from_finding(f)
        # Do NOT clear auto_applicable here — that permanently blocks Apply later.
        # Filter risk only at apply-time via only_safe.
        if mode == "all_safe" and action.risk != "safe":
            action.preview = (
                "Included in plan but risk is not safe — uncheck "
                "“Only safe fixes” (or use PLAN ALL) to apply."
            )
        actions.append(action)

    # severity order
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    actions.sort(key=lambda a: (order.get(a.severity, 9), a.risk != "safe"))

    job = {
        "job_id": f"JOB-{uuid.uuid4().hex[:8].upper()}",
        "created_at": utcnow(),
        "updated_at": utcnow(),
        "scan_id": (scan or {}).get("scan_id"),
        "mode": mode,
        "status": "planned",
        "ai_used": False,
        "actions": [a.to_dict() for a in actions],
        "score_before": (scan or {}).get("score"),
        "score_after": None,
        "rollback_available": False,
    }
    return _upsert_job(job)


def _client(session: boto3.Session | None, service: str, region: str):
    if session is None:
        return None
    if service in ("iam", "s3"):
        return session.client(service)
    return session.client(service, region_name=region)


def _snapshot_before(
    session: boto3.Session | None,
    action: dict[str, Any],
    *,
    simulate: bool,
) -> dict[str, Any]:
    """Capture pre-change state for 'make as before' rollback."""
    rid = (action.get("rule_id") or "").upper()
    resource = action.get("resource") or ""
    region = action.get("region") or "us-east-1"
    snap: dict[str, Any] = {"rule_id": rid, "resource": resource, "at": utcnow()}

    if simulate or session is None:
        snap["simulate"] = True
        snap["note"] = "Demo snapshot — rollback re-opens the finding"
        return snap

    try:
        if rid.startswith("S3-"):
            s3 = session.client("s3")
            bucket = resource
            if rid in ("S3-BPA-INCOMPLETE", "S3-BPA-MISSING"):
                try:
                    snap["public_access_block"] = s3.get_public_access_block(
                        Bucket=bucket
                    ).get("PublicAccessBlockConfiguration")
                except ClientError as e:
                    snap["public_access_block"] = None
                    snap["public_access_block_error"] = e.response["Error"].get("Code")
            if rid == "S3-PUBLIC-ACL":
                try:
                    snap["acl"] = s3.get_bucket_acl(Bucket=bucket)
                except ClientError:
                    snap["acl"] = None
            if rid == "S3-NO-ENCRYPTION":
                try:
                    snap["encryption"] = s3.get_bucket_encryption(Bucket=bucket)
                except ClientError:
                    snap["encryption"] = None
            if rid == "S3-NO-VERSIONING":
                try:
                    snap["versioning"] = s3.get_bucket_versioning(Bucket=bucket)
                except ClientError:
                    snap["versioning"] = None
            if rid == "S3-PUBLIC-POLICY":
                try:
                    snap["policy"] = s3.get_bucket_policy(Bucket=bucket).get("Policy")
                except ClientError:
                    snap["policy"] = None
        elif rid.startswith("SG-OPEN") or rid == "SG-OPEN-ALL":
            ec2 = session.client("ec2", region_name=region)
            gid = resource if str(resource).startswith("sg-") else resource
            sgs = ec2.describe_security_groups(GroupIds=[gid]).get("SecurityGroups", [])
            if sgs:
                snap["ip_permissions"] = sgs[0].get("IpPermissions", [])
        elif rid == "IAM-TRUST-WILDCARD":
            iam = session.client("iam")
            rname = _iam_role_name(resource)
            try:
                role = iam.get_role(RoleName=rname)["Role"]
                snap["assume_role_policy"] = role.get("AssumeRolePolicyDocument")
                snap["role_name"] = rname
            except ClientError as e:
                if _is_missing_entity(e):
                    snap["missing"] = True
                    snap["role_name"] = rname
                else:
                    raise
            try:
                snap["account_id"] = session.client("sts").get_caller_identity()[
                    "Account"
                ]
            except ClientError:
                snap["account_id"] = None
        elif rid == "KMS-PUBLIC-POLICY":
            kms = session.client("kms", region_name=region)
            key_id = (action.get("evidence") or {}).get("key_id") or resource
            if str(key_id).startswith("alias/"):
                # resolve alias
                key_id = resource
            try:
                snap["key_policy"] = kms.get_key_policy(
                    KeyId=key_id, PolicyName="default"
                ).get("Policy")
                snap["key_id"] = key_id
            except ClientError as e:
                snap["key_policy_error"] = str(e)
        elif rid == "SQS-PUBLIC-POLICY":
            sqs = session.client("sqs", region_name=region)
            qurl = (action.get("evidence") or {}).get("queue_url")
            if not qurl:
                # list and match by name
                urls = sqs.list_queues().get("QueueUrls") or []
                for u in urls:
                    if u.rstrip("/").endswith("/" + resource) or resource in u:
                        qurl = u
                        break
            snap["queue_url"] = qurl
            if qurl:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=qurl, AttributeNames=["Policy"]
                ).get("Attributes", {})
                snap["policy"] = attrs.get("Policy")
        elif rid in ("SM-PUBLIC-POLICY", "SM-OVERBROAD-POLICY"):
            sm = session.client("secretsmanager", region_name=region)
            try:
                rp = sm.get_resource_policy(SecretId=resource)
                snap["resource_policy"] = rp.get("ResourcePolicy")
                snap["secret_arn"] = rp.get("ARN") or resource
            except ClientError as e:
                snap["resource_policy_error"] = str(e)
        elif rid == "EC2-IMDSV1":
            ec2 = session.client("ec2", region_name=region)
            iid = str(resource).split("(")[0].strip()
            meta = (
                ec2.describe_instances(InstanceIds=[iid])
                .get("Reservations", [{}])[0]
                .get("Instances", [{}])[0]
                .get("MetadataOptions", {})
            )
            snap["metadata_options"] = meta
        elif rid in ("IAM-ROLE-ADMIN", "IAM-ADMIN-POLICY") or rid.startswith("IAM-"):
            iam = session.client("iam")
            name = resource
            if rid == "IAM-ROLE-ADMIN":
                snap["attached"] = iam.list_attached_role_policies(RoleName=name).get(
                    "AttachedPolicies", []
                )
            else:
                try:
                    snap["attached"] = iam.list_attached_user_policies(
                        UserName=name
                    ).get("AttachedPolicies", [])
                except ClientError:
                    try:
                        snap["attached"] = iam.list_attached_role_policies(
                            RoleName=name
                        ).get("AttachedPolicies", [])
                        snap["entity"] = "role"
                    except ClientError:
                        snap["attached"] = []
    except Exception as exc:  # noqa: BLE001
        snap["snapshot_error"] = str(exc)
    return snap


def _iam_role_name(resource: str) -> str:
    """Extract IAM role name from bare name or ARN."""
    r = (resource or "").strip()
    if ":role/" in r:
        # arn:aws:iam::123:role/path/name or role/name
        return r.split(":role/", 1)[-1].split("/")[-1]
    if r.startswith("role/"):
        return r.split("/", 1)[-1]
    return r


def _is_missing_entity(exc: BaseException) -> bool:
    msg = str(exc)
    if "NoSuchEntity" in msg or "NoSuchBucket" in msg or "InvalidGroup.NotFound" in msg:
        return True
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {
            "NoSuchEntity",
            "NoSuchBucket",
            "NoSuchKey",
            "InvalidGroup.NotFound",
            "InvalidInstanceID.NotFound",
            "ResourceNotFoundException",
            "NotFoundException",
            "QueueDoesNotExist",
            "AWS.SimpleQueueService.NonExistentQueue",
        }
    return False


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for key in ("AWS", "CanonicalUser", "Federated"):
            vals = principal.get(key)
            if vals == "*" or vals == ["*"]:
                return True
            if isinstance(vals, list) and any(v == "*" for v in vals):
                return True
    return False


def _strip_public_policy_doc(doc: dict[str, Any]) -> dict[str, Any] | None:
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    kept = []
    for st in stmts:
        if not isinstance(st, dict):
            continue
        if str(st.get("Effect", "Allow")).lower() == "allow" and _principal_is_public(
            st.get("Principal")
        ):
            continue
        kept.append(st)
    if not kept:
        return None
    out = dict(doc)
    out["Statement"] = kept
    return out


def _tighten_trust_policy(doc: dict[str, Any], *, account_id: str, role_name: str) -> dict[str, Any]:
    """
    Replace Principal * / AWS:* with a safe principal.
    EC2-style roles → Service: ec2.amazonaws.com; else account root.
    """
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    new_stmts = []
    for st in stmts:
        if not isinstance(st, dict):
            continue
        st = dict(st)
        if str(st.get("Effect", "Allow")).lower() == "allow" and _principal_is_public(
            st.get("Principal")
        ):
            if "ec2" in role_name.lower():
                st["Principal"] = {"Service": "ec2.amazonaws.com"}
            else:
                st["Principal"] = {
                    "AWS": f"arn:aws:iam::{account_id}:root"
                }
            # keep Action sts:AssumeRole
            if not st.get("Action"):
                st["Action"] = "sts:AssumeRole"
        new_stmts.append(st)
    if not new_stmts:
        # minimal safe trust so the role is not left unusable
        if "ec2" in role_name.lower():
            principal: Any = {"Service": "ec2.amazonaws.com"}
        else:
            principal = {"AWS": f"arn:aws:iam::{account_id}:root"}
        new_stmts = [
            {
                "Effect": "Allow",
                "Principal": principal,
                "Action": "sts:AssumeRole",
            }
        ]
    return {"Version": doc.get("Version") or "2012-10-17", "Statement": new_stmts}


def _strip_public_or_root_broad_secret_policy(
    doc: dict[str, Any],
) -> dict[str, Any] | None:
    """Remove Allow statements with Principal * or overly broad account-root wildcards."""
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    kept = []
    for st in stmts:
        if not isinstance(st, dict):
            continue
        if str(st.get("Effect", "Allow")).lower() != "allow":
            kept.append(st)
            continue
        if _principal_is_public(st.get("Principal")):
            continue
        # drop root principal with many secretsmanager actions (lab overbroad)
        principal = st.get("Principal") or {}
        aws_p = principal.get("AWS") if isinstance(principal, dict) else None
        is_root = False
        for v in (aws_p if isinstance(aws_p, list) else [aws_p]):
            if isinstance(v, str) and v.endswith(":root"):
                is_root = True
        actions = st.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        actions = [str(a).lower() for a in (actions or [])]
        dangerous = {
            "secretsmanager:getsecretvalue",
            "secretsmanager:putsecretvalue",
            "secretsmanager:deletesecret",
            "secretsmanager:*",
            "*",
        }
        if is_root and (set(actions) & dangerous or "*" in actions):
            continue
        kept.append(st)
    if not kept:
        return None
    out = dict(doc)
    out["Statement"] = kept
    return out


def apply_one(
    session: boto3.Session | None,
    action: dict[str, Any],
    *,
    simulate: bool,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Apply or dry-run a single FixAction dict. Mutates and returns action."""
    a = deepcopy(action)
    if not a.get("auto_applicable") and not dry_run:
        a["status"] = "skipped"
        a["error"] = "Not auto-applicable — use CLI / console"
        return a

    rid = (a.get("rule_id") or "").upper()
    resource = a.get("resource") or ""
    region = a.get("region") or "us-east-1"

    # Always snapshot before real apply (and before dry-run for preview)
    if not a.get("snapshot"):
        a["snapshot"] = _snapshot_before(session, a, simulate=simulate)

    if dry_run:
        a["status"] = "dry_run_ok"
        a["preview"] = (
            f"[dry-run] Would apply {rid} on {resource}: "
            + ", ".join(
                f"{c.get('service')}.{c.get('method')}"
                for c in (a.get("aws_calls") or [])
            )
            or "manual only"
        )
        if not a.get("auto_applicable"):
            a["status"] = "dry_run_fail"
            a["preview"] = "No automated apply path — AI/CLI plan only"
        return a

    if simulate or session is None:
        # Demo apply: persist suppress keys (serverless-safe).
        # Also mark rule_id alone — simulate re-scans often mint new resource IDs (e.g. sg-*).
        fid = str(a.get("finding_id") or "")
        if fid:
            mark_fixed(fid)
        if rid and resource:
            mark_fixed(f"{rid}:{resource}")
        if rid:
            mark_fixed(rid)
        a["status"] = "applied"
        a["preview"] = f"[demo] Simulated apply of {rid} on {resource}"
        a["error"] = None
        return a

    try:
        if rid in ("S3-BPA-INCOMPLETE", "S3-BPA-MISSING"):
            s3 = session.client("s3")
            s3.put_public_access_block(
                Bucket=resource,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
        elif rid == "S3-PUBLIC-ACL":
            session.client("s3").put_bucket_acl(Bucket=resource, ACL="private")
        elif rid == "S3-NO-ENCRYPTION":
            session.client("s3").put_bucket_encryption(
                Bucket=resource,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            },
                            "BucketKeyEnabled": True,
                        }
                    ]
                },
            )
        elif rid == "S3-NO-VERSIONING":
            session.client("s3").put_bucket_versioning(
                Bucket=resource,
                VersioningConfiguration={"Status": "Enabled"},
            )
        elif rid == "S3-PUBLIC-POLICY":
            s3 = session.client("s3")
            try:
                raw = s3.get_bucket_policy(Bucket=resource)["Policy"]
                doc = json.loads(raw) if isinstance(raw, str) else raw
                new_doc = _strip_public_policy_doc(doc)
                if new_doc is None:
                    s3.delete_bucket_policy(Bucket=resource)
                else:
                    s3.put_bucket_policy(
                        Bucket=resource, Policy=json.dumps(new_doc)
                    )
            except ClientError as e:
                raise RuntimeError(f"Policy update failed: {e}") from e
        elif rid.startswith("SG-OPEN") or rid == "SG-OPEN-ALL":
            ec2 = session.client("ec2", region_name=region)
            gid = resource if str(resource).startswith("sg-") else resource
            sgs = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"]
            perms = sgs[0].get("IpPermissions", []) if sgs else []
            revoke = []
            for p in perms:
                ranges = p.get("IpRanges") or []
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in ranges):
                    revoke.append(p)
            if revoke:
                ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=revoke)
            else:
                a["preview"] = "No 0.0.0.0/0 ingress found to revoke"
        elif rid == "EC2-IMDSV1":
            iid = str(resource).split("(")[0].strip()
            session.client("ec2", region_name=region).modify_instance_metadata_options(
                InstanceId=iid,
                HttpTokens="required",
                HttpEndpoint="enabled",
            )
        elif rid in ("IAM-ROLE-ADMIN", "IAM-ADMIN-POLICY"):
            iam = session.client("iam")
            name = _iam_role_name(resource) if rid == "IAM-ROLE-ADMIN" else resource
            try:
                if rid == "IAM-ROLE-ADMIN":
                    for pol in iam.list_attached_role_policies(RoleName=name).get(
                        "AttachedPolicies", []
                    ):
                        if "AdministratorAccess" in (pol.get("PolicyName") or ""):
                            iam.detach_role_policy(
                                RoleName=name, PolicyArn=pol["PolicyArn"]
                            )
                else:
                    detached = False
                    try:
                        for pol in iam.list_attached_user_policies(UserName=name).get(
                            "AttachedPolicies", []
                        ):
                            if "AdministratorAccess" in (pol.get("PolicyName") or ""):
                                iam.detach_user_policy(
                                    UserName=name, PolicyArn=pol["PolicyArn"]
                                )
                                detached = True
                    except ClientError:
                        pass
                    if not detached:
                        rname = _iam_role_name(name)
                        for pol in iam.list_attached_role_policies(RoleName=rname).get(
                            "AttachedPolicies", []
                        ):
                            if "AdministratorAccess" in (pol.get("PolicyName") or ""):
                                iam.detach_role_policy(
                                    RoleName=rname, PolicyArn=pol["PolicyArn"]
                                )
            except ClientError as e:
                if _is_missing_entity(e):
                    a["preview"] = f"IAM entity {name} not found — already removed"
                    a["status"] = "applied"
                    a["error"] = None
                    return a
                raise
        elif rid in (
            "IAM-CLOUDTRAIL-DESTROY",
            "IAM-IMAGE-LEAK",
            "IAM-PRIVESC-NO-BOUNDARY",
        ):
            iam = session.client("iam")
            name = resource
            want = (a.get("snapshot") or {}).get("policy_name") or ""
            for c in a.get("aws_calls") or []:
                want = c.get("params", {}).get("policy_name") or want
            detached = False
            missing = False
            for list_fn, detach_fn, key in (
                (
                    lambda: iam.list_attached_user_policies(UserName=name),
                    lambda arn: iam.detach_user_policy(UserName=name, PolicyArn=arn),
                    "AttachedPolicies",
                ),
                (
                    lambda: iam.list_attached_role_policies(
                        RoleName=_iam_role_name(name)
                    ),
                    lambda arn: iam.detach_role_policy(
                        RoleName=_iam_role_name(name), PolicyArn=arn
                    ),
                    "AttachedPolicies",
                ),
            ):
                try:
                    for pol in list_fn().get(key, []):
                        pname = pol.get("PolicyName") or ""
                        if want and want != pname:
                            continue
                        if want or any(
                            x in pname.lower()
                            for x in ("trail", "leakage", "privesc", "scanner")
                        ):
                            detach_fn(pol["PolicyArn"])
                            detached = True
                    if detached:
                        break
                except ClientError as e:
                    if _is_missing_entity(e):
                        missing = True
                        continue
                    continue
            if missing and not detached:
                a["preview"] = f"IAM entity {name} not found — already removed"
                a["status"] = "applied"
                a["error"] = None
                return a
            if not detached:
                raise RuntimeError(
                    "Could not find/detach matching managed policy — apply manually"
                )
        elif rid == "IAM-TRUST-WILDCARD":
            iam = session.client("iam")
            role_name = _iam_role_name(
                (a.get("snapshot") or {}).get("role_name") or resource
            )
            try:
                role = iam.get_role(RoleName=role_name)["Role"]
            except ClientError as e:
                if _is_missing_entity(e):
                    # Role gone → trust issue is already "fixed" (nothing to assume)
                    a["preview"] = (
                        f"Role '{role_name}' does not exist in this account "
                        f"(caller account may differ from scan, or role was deleted). "
                        f"Treated as resolved."
                    )
                    a["status"] = "applied"
                    a["error"] = None
                    return a
                raise
            doc = role.get("AssumeRolePolicyDocument") or {}
            if isinstance(doc, str):
                doc = json.loads(doc)
            if not a.get("snapshot") or not a["snapshot"].get("assume_role_policy"):
                a["snapshot"] = a.get("snapshot") or {}
                a["snapshot"]["assume_role_policy"] = doc
                a["snapshot"]["role_name"] = role_name
            account_id = (
                (a.get("snapshot") or {}).get("account_id")
                or session.client("sts").get_caller_identity()["Account"]
            )
            tight = _tighten_trust_policy(
                doc, account_id=str(account_id), role_name=role_name
            )
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(tight),
            )
            a["preview"] = (
                f"Updated trust policy on {role_name}: removed Principal * "
                f"(now ec2.amazonaws.com or account root)"
            )
        elif rid == "KMS-PUBLIC-POLICY":
            kms = session.client("kms", region_name=region)
            key_id = (
                (a.get("snapshot") or {}).get("key_id")
                or (a.get("evidence") or {}).get("key_id")
                or resource
            )
            # evidence may only be on original finding — try list aliases
            if str(resource).startswith("alias/"):
                key_id = resource
            try:
                raw = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            except ClientError:
                # resolve alias → key id
                aliases = kms.list_aliases().get("Aliases", [])
                for al in aliases:
                    if al.get("AliasName") == resource or al.get("AliasName") == f"alias/{resource}":
                        key_id = al.get("TargetKeyId") or key_id
                        break
                raw = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            doc = json.loads(raw) if isinstance(raw, str) else raw
            a.setdefault("snapshot", {})
            a["snapshot"]["key_policy"] = raw if isinstance(raw, str) else json.dumps(doc)
            a["snapshot"]["key_id"] = key_id
            new_doc = _strip_public_policy_doc(doc)
            if new_doc is None:
                # keep account root kms:* so key is not locked out
                account_id = session.client("sts").get_caller_identity()["Account"]
                new_doc = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "EnableRootPermissions",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": f"arn:aws:iam::{account_id}:root"
                            },
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                }
            kms.put_key_policy(
                KeyId=key_id,
                PolicyName="default",
                Policy=json.dumps(new_doc),
            )
            a["preview"] = f"Removed public Principal * from KMS key policy ({key_id})"
        elif rid == "SQS-PUBLIC-POLICY":
            sqs = session.client("sqs", region_name=region)
            qurl = (a.get("snapshot") or {}).get("queue_url")
            if not qurl:
                urls = sqs.list_queues().get("QueueUrls") or []
                for u in urls:
                    if resource in u or u.rstrip("/").endswith("/" + resource):
                        qurl = u
                        break
            if not qurl:
                raise RuntimeError(f"Could not resolve SQS queue URL for {resource}")
            attrs = sqs.get_queue_attributes(
                QueueUrl=qurl, AttributeNames=["Policy", "QueueArn"]
            ).get("Attributes", {})
            a.setdefault("snapshot", {})
            a["snapshot"]["queue_url"] = qurl
            a["snapshot"]["policy"] = attrs.get("Policy")
            policy_raw = attrs.get("Policy")
            if policy_raw:
                doc = json.loads(policy_raw)
                new_doc = _strip_public_policy_doc(doc)
                if new_doc is None:
                    sqs.set_queue_attributes(
                        QueueUrl=qurl, Attributes={"Policy": ""}
                    )
                    # empty policy = delete
                    try:
                        # some regions need omit; use empty JSON account-only deny public
                        account_id = session.client("sts").get_caller_identity()[
                            "Account"
                        ]
                        qarn = attrs.get("QueueArn") or ""
                        private = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": f"arn:aws:iam::{account_id}:root"
                                    },
                                    "Action": "sqs:*",
                                    "Resource": qarn or "*",
                                }
                            ],
                        }
                        sqs.set_queue_attributes(
                            QueueUrl=qurl,
                            Attributes={"Policy": json.dumps(private)},
                        )
                    except ClientError:
                        pass
                else:
                    sqs.set_queue_attributes(
                        QueueUrl=qurl,
                        Attributes={"Policy": json.dumps(new_doc)},
                    )
            a["preview"] = f"Removed public Principal * from SQS queue {resource}"
        elif rid in ("SM-PUBLIC-POLICY", "SM-OVERBROAD-POLICY"):
            sm = session.client("secretsmanager", region_name=region)
            try:
                rp = sm.get_resource_policy(SecretId=resource)
            except ClientError as e:
                raise RuntimeError(f"Secrets Manager get policy failed: {e}") from e
            raw = rp.get("ResourcePolicy")
            a.setdefault("snapshot", {})
            a["snapshot"]["resource_policy"] = raw
            a["snapshot"]["secret_arn"] = rp.get("ARN") or resource
            if not raw:
                a["preview"] = "No resource policy on secret — nothing to strip"
            else:
                doc = json.loads(raw) if isinstance(raw, str) else raw
                new_doc = _strip_public_or_root_broad_secret_policy(doc)
                if new_doc is None:
                    sm.delete_resource_policy(SecretId=resource)
                    a["preview"] = f"Deleted over-broad resource policy on {resource}"
                else:
                    sm.put_resource_policy(
                        SecretId=resource,
                        ResourcePolicy=json.dumps(new_doc),
                    )
                    a["preview"] = f"Tightened Secrets Manager policy on {resource}"
        elif rid == "IAM-NO-MFA":
            # Cannot programmatically enroll MFA for a human without device
            raise RuntimeError(
                f"IAM-NO-MFA cannot be fully automated: user '{resource}' must assign "
                "an MFA device in IAM console (Users → Security credentials). "
                "Other findings in this job can still be auto-fixed."
            )
        else:
            a["status"] = "skipped"
            a["error"] = "No automated apply handler for this rule"
            return a

        if a.get("status") != "applied":
            a["status"] = "applied"
            a["error"] = None
            if not a.get("preview"):
                a["preview"] = f"Applied {rid} on {resource} in AWS"
        # Do NOT mark_fixed for live AWS — next scan must reflect real account state.
    except (ClientError, BotoCoreError, RuntimeError) as exc:
        if _is_missing_entity(exc):
            # Resource already gone → treat as fixed so re-scan is clean
            a["status"] = "applied"
            a["error"] = None
            a["preview"] = (
                f"Resource not found for {rid} ({resource}) — treated as already fixed. "
                f"If this keeps appearing, re-scan with credentials in the correct account."
            )
            return a
        a["status"] = "failed"
        err = str(exc)
        if "AccessDenied" in err or "UnauthorizedOperation" in err or "not authorized" in err.lower():
            a["error"] = (
                f"AWS denied this write ({rid} on {resource}). "
                "Apply uses the scan AssumeRole when possible, else your Access Keys. "
                "Both need permission in the **same account** as the finding. "
                f"Detail: {err}"
            )
        else:
            a["error"] = err
    return a


def rollback_one(
    session: boto3.Session | None,
    action: dict[str, Any],
    *,
    simulate: bool,
) -> dict[str, Any]:
    """Restore pre-apply snapshot — 'make as before'."""
    a = deepcopy(action)
    snap = a.get("snapshot") or {}
    rid = (a.get("rule_id") or "").upper()
    resource = a.get("resource") or ""
    region = a.get("region") or "us-east-1"

    if a.get("status") not in ("applied", "rollback_failed"):
        a["error"] = "Nothing to roll back (not applied)"
        a["status"] = "skipped"
        return a

    if simulate or session is None or snap.get("simulate"):
        fid = str(a.get("finding_id") or "")
        if fid:
            unmark_fixed(fid)
        if rid and resource:
            unmark_fixed(f"{rid}:{resource}")
        if rid:
            unmark_fixed(rid)
        a["status"] = "rolled_back"
        a["preview"] = f"[demo] Restored finding {a.get('finding_id')}"
        a["error"] = None
        return a

    try:
        if rid in ("S3-BPA-INCOMPLETE", "S3-BPA-MISSING"):
            s3 = session.client("s3")
            prev = snap.get("public_access_block")
            if prev:
                s3.put_public_access_block(
                    Bucket=resource, PublicAccessBlockConfiguration=prev
                )
            else:
                # was missing entirely
                try:
                    s3.delete_public_access_block(Bucket=resource)
                except ClientError:
                    pass
        elif rid == "S3-PUBLIC-ACL":
            # best-effort: cannot perfectly restore complex ACL grants via simple API;
            # re-apply public-read if original had AllUsers (common lab case)
            s3 = session.client("s3")
            acl = snap.get("acl") or {}
            grants = acl.get("Grants") or []
            public = any(
                "AllUsers" in str(g.get("Grantee", {}).get("URI", ""))
                for g in grants
            )
            if public:
                s3.put_bucket_acl(Bucket=resource, ACL="public-read")
            else:
                s3.put_bucket_acl(Bucket=resource, ACL="private")
        elif rid == "S3-NO-ENCRYPTION":
            s3 = session.client("s3")
            enc = snap.get("encryption")
            if not enc:
                try:
                    s3.delete_bucket_encryption(Bucket=resource)
                except ClientError:
                    pass
            else:
                cfg = enc.get("ServerSideEncryptionConfiguration") or enc
                s3.put_bucket_encryption(
                    Bucket=resource, ServerSideEncryptionConfiguration=cfg
                )
        elif rid == "S3-NO-VERSIONING":
            prev = (snap.get("versioning") or {}).get("Status") or "Suspended"
            session.client("s3").put_bucket_versioning(
                Bucket=resource,
                VersioningConfiguration={
                    "Status": "Suspended" if prev != "Enabled" else "Enabled"
                },
            )
            if prev != "Enabled":
                session.client("s3").put_bucket_versioning(
                    Bucket=resource,
                    VersioningConfiguration={"Status": "Suspended"},
                )
        elif rid == "S3-PUBLIC-POLICY":
            s3 = session.client("s3")
            prev = snap.get("policy")
            if prev:
                s3.put_bucket_policy(Bucket=resource, Policy=prev if isinstance(prev, str) else json.dumps(prev))
            else:
                try:
                    s3.delete_bucket_policy(Bucket=resource)
                except ClientError:
                    pass
        elif rid.startswith("SG-OPEN") or rid == "SG-OPEN-ALL":
            ec2 = session.client("ec2", region_name=region)
            gid = resource if str(resource).startswith("sg-") else resource
            perms = snap.get("ip_permissions") or []
            if perms:
                # authorize back (may fail if already present)
                try:
                    ec2.authorize_security_group_ingress(
                        GroupId=gid, IpPermissions=perms
                    )
                except ClientError as e:
                    if e.response["Error"].get("Code") not in (
                        "InvalidPermission.Duplicate",
                    ):
                        raise
        elif rid == "IAM-TRUST-WILDCARD":
            prev = snap.get("assume_role_policy")
            if prev:
                if not isinstance(prev, str):
                    prev = json.dumps(prev)
                session.client("iam").update_assume_role_policy(
                    RoleName=resource, PolicyDocument=prev
                )
        elif rid == "KMS-PUBLIC-POLICY":
            prev = snap.get("key_policy")
            key_id = snap.get("key_id") or resource
            if prev:
                session.client("kms", region_name=region).put_key_policy(
                    KeyId=key_id,
                    PolicyName="default",
                    Policy=prev if isinstance(prev, str) else json.dumps(prev),
                )
        elif rid == "SQS-PUBLIC-POLICY":
            qurl = snap.get("queue_url")
            prev = snap.get("policy")
            if qurl and prev is not None:
                session.client("sqs", region_name=region).set_queue_attributes(
                    QueueUrl=qurl,
                    Attributes={"Policy": prev if isinstance(prev, str) else json.dumps(prev)},
                )
        elif rid in ("SM-PUBLIC-POLICY", "SM-OVERBROAD-POLICY"):
            sm = session.client("secretsmanager", region_name=region)
            prev = snap.get("resource_policy")
            sid = snap.get("secret_arn") or resource
            if prev:
                sm.put_resource_policy(
                    SecretId=sid,
                    ResourcePolicy=prev if isinstance(prev, str) else json.dumps(prev),
                )
            else:
                try:
                    sm.delete_resource_policy(SecretId=sid)
                except ClientError:
                    pass
        elif rid == "EC2-IMDSV1":
            meta = snap.get("metadata_options") or {}
            tokens = meta.get("HttpTokens") or "optional"
            session.client("ec2", region_name=region).modify_instance_metadata_options(
                InstanceId=str(resource).split("(")[0].strip(),
                HttpTokens=tokens if tokens in ("optional", "required") else "optional",
                HttpEndpoint=meta.get("HttpEndpoint") or "enabled",
            )
        elif rid in ("IAM-ROLE-ADMIN", "IAM-ADMIN-POLICY") or rid.startswith("IAM-"):
            iam = session.client("iam")
            name = resource
            for pol in snap.get("attached") or []:
                arn = pol.get("PolicyArn")
                if not arn:
                    continue
                try:
                    if rid == "IAM-ROLE-ADMIN" or snap.get("entity") == "role":
                        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                    else:
                        try:
                            iam.attach_user_policy(UserName=name, PolicyArn=arn)
                        except ClientError:
                            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                except ClientError:
                    continue
        else:
            a["status"] = "rollback_failed"
            a["error"] = "No rollback handler for this rule"
            return a

        a["status"] = "rolled_back"
        a["error"] = None
        a["preview"] = f"Rolled back {rid} on {resource} to pre-fix snapshot"
        fid = str(a.get("finding_id") or "")
        if fid:
            unmark_fixed(fid)
        if rid and resource:
            unmark_fixed(f"{rid}:{resource}")
    except (ClientError, BotoCoreError, RuntimeError) as exc:
        a["status"] = "rollback_failed"
        a["error"] = str(exc)
    return a


def dry_run_job(
    job_id: str,
    session: boto3.Session | None,
    *,
    simulate: bool,
) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise KeyError(job_id)
    results = []
    for act in job.get("actions") or []:
        if job.get("mode") == "all_safe" and act.get("risk") != "safe":
            act = deepcopy(act)
            act["status"] = "skipped"
            act["preview"] = "Skipped (all_safe mode)"
            results.append(act)
            continue
        results.append(
            apply_one(session, act, simulate=simulate, dry_run=True)
        )
    job["actions"] = results
    job["status"] = "dry_run"
    job["updated_at"] = utcnow()
    return _upsert_job(job)


def apply_job(
    job_id: str,
    session: boto3.Session | None,
    *,
    simulate: bool,
    only_safe: bool = False,
    confirm_dangerous: bool = False,
) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise KeyError(job_id)
    results = []
    for act in job.get("actions") or []:
        act = deepcopy(act)
        risk = act.get("risk") or "elevated"
        # Rebuild auto flag from rule_id (plans may have stale flags)
        rid = str(act.get("rule_id") or "")
        if not act.get("auto_applicable"):
            act["auto_applicable"] = _auto_applicable(rid)
        # Reset plan-time skipped so apply can run
        if act.get("status") in ("skipped", "planned", "dry_run_ok", "dry_run_fail"):
            if act.get("status") != "applied":
                act["error"] = None
                if act.get("status") != "dry_run_ok":
                    act["status"] = "planned"

        if only_safe and risk != "safe":
            act["status"] = "skipped"
            act["preview"] = (
                "Skipped: “Only safe fixes” is on. Uncheck it to apply elevated fixes "
                f"(this one is risk={risk})."
            )
            act["error"] = act["preview"]
            results.append(act)
            continue
        # Elevated applies without phrase; only dangerous needs APPLY
        if risk == "dangerous" and not confirm_dangerous:
            act["status"] = "skipped"
            act["error"] = (
                "Skipped: dangerous change — type APPLY in the confirm box, then Apply again."
            )
            results.append(act)
            continue
        if not act.get("auto_applicable") and not (act.get("aws_calls") or []):
            act["status"] = "skipped"
            act["error"] = "Not auto-applicable — copy the CLI hint and fix manually"
            results.append(act)
            continue
        # Ensure aws_calls exist by rebuilding from rule if missing
        if not act.get("aws_calls") and act.get("auto_applicable"):
            rebuilt = build_action_from_finding(
                {
                    "id": act.get("finding_id"),
                    "rule_id": act.get("rule_id"),
                    "resource": act.get("resource"),
                    "title": act.get("title"),
                    "remediation": act.get("cli_hint"),
                    "severity": act.get("severity"),
                    "service": act.get("service"),
                    "region": act.get("region"),
                }
            )
            act["aws_calls"] = rebuilt.aws_calls
            act["auto_applicable"] = rebuilt.auto_applicable

        results.append(apply_one(session, act, simulate=simulate, dry_run=False))

    job["actions"] = results
    job["status"] = "applied"
    job["updated_at"] = utcnow()
    job["rollback_available"] = any(a.get("status") == "applied" for a in results)
    return _upsert_job(job)


def rollback_job(
    job_id: str,
    session: boto3.Session | None,
    *,
    simulate: bool,
    action_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Restore environment as before the job (or selected actions)."""
    job = get_job(job_id)
    if not job:
        raise KeyError(job_id)
    id_set = set(action_ids or [])
    results = []
    for act in job.get("actions") or []:
        if id_set and act.get("action_id") not in id_set:
            results.append(act)
            continue
        if act.get("status") == "applied" or act.get("status") == "rollback_failed":
            results.append(rollback_one(session, act, simulate=simulate))
        else:
            results.append(act)
    job["actions"] = results
    job["status"] = "rolled_back"
    job["updated_at"] = utcnow()
    job["rollback_available"] = any(a.get("status") == "applied" for a in results)
    return _upsert_job(job)
