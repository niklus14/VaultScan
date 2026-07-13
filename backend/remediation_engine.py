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
        if mode == "all_safe" and action.risk != "safe":
            action.auto_applicable = False
            action.status = "skipped"
            action.preview = "Excluded from all_safe (not risk=safe). Select explicitly to plan apply."
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
            name = resource
            arns = [
                "arn:aws:iam::aws:policy/AdministratorAccess",
            ]
            # also try local AdministratorAccess by listing
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
                    for pol in iam.list_attached_role_policies(RoleName=name).get(
                        "AttachedPolicies", []
                    ):
                        if "AdministratorAccess" in (pol.get("PolicyName") or ""):
                            iam.detach_role_policy(
                                RoleName=name, PolicyArn=pol["PolicyArn"]
                            )
        elif rid in (
            "IAM-CLOUDTRAIL-DESTROY",
            "IAM-IMAGE-LEAK",
            "IAM-PRIVESC-NO-BOUNDARY",
        ):
            iam = session.client("iam")
            name = resource
            want = (a.get("snapshot") or {}).get("policy_name") or ""
            # from aws_calls
            for c in a.get("aws_calls") or []:
                want = c.get("params", {}).get("policy_name") or want
            detached = False
            for list_fn, detach_fn, key in (
                (
                    lambda: iam.list_attached_user_policies(UserName=name),
                    lambda arn: iam.detach_user_policy(UserName=name, PolicyArn=arn),
                    "AttachedPolicies",
                ),
                (
                    lambda: iam.list_attached_role_policies(RoleName=name),
                    lambda arn: iam.detach_role_policy(RoleName=name, PolicyArn=arn),
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
                except ClientError:
                    continue
            if not detached:
                raise RuntimeError(
                    "Could not find/detach matching managed policy — apply manually"
                )
        elif rid in (
            "IAM-TRUST-WILDCARD",
            "KMS-PUBLIC-POLICY",
            "SQS-PUBLIC-POLICY",
            "SM-PUBLIC-POLICY",
            "SM-OVERBROAD-POLICY",
            "IAM-NO-MFA",
        ):
            # Live AWS: suppress on next scan only after successful demo path;
            # for real accounts require manual for MFA/trust/KMS complexity —
            # still mark applied only if simulate already handled above.
            raise RuntimeError(
                f"{rid} requires manual/console steps in live AWS "
                f"(or use Demo mode for full auto demo). CLI: {a.get('cli_hint') or 'see finding'}"
            )
        else:
            a["status"] = "skipped"
            a["error"] = "No automated apply handler for this rule"
            return a

        a["status"] = "applied"
        a["error"] = None
        a["preview"] = f"Applied {rid} on {resource} in AWS"
        # Do NOT mark_fixed for live AWS — next scan must reflect real account state.
        # (Demo/simulate path marks fixed above.)
    except (ClientError, BotoCoreError, RuntimeError) as exc:
        a["status"] = "failed"
        err = str(exc)
        # Friendlier AccessDenied guidance
        if "AccessDenied" in err or "UnauthorizedOperation" in err or "not authorized" in err.lower():
            a["error"] = (
                f"AWS denied this write ({rid} on {resource}). "
                "Your Access Key / remediator role needs permission for this API "
                "(e.g. s3:PutBucketPublicAccessBlock, ec2:RevokeSecurityGroupIngress, iam:DetachRolePolicy). "
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
        risk = act.get("risk") or "elevated"
        # Re-enable actions that were only skipped at plan-time for all_safe display
        if act.get("status") == "skipped" and act.get("auto_applicable"):
            act = deepcopy(act)
            act["status"] = "planned"
            act["preview"] = None
            act["error"] = None
        if only_safe and risk != "safe":
            act = deepcopy(act)
            act["status"] = "skipped"
            act["preview"] = "Skipped (only safe fixes selected)"
            results.append(act)
            continue
        if risk == "dangerous" and not confirm_dangerous:
            act = deepcopy(act)
            act["status"] = "skipped"
            act["error"] = "Dangerous fix requires typing APPLY to confirm"
            results.append(act)
            continue
        if not act.get("auto_applicable"):
            act = deepcopy(act)
            act["status"] = "skipped"
            act["error"] = "Not auto-applicable — use CLI hint or Make as before after manual fix"
            results.append(act)
            continue
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
