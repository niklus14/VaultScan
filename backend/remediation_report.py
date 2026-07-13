
"""Build human-readable fix change reports (before → after + CLI + AI)."""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from remediation_engine import build_cli_commands, get_job, utcnow


def _brief_json(obj: Any, limit: int = 900) -> str:
    try:
        if obj is None:
            return "—"
        if isinstance(obj, str):
            try:
                obj = json.loads(obj)
            except json.JSONDecodeError:
                s = obj.strip()
                return s if len(s) <= limit else s[: limit - 1] + "…"
        s = json.dumps(obj, indent=2, default=str)
        return s if len(s) <= limit else s[: limit - 1] + "…"
    except Exception:  # noqa: BLE001
        return str(obj)[:limit]


def _describe_before(action: dict[str, Any]) -> str:
    rid = str(action.get("rule_id") or "").upper()
    snap = action.get("snapshot") or {}
    resource = action.get("resource") or "resource"

    if snap.get("missing"):
        return f"Resource {resource} was not found at snapshot time."

    if rid == "IAM-TRUST-WILDCARD":
        pol = snap.get("assume_role_policy")
        return (
            f"Trust policy on role allowed broad principals (often Principal *).\n"
            f"Snapshot:\n{_brief_json(pol)}"
        )
    if rid in ("IAM-ROLE-ADMIN", "IAM-ADMIN-POLICY") or rid.startswith("IAM-"):
        attached = snap.get("attached") or []
        names = [p.get("PolicyName") or p.get("PolicyArn") for p in attached]
        if names:
            return f"Attached managed policies on {resource}: {', '.join(str(n) for n in names)}"
        return f"IAM identity {resource} — policy attachments recorded at snapshot (or empty)."
    if rid.startswith("SG-OPEN") or rid == "SG-OPEN-ALL":
        return (
            f"Security group {resource} had open ingress (often 0.0.0.0/0).\n"
            f"Ingress snapshot:\n{_brief_json(snap.get('ip_permissions'))}"
        )
    if rid in ("S3-BPA-INCOMPLETE", "S3-BPA-MISSING"):
        return (
            f"Bucket public access block incomplete/missing.\n"
            f"Before: {_brief_json(snap.get('public_access_block'))}"
        )
    if rid == "S3-PUBLIC-POLICY":
        return f"Bucket policy before change:\n{_brief_json(snap.get('policy'))}"
    if rid == "EC2-IMDSV1":
        return f"Instance metadata options before: {_brief_json(snap.get('metadata_options'))}"
    if rid == "KMS-PUBLIC-POLICY":
        return f"KMS key policy before:\n{_brief_json(snap.get('key_policy'))}"
    if rid == "SQS-PUBLIC-POLICY":
        return f"SQS queue policy before:\n{_brief_json(snap.get('policy'))}"
    if rid in ("SM-PUBLIC-POLICY", "SM-OVERBROAD-POLICY"):
        return f"Secrets Manager resource policy before:\n{_brief_json(snap.get('resource_policy'))}"
    if snap:
        return f"Pre-change snapshot:\n{_brief_json(snap)}"
    return (
        f"No detailed snapshot stored for {rid} on {resource}. "
        "Before state = finding from the scan (misconfiguration present)."
    )


def _describe_changed(action: dict[str, Any]) -> str:
    status = action.get("status") or "planned"
    preview = (action.get("preview") or "").strip()
    summary = (action.get("summary") or "").strip()
    err = (action.get("error") or "").split("--- MANUAL CLI")[0].strip()

    if status == "applied":
        return preview or summary or f"Applied {action.get('rule_id')} on {action.get('resource')}"
    if status == "rolled_back":
        return preview or "Restored snapshot (Please make it as before)."
    if status == "failed":
        return f"Attempted change failed. {err or preview or summary}"
    if status == "skipped":
        return f"Skipped: {err or preview or 'not run'}"
    if status in ("dry_run_ok", "dry_run_fail"):
        return preview or "Dry-run only — AWS not modified."
    return summary or "Planned change (not applied yet)."


def _describe_after(action: dict[str, Any]) -> str:
    rid = str(action.get("rule_id") or "").upper()
    status = action.get("status") or ""
    resource = action.get("resource") or "resource"

    if status == "rolled_back":
        return "Configuration restored toward the pre-apply snapshot (lab may again show the original finding)."
    if status == "failed":
        return "Unchanged in AWS for this item (error blocked the write)."
    if status == "skipped":
        return "Unchanged — action was not executed."
    if status != "applied":
        return "Not applied yet — after state will appear once Apply succeeds."

    if rid == "IAM-TRUST-WILDCARD":
        return (
            f"Trust policy on {resource} no longer uses Principal *. "
            "Should allow only specific services/operators (e.g. EC2 + your Access Key user). "
            "Re-scan should clear IAM-TRUST-WILDCARD if * is gone."
        )
    if rid in ("IAM-ROLE-ADMIN", "IAM-ADMIN-POLICY"):
        return f"AdministratorAccess (or matching admin policy) detached from {resource}."
    if rid in ("IAM-CLOUDTRAIL-DESTROY", "IAM-IMAGE-LEAK", "IAM-PRIVESC-NO-BOUNDARY"):
        return f"Dangerous managed policy attachment removed from {resource} (see preview for names)."
    if rid.startswith("SG-OPEN"):
        return f"0.0.0.0/0 ingress rules revoked where possible on {resource}."
    if rid.startswith("S3-"):
        return f"S3 hardening applied on {resource} (BPA / ACL / policy / encryption / versioning as planned)."
    if rid == "EC2-IMDSV1":
        return f"IMDSv2 required on instance {resource}."
    if rid == "IAM-NO-MFA":
        return "MFA still requires a human device — not fully automated."
    return action.get("preview") or f"Live change applied for {rid} on {resource}."


def build_change_entries(job: dict[str, Any]) -> list[dict[str, Any]]:
    entries = []
    for a in job.get("actions") or []:
        a = dict(a)
        cli = a.get("cli_commands") or build_cli_commands(a)
        entries.append(
            {
                "action_id": a.get("action_id"),
                "rule_id": a.get("rule_id"),
                "resource": a.get("resource"),
                "title": a.get("title") or a.get("summary"),
                "summary": a.get("summary"),
                "risk": a.get("risk"),
                "severity": a.get("severity"),
                "status": a.get("status"),
                "before": _describe_before(a),
                "what_changed": _describe_changed(a),
                "after": _describe_after(a),
                "cli_commands": cli,
                "cli_text": "\n".join(cli) if isinstance(cli, list) else str(cli or ""),
                "ai_notes": a.get("ai_notes"),
                "preview": a.get("preview"),
                "error": (a.get("error") or "").split("--- MANUAL CLI")[0].strip() or None,
                "snapshot": a.get("snapshot") or {},
            }
        )
    return entries


def build_fix_report(
    job: dict[str, Any],
    *,
    ai_executive: str | None = None,
    ai_recommendations: list[str] | None = None,
) -> dict[str, Any]:
    entries = build_change_entries(job)
    applied = sum(1 for e in entries if e.get("status") == "applied")
    failed = sum(1 for e in entries if e.get("status") == "failed")
    rolled = sum(1 for e in entries if e.get("status") == "rolled_back")
    skipped = sum(1 for e in entries if e.get("status") == "skipped")

    score_b = job.get("score_before")
    score_a = job.get("score_after")
    delta = None
    if isinstance(score_b, (int, float)) and isinstance(score_a, (int, float)):
        delta = round(float(score_a) - float(score_b), 1)

    if not ai_executive:
        parts = [
            f"Job {job.get('job_id')} processed {len(entries)} remediation action(s): "
            f"{applied} applied, {failed} failed, {skipped} skipped, {rolled} restored."
        ]
        if delta is not None:
            direction = "improved" if delta > 0 else "declined" if delta < 0 else "unchanged"
            parts.append(
                f"Posture score {direction}: {score_b} → {score_a} (Δ {delta:+})."
            )
        if failed:
            parts.append(
                "Failed items usually mean AccessDenied (role lacks IAM write), "
                "wrong account session, or manual-only steps (e.g. MFA). "
                "Use the CLI section for each failed action."
            )
        if applied:
            parts.append(
                "Applied changes used live AWS with snapshots so "
                "“Please make it as before” can restore prior config when permissions allow."
            )
        ai_executive = " ".join(parts)

    recs = ai_recommendations or []
    if not recs:
        recs = [
            "Re-scan after apply to confirm findings cleared.",
            "If AssumeRole fails after trust fixes, keep your operator user ARN on the role trust (not *).",
            "If AccessDenied on IAM writes, attach AdministratorAccess or iam:UpdateAssumeRolePolicy to the lab role.",
            "Use Please make it as before only when the role still has write permission to restore snapshots.",
        ]

    full_cli = job.get("cli_script") or "\n\n".join(
        e["cli_text"] for e in entries if e.get("cli_text")
    )

    return {
        "report_id": f"FIXRPT-{(job.get('job_id') or 'NA')}",
        "generated_at": utcnow(),
        "job_id": job.get("job_id"),
        "scan_id": job.get("scan_id"),
        "job_status": job.get("status"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "score_before": score_b,
        "score_after": score_a,
        "score_delta": delta,
        "counts": {
            "total": len(entries),
            "applied": applied,
            "failed": failed,
            "skipped": skipped,
            "rolled_back": rolled,
        },
        "executive_summary": ai_executive,
        "recommendations": recs,
        "changes": entries,
        "cli_script": full_cli,
        "ai_used": False,
    }
