#!/usr/bin/env python3
"""
VaultScan CSPM API
──────────────────
FastAPI backend for the cspm-dashboard-design frontend.

  • Settings UI stores AWS connection credentials server-side
  • Scans via AssumeRole / direct keys / simulate
  • Grok summaries + security assistant
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from aws_client import get_remediate_session, get_scan_session, probe_connection
from config import settings
import connection_store
from grok_client import (
    GrokError,
    assistant_reply,
    enrich_attack_paths,
    enrich_fix_actions,
    generate_report_narrative,
    summarize_scan,
)
from report_export import build_report_context, export_docx, export_pdf
import remediation_engine
import scan_persistence
from scanner_engine import run_scan

app = FastAPI(
    title="VaultScan CSPM API",
    version="1.3.0",
    description="Cloud connection settings, real AWS scanning, Cloud Assistant, AI remediation",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load persisted scans so reports/PDF work after restart without a new scan
scan_history, latest_scan = scan_persistence.load_scans()


class ScanRequest(BaseModel):
    mode: Literal["assume_role", "direct", "simulate"] | None = None
    role_arn: str | None = None
    external_id: str | None = None
    region: str | None = None


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"] = "user"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = Field(default_factory=list)
    scan_id: str | None = None


class SummarizeRequest(BaseModel):
    scan_id: str | None = None
    force_refresh: bool = False


class ConnectionSettingsUpdate(BaseModel):
    connection_name: str | None = None
    provider: Literal["aws", "gcp"] | None = None
    auth_mode: Literal["assume_role", "direct", "simulate"] | None = None
    role_arn: str | None = None
    external_id: str | None = None
    region: str | None = None
    session_name: str | None = None
    access_key_id: str | None = Field(
        default=None,
        description="IAM Access Key ID. Leave empty to keep the existing value.",
    )
    secret_access_key: str | None = Field(
        default=None,
        description="IAM Secret Access Key. Leave empty to keep the existing value.",
    )
    session_token: str | None = Field(
        default=None,
        description="Optional temporary session token. Leave empty to keep existing.",
    )
    gcp_project_id: str | None = None
    gcp_service_account_email: str | None = None
    gcp_service_account_json: str | None = Field(
        default=None,
        description="Full GCP service account JSON. Leave empty to keep existing.",
    )
    clear_credentials: bool = False
    clear_session_token: bool = False


def _find_scan(scan_id: str | None) -> dict[str, Any] | None:
    """Find scan in memory, then on disk. Never requires a brand-new scan."""
    found = scan_persistence.get_scan(scan_id, scan_history, latest_scan)
    if found and found not in scan_history:
        # Re-hydrate memory from disk so subsequent calls are fast
        if not any(s.get("scan_id") == found.get("scan_id") for s in scan_history):
            scan_history.insert(0, found)
    return found


def _build_report_package(scan: dict[str, Any], narrative: dict[str, str]) -> dict[str, Any]:
    service_counts: dict[str, int] = {}
    for v in scan.get("vulnerabilities") or scan.get("findings") or []:
        svc = str(v.get("service") or "OTHER")
        service_counts[svc] = service_counts.get(svc, 0) + 1
    by_service = [
        {"service": k, "count": c}
        for k, c in sorted(service_counts.items(), key=lambda x: -x[1])
    ]
    summary = scan.get("summary") or {}
    by_severity = [
        {"severity": sev, "count": int(summary.get(sev, 0)), "label": label}
        for sev, label in [
            ("CRITICAL", "Critical — fix immediately"),
            ("HIGH", "High — fix this week"),
            ("MEDIUM", "Medium — plan remediation"),
            ("LOW", "Low — harden when possible"),
        ]
    ]
    findings_table = []
    for f in scan.get("vulnerabilities") or scan.get("findings") or []:
        findings_table.append(
            {
                "resource": f.get("id") or f.get("resource"),
                "service": f.get("service"),
                "severity": f.get("severity"),
                "title": f.get("title") or "",
                "description": f.get("description") or "",
                "remediation": f.get("remediation") or "",
                "compliance": f.get("compliance") or [],
                "why_it_matters": _why_it_matters(f),
            }
        )
    return {
        "scan_id": scan["scan_id"],
        "generated_at": scan.get("timestamp"),
        "narrative": narrative,
        "metrics": {
            "score": scan.get("score"),
            "total_findings": scan.get("total_findings"),
            "summary": summary,
            "account_id": scan.get("account_id"),
            "region": scan.get("region"),
            "mode": scan.get("mode"),
            "role_arn": scan.get("role_arn"),
        },
        "charts": {
            "by_severity": by_severity,
            "by_service": by_service,
        },
        "findings_table": findings_table,
        "compliance": scan.get("compliance") or [],
        "remediation": scan.get("remediation") or {},
        "glossary": [
            {
                "term": "Posture score",
                "meaning": "0–100 health score. 100 means no known misconfigurations in this scan.",
            },
            {
                "term": "Critical",
                "meaning": "Actively dangerous exposure (e.g. public data or world-open admin ports).",
            },
            {
                "term": "High",
                "meaning": "Serious weakness that attackers often chain with other issues.",
            },
            {
                "term": "Medium / Low",
                "meaning": "Hardening and compliance gaps; less urgent but still important.",
            },
            {
                "term": "CIS / NIST / GDPR",
                "meaning": "Industry and legal frameworks. Findings map to rules auditors care about.",
            },
        ],
    }


def _connection_payload(info, *, mode: str) -> dict[str, Any]:
    return {
        "connected": info.error is None and mode != "simulate",
        "mode": info.mode,
        "account_id": info.account_id,
        "arn": info.arn,
        "role_arn": info.role_arn,
        "region": info.region,
        "connection_name": info.connection_name,
        "error": info.error,
        "hint": (
            None
            if info.error is None
            else (
                "Open Settings → Cloud Connection to add credentials, "
                "verify the Role ARN trust policy, or switch to Demo mode."
            )
        ),
    }


# Bump when real-AWS apply path changes so we can confirm the right build is live.
CODE_VERSION = "2026-07-14-trust-keep-operator-v6"


@app.get("/api/health")
def health():
    view = connection_store.public_view()
    return {
        "ok": True,
        "service": "vaultscan-api",
        "code_version": CODE_VERSION,
        "trust_apply": "live_boto3",  # IAM-TRUST-WILDCARD uses UpdateAssumeRolePolicy
        "grok_configured": bool(settings.grok_api_key),
        "default_role_arn": view.get("role_arn"),
        "region": view.get("region"),
        "credentials_configured": view.get("credentials_configured"),
        "ready_to_scan": view.get("ready_to_scan"),
        "scans_cached": len(scan_history),
    }


# ─── Settings: Cloud Connection ───────────────────────────────────────────────

@app.get("/api/settings/connection")
def get_connection_settings():
    """Return connection settings for the product UI (secrets masked)."""
    return connection_store.public_view()


@app.put("/api/settings/connection")
def put_connection_settings(body: ConnectionSettingsUpdate):
    """Save connection settings from the Settings page."""
    payload = body.model_dump(exclude_unset=True)
    try:
        connection_store.update_profile(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "message": "Connection settings saved.",
        "connection": connection_store.public_view(),
    }


@app.post("/api/settings/connection/test")
def test_connection_settings():
    """Validate saved credentials (AWS STS / GCP service account)."""
    rt = connection_store.resolve_runtime()
    provider = rt.get("provider") or "aws"
    mode = rt["auth_mode"]

    if provider == "gcp" and mode != "simulate":
        ok, msg, project = connection_store.test_gcp_connection()
        connection_store.record_test_result(
            ok=ok,
            message=msg,
            account_id=project,
            caller_arn=rt.get("gcp_service_account_email") or None,
        )
        return {
            "ok": ok,
            "message": msg,
            "connection": {
                "connected": ok,
                "mode": mode,
                "account_id": project,
                "arn": rt.get("gcp_service_account_email"),
                "role_arn": None,
                "region": rt.get("region"),
                "connection_name": rt.get("connection_name"),
                "error": None if ok else msg,
                "hint": None
                if ok
                else "Check Project ID and paste a full service account JSON key.",
            },
            "settings": connection_store.public_view(),
        }

    info = probe_connection(
        mode=mode,
        role_arn=rt.get("role_arn"),
        external_id=rt.get("external_id") or None,
        region=rt.get("region"),
    )
    ok = info.error is None
    if mode == "simulate":
        msg = "Demo mode is active — no live cloud connection is used."
        ok = True
    elif ok:
        msg = (
            f"Connected successfully"
            + (f" as account {info.account_id}" if info.account_id else "")
            + "."
        )
    else:
        msg = info.error or "Connection failed."

    connection_store.record_test_result(
        ok=True if mode == "simulate" else ok,
        message=msg,
        account_id=info.account_id,
        caller_arn=info.arn,
    )
    return {
        "ok": ok if mode != "simulate" else True,
        "message": msg,
        "connection": _connection_payload(info, mode=mode),
        "settings": connection_store.public_view(),
    }


@app.delete("/api/settings/connection/credentials")
def clear_connection_credentials():
    """Remove stored Access Key / Secret from the server."""
    connection_store.update_profile({"clear_credentials": True})
    return {
        "ok": True,
        "message": "Stored AWS access keys were removed.",
        "connection": connection_store.public_view(),
    }


@app.get("/api/connection")
def connection(
    mode: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
):
    """Probe connectivity using saved Settings (optional query overrides)."""
    rt = connection_store.resolve_runtime()
    use_mode = mode or rt["auth_mode"]
    info = probe_connection(
        mode=use_mode,
        role_arn=role_arn or rt.get("role_arn"),
        external_id=external_id if external_id is not None else (rt.get("external_id") or None),
        region=region or rt.get("region"),
    )
    return _connection_payload(info, mode=use_mode)


@app.post("/api/scan")
def api_scan(body: ScanRequest | None = None):
    """Run a scan using Settings credentials (body fields optional overrides)."""
    global latest_scan
    try:
        body = body or ScanRequest()
        rt = connection_store.resolve_runtime()

        mode = body.mode or rt["auth_mode"]
        role_arn = body.role_arn or rt.get("role_arn")
        external_id = (
            body.external_id
            if body.external_id is not None
            else (rt.get("external_id") or None)
        )
        region = body.region or rt.get("region") or "us-east-1"

        result = run_scan(
            mode=mode,
            role_arn=role_arn,
            external_id=external_id,
            region=region,
        )
        # Demo only: hide findings applied in simulate until Make as before.
        # Real AWS re-scan always reflects the live account (no fake suppress).
        if mode == "simulate":
            fixed = remediation_engine.get_simulate_fixed()
            if fixed:
                findings = [
                    f
                    for f in (result.get("findings") or [])
                    if not remediation_engine.finding_is_fixed(f, fixed)
                ]
                result["findings"] = findings
                result["total_findings"] = len(findings)
                summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for f in findings:
                    sev = f.get("severity")
                    if sev in summary:
                        summary[sev] += 1
                result["summary"] = summary
                from scanner_engine import compute_score

                result["score"] = compute_score(findings)
                result["vulnerabilities"] = [
                    {
                        "id": f.get("id") or f.get("resource"),
                        "service": f.get("service"),
                        "severity": f.get("severity"),
                        "description": f.get("description"),
                        "title": f.get("title"),
                        "remediation": f.get("remediation"),
                        "compliance": f.get("compliance"),
                        "rule_id": f.get("rule_id"),
                        "region": f.get("region"),
                    }
                    for f in findings
                ]
        else:
            # Normalize vulnerability ids for Fix matching
            result["vulnerabilities"] = [
                {
                    "id": f.get("id") or f.get("resource"),
                    "service": f.get("service"),
                    "severity": f.get("severity"),
                    "description": f.get("description"),
                    "title": f.get("title"),
                    "remediation": f.get("remediation"),
                    "compliance": f.get("compliance"),
                    "rule_id": f.get("rule_id"),
                    "region": f.get("region"),
                }
                for f in (result.get("findings") or [])
            ]
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail={
                "error": str(exc),
                "hint": (
                    "Open Settings → Cloud Connection to fix credentials or Role ARN. "
                    "You can also enable Demo mode to try the product without AWS."
                ),
            },
        ) from exc

    latest_scan = result
    scan_history.insert(0, result)
    if len(scan_history) > 50:
        del scan_history[50:]
    # Persist so reopen + PDF work without a new scan
    scan_persistence.save_scan(result, scan_history)

    return result


@app.get("/api/scans")
def list_scans():
    light = []
    for s in scan_history:
        light.append(
            {
                "id": s["scan_id"],
                "scan_id": s["scan_id"],
                "timestamp": s["timestamp"],
                "score": s["score"],
                "critical": s["summary"].get("CRITICAL", 0),
                "summary": s["summary"],
                "mode": s["mode"],
                "account_id": s.get("account_id"),
                "region": s.get("region"),
                "total_findings": s.get("total_findings", 0),
            }
        )
    return {"scans": light, "count": len(light)}


@app.get("/api/scans/latest")
def get_latest():
    s = _find_scan(None)
    if not s:
        raise HTTPException(status_code=404, detail="No scans yet. Run a scan first.")
    return s


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    s = _find_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return s


@app.post("/api/ai/summarize")
async def ai_summarize(body: SummarizeRequest):
    scan = _find_scan(body.scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No scan available to summarize. Run a scan first.",
        )
    try:
        summary = await summarize_scan(scan)
    except GrokError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "scan_id": scan["scan_id"],
        "summary": summary,
        "model": "cloud-assistant",
    }


@app.post("/api/ai/attack-paths")
async def ai_attack_paths(body: SummarizeRequest):
    """
    Return attack paths for a scan, enriched with Cloud Assistant narrative.
    Uses deterministic chains from the scan, then AI storytelling (no invented resources).
    """
    from attack_paths import build_attack_paths

    scan = _find_scan(body.scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No scan available. Run a scan first.",
        )
    raw_paths = scan.get("attack_paths") or build_attack_paths(
        scan.get("findings") or scan.get("vulnerabilities") or []
    )
    paths = await enrich_attack_paths(raw_paths, scan=scan)
    # cache on scan object in memory for session
    scan["attack_paths"] = paths
    return {
        "scan_id": scan["scan_id"],
        "paths": paths,
        "count": len(paths),
        "ai_used": any(p.get("ai_enriched") for p in paths),
    }


async def _report_bundle(
    scan_id: str | None = None,
    *,
    force_refresh: bool = False,
) -> tuple[dict, dict[str, str], dict[str, Any] | None]:
    """
    Load scan + narrative for UI/export.

    Reuses a cached report package when the scan has not changed, so reopening
    the report or downloading PDF does not require a new scan.
    """
    scan = _find_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail=(
                "No saved scan found. Run a scan once; afterward you can reopen "
                "the report and export PDF/Word anytime without scanning again."
            ),
        )

    cached = None if force_refresh else scan_persistence.load_report_package(scan["scan_id"])
    if cached and cached.get("narrative"):
        return scan, cached["narrative"], cached

    narrative = await generate_report_narrative(scan)
    package = _build_report_package(scan, narrative)
    scan_persistence.save_report_package(scan["scan_id"], package)
    return scan, narrative, package


@app.get("/api/report/export/pdf")
async def export_report_pdf(
    scan_id: str | None = Query(default=None),
    refresh: bool = Query(default=False),
):
    """Export PDF for an existing scan (default: latest). No new scan required."""
    scan, narrative, _pkg = await _report_bundle(scan_id, force_refresh=refresh)
    ctx = build_report_context(scan, narrative)
    data = export_pdf(ctx)
    filename = f"VaultScan_{ctx['scan_id']}.pdf"
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/report/export/docx")
async def export_report_docx(
    scan_id: str | None = Query(default=None),
    refresh: bool = Query(default=False),
):
    """Export Word doc for an existing scan (default: latest). No new scan required."""
    scan, narrative, _pkg = await _report_bundle(scan_id, force_refresh=refresh)
    ctx = build_report_context(scan, narrative)
    data = export_docx(ctx)
    filename = f"VaultScan_{ctx['scan_id']}.docx"
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/ai/report")
async def ai_report(body: SummarizeRequest):
    """
    Build or reload a full report package for the UI.

    Uses the last saved scan when scan_id is omitted. Cached packages are
    returned when available so closing/reopening the report does not require
    a new scan. Pass force_refresh=true only when the user clicks Regenerate.
    """
    scan, _narrative, package = await _report_bundle(
        body.scan_id,
        force_refresh=body.force_refresh,
    )
    if package is None:
        package = _build_report_package(scan, _narrative)
        scan_persistence.save_report_package(scan["scan_id"], package)
    return package


@app.get("/api/report/latest")
def get_latest_report():
    """Return the last saved report package without regenerating AI text."""
    pkg = scan_persistence.load_report_package(None)
    if pkg:
        return pkg

    scan = _find_scan(None)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No report yet. Run a scan and open Generate Report once.",
        )

    score = int(scan.get("score") or 0)
    if score >= 90:
        risk = "LOW"
    elif score >= 70:
        risk = "MODERATE"
    elif score >= 40:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    narrative = {
        "headline": f"Cloud security posture is {risk.lower()} ({score}/100)",
        "risk_level": risk,
        "executive_summary": (
            f"VaultScan found {scan.get('total_findings', 0)} issue(s) in this environment "
            f"(score {score}/100). Reopen Generate Report or click Regenerate for a full "
            "Cloud Assistant narrative."
        ),
        "what_this_means": (
            "This is your last saved scan. You can download PDF/Word anytime. "
            "Run a new scan only when you want updated findings."
        ),
        "priority_actions": (
            "1. Review the findings table.\n"
            "2. Remediate critical and high issues.\n"
            "3. Re-scan only after changes to verify."
        ),
        "technical_notes": (
            "Cached scan view from disk. Use Regenerate for a fresh Cloud Assistant brief."
        ),
    }
    pkg = _build_report_package(scan, narrative)
    scan_persistence.save_report_package(scan["scan_id"], pkg)
    return pkg


def _why_it_matters(finding: dict[str, Any]) -> str:
    sev = str(finding.get("severity") or "").upper()
    service = str(finding.get("service") or "").upper()
    title = str(finding.get("title") or finding.get("description") or "").lower()

    if "public" in title or "0.0.0.0" in title or "world" in title:
        return "Anyone on the internet may reach this resource without being your employee or customer."
    if "encrypt" in title:
        return "If disks or objects are stolen or copied, data may be readable without a key."
    if "mfa" in title:
        return "A stolen password alone could let an attacker sign in as this identity."
    if "admin" in title or "permissive" in title or "*" in title:
        return "If this identity is compromised, the attacker may control large parts of the account."
    if service == "S3":
        return "Storage misconfigurations are a leading cause of cloud data breaches."
    if service == "EC2":
        return "Network exposure on compute often leads to intrusion and lateral movement."
    if service == "IAM":
        return "Identity weaknesses turn a small compromise into full account takeover."
    if service == "RDS":
        return "Database exposure can leak customer or business-critical records."
    if sev == "CRITICAL":
        return "Highest priority — treat as an active security incident until fixed."
    if sev == "HIGH":
        return "Should be fixed soon; increases risk of breach or audit failure."
    return "Improves resilience and compliance; schedule alongside other hardening work."


@app.post("/api/ai/chat")
async def ai_chat(body: ChatRequest):
    scan = _find_scan(body.scan_id)
    history = [m.model_dump() for m in body.history]
    try:
        reply = await assistant_reply(body.message, history=history, scan=scan)
    except GrokError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "reply": reply,
        "model": settings.grok_model,
        "scan_id": scan.get("scan_id") if scan else None,
    }


@app.get("/api/config/public")
def public_config():
    view = connection_store.public_view()
    return {
        "default_role_arn": view.get("role_arn"),
        "default_region": view.get("region"),
        "auth_mode": view.get("auth_mode"),
        "connection_name": view.get("connection_name"),
        "credentials_configured": view.get("credentials_configured"),
        "ready_to_scan": view.get("ready_to_scan"),
        "grok_enabled": bool(settings.grok_api_key),
        "grok_model": settings.grok_model if settings.grok_api_key else None,
        "remediation_enabled": True,
    }


# ─── AI remediation (plan → dry-run → apply → make as before) ────────────────


class RemediatePlanRequest(BaseModel):
    scan_id: str | None = None
    finding_ids: list[str] | None = None
    mode: Literal["all_safe", "selected", "all"] = "all_safe"
    use_ai: bool = True


class RemediateJobRequest(BaseModel):
    job_id: str
    # Apply gates
    confirm: bool = False
    confirm_phrase: str | None = None
    only_safe: bool = False
    allow_write_with_scan_creds: bool = False
    rescan: bool = True
    # Optional re-hydrate for Vercel (ephemeral /tmp may lose Settings between calls)
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    role_arn: str | None = None
    auth_mode: Literal["assume_role", "direct", "simulate"] | None = None
    region: str | None = None
    external_id: str | None = None


class RemediateRollbackRequest(BaseModel):
    job_id: str
    action_ids: list[str] | None = None
    confirm: bool = False
    confirm_phrase: str | None = None
    allow_write_with_scan_creds: bool = False
    rescan: bool = True
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    role_arn: str | None = None
    auth_mode: Literal["assume_role", "direct", "simulate"] | None = None
    region: str | None = None
    external_id: str | None = None


def _hydrate_connection_from_body(body: object) -> None:
    """Merge optional AWS secrets from the request into the runtime store."""
    payload: dict[str, Any] = {}
    for key in (
        "access_key_id",
        "secret_access_key",
        "session_token",
        "role_arn",
        "auth_mode",
        "region",
        "external_id",
    ):
        val = getattr(body, key, None)
        if val is not None and str(val).strip() != "":
            payload[key] = val
    if not payload:
        return
    try:
        connection_store.update_profile(payload)
    except ValueError as exc:
        # Still try to stash keys if only role ARN validation failed mid-save
        if payload.get("access_key_id") or payload.get("secret_access_key"):
            try:
                connection_store.update_profile(
                    {
                        k: v
                        for k, v in payload.items()
                        if k in ("access_key_id", "secret_access_key", "session_token", "region")
                    }
                )
            except ValueError:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        else:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


def _remediate_session(allow_write_with_scan_creds: bool = False):
    """Return (session|None, simulate: bool, error: str|None, mode_label: str)."""
    session, label, err = get_remediate_session(
        allow_write=allow_write_with_scan_creds,
    )
    if label == "simulate":
        return None, True, None, label
    return session, False, err, label


def _maybe_rescan(do_rescan: bool) -> dict[str, Any] | None:
    if not do_rescan:
        return None
    rt = connection_store.resolve_runtime()
    body = ScanRequest(
        mode=rt.get("auth_mode"),
        role_arn=rt.get("role_arn"),
        external_id=rt.get("external_id") or None,
        region=rt.get("region"),
    )
    return api_scan(body)


@app.post("/api/remediate/plan")
async def remediate_plan(body: RemediatePlanRequest):
    """Build a fix plan for scan findings (registry + optional AI notes)."""
    scan = _find_scan(body.scan_id)
    if not scan and body.mode != "all_safe":
        # still allow empty plan messaging
        pass
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="No scan available. Run a scan first, then plan fixes.",
        )
    job = remediation_engine.plan_from_scan(
        scan,
        finding_ids=body.finding_ids,
        mode=body.mode,
    )
    ai_used = False
    if body.use_ai and settings.grok_api_key:
        try:
            enriched = await enrich_fix_actions(job.get("actions") or [], scan)
            job["actions"] = enriched
            job["ai_used"] = True
            ai_used = True
            job = remediation_engine._upsert_job(job)
        except Exception:
            pass
    return {
        "ok": True,
        "job": job,
        "ai_used": ai_used or bool(job.get("ai_used")),
        "counts": {
            "total": len(job.get("actions") or []),
            "auto": sum(
                1 for a in (job.get("actions") or []) if a.get("auto_applicable")
            ),
            "safe": sum(
                1 for a in (job.get("actions") or []) if a.get("risk") == "safe"
            ),
        },
    }


@app.post("/api/remediate/dry-run")
def remediate_dry_run(body: RemediateJobRequest):
    session, simulate, err, label = _remediate_session(
        allow_write_with_scan_creds=True
    )
    if err and not simulate:
        session = None
        simulate = True
        label = "preview_only"
    try:
        job = remediation_engine.dry_run_job(
            body.job_id, session, simulate=simulate
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation job not found") from None
    return {"ok": True, "job": job, "session_mode": label}


@app.post("/api/remediate/apply")
def remediate_apply(body: RemediateJobRequest):
    """
    Apply planned fixes against real AWS.

    With Access Key + Secret + Role ARN (normal lab): AssumeRole into that Role ARN
    first (same account as scan findings), then write. Base keys alone are only used
    when auth_mode=direct.
    """
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set confirm=true to apply remediations.",
        )
    _hydrate_connection_from_body(body)
    confirm_dangerous = (body.confirm_phrase or "").strip().upper() == "APPLY"
    session, simulate, err, label = _remediate_session(
        allow_write_with_scan_creds=bool(body.allow_write_with_scan_creds)
        if body.allow_write_with_scan_creds is not None
        else True
    )
    # Force allow when client forgot the flag but has real keys — Apply means write
    if err and "allow_write" in (err or ""):
        session, simulate, err, label = _remediate_session(allow_write_with_scan_creds=True)
    if err:
        raise HTTPException(
            status_code=403,
            detail={
                "error": err,
                "hint": (
                    "REAL AWS only: Settings → Access Key ID + Secret Access Key + Role ARN "
                    "(auth mode Assume Role). Save, Test Connection, then re-scan. "
                    "On Vercel, re-save after idle (server /tmp storage is ephemeral). "
                    "Apply AssumeRoles into that Role ARN so GetRole/fixes hit the lab account."
                ),
            },
        )
    try:
        job = remediation_engine.apply_job(
            body.job_id,
            session,
            simulate=simulate,
            only_safe=body.only_safe,
            confirm_dangerous=confirm_dangerous,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation job not found") from None

    applied = sum(1 for a in (job.get("actions") or []) if a.get("status") == "applied")
    failed = [a for a in (job.get("actions") or []) if a.get("status") == "failed"]
    skipped = sum(1 for a in (job.get("actions") or []) if a.get("status") == "skipped")

    rescan = None
    try:
        rescan = _maybe_rescan(body.rescan)
        if rescan and isinstance(rescan, dict) and "score" in rescan:
            job["score_after"] = rescan.get("score")
            job = remediation_engine._upsert_job(job)
    except Exception as exc:  # noqa: BLE001
        rescan = {"error": str(exc)}

    cli_script = job.get("cli_script") or remediation_engine.cli_script_for_actions(
        job.get("actions") or []
    )
    job["cli_script"] = cli_script

    if applied == 0:
        first_err = (
            (failed[0].get("error") if failed else None)
            or (failed[0].get("preview") if failed else None)
            or "All actions skipped — uncheck only-safe and type APPLY for dangerous items."
        )
        # Shorten top banner — full CLI is in job.cli_script
        short = (first_err or "").split("\n")[0][:220]
        return {
            "ok": False,
            "job": job,
            "rescan": rescan,
            "session_mode": label,
            "code_version": CODE_VERSION,
            "cli_script": cli_script,
            "message": (
                f"No AWS auto-changes ({skipped} skipped, {len(failed)} failed) "
                f"[session={label}] [build={CODE_VERSION}]. {short} "
                "Copy the MANUAL CLI SCRIPT below and run it with lab-account AWS credentials."
            ),
        }

    fail_note = ""
    if failed:
        fail_note = f" {len(failed)} failed — use MANUAL CLI SCRIPT for those."
    return {
        "ok": True,
        "job": job,
        "rescan": rescan,
        "session_mode": label,
        "code_version": CODE_VERSION,
        "cli_script": cli_script,
        "message": (
            f"Applied {applied} fix(es) via {label}.{fail_note} "
            "Re-scan uses live AWS. Please make it as before undoes this job when snapshots exist."
        ),
    }


@app.post("/api/remediate/rollback")
def remediate_rollback(body: RemediateRollbackRequest):
    """Restore resources as they were before this job (make as before)."""
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set confirm=true to roll back (make as before).",
        )
    if (body.confirm_phrase or "").strip().upper() not in ("APPLY", "ROLLBACK", "RESTORE"):
        raise HTTPException(
            status_code=400,
            detail='confirm_phrase must be "ROLLBACK" (or APPLY/RESTORE) to restore previous state.',
        )
    session, simulate, err, label = _remediate_session(
        allow_write_with_scan_creds=True
    )
    if err:
        raise HTTPException(status_code=403, detail={"error": err})
    try:
        job = remediation_engine.rollback_job(
            body.job_id,
            session,
            simulate=simulate,
            action_ids=body.action_ids,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation job not found") from None

    rescan = None
    try:
        rescan = _maybe_rescan(body.rescan)
        if rescan and isinstance(rescan, dict) and "score" in rescan:
            job["score_after"] = rescan.get("score")
            job = remediation_engine._upsert_job(job)
    except Exception as exc:  # noqa: BLE001
        rescan = {"error": str(exc)}

    return {
        "ok": True,
        "job": job,
        "rescan": rescan,
        "session_mode": label,
        "message": "Restored previous configuration where snapshots allowed (Please make it as before).",
    }


@app.get("/api/remediate/jobs")
def remediate_jobs():
    return {"jobs": remediation_engine.list_jobs()}


@app.get("/api/remediate/jobs/{job_id}")
def remediate_job(job_id: str):
    job = remediation_engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


if __name__ == "__main__":
    import uvicorn

    print("\n" + "=" * 60)
    print("  VaultScan CSPM API")
    print(f"  http://{settings.api_host}:{settings.api_port}")
    print(f"  Grok: {'configured' if settings.grok_api_key else 'MISSING KEY'}")
    print("  Configure AWS from the product Settings page.")
    print("=" * 60 + "\n")
    uvicorn.run(
        "app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
