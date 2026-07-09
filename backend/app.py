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

from aws_client import probe_connection
from config import settings
import connection_store
from grok_client import (
    GrokError,
    assistant_reply,
    generate_report_narrative,
    summarize_scan,
)
from report_export import build_report_context, export_docx, export_pdf
import scan_persistence
from scanner_engine import run_scan

app = FastAPI(
    title="VaultScan CSPM API",
    version="1.2.0",
    description="Cloud connection settings, real AWS scanning, Cloud Assistant reports",
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


@app.get("/api/health")
def health():
    view = connection_store.public_view()
    return {
        "ok": True,
        "service": "vaultscan-api",
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
    """Validate saved credentials by calling STS (AssumeRole or GetCallerIdentity)."""
    rt = connection_store.resolve_runtime()
    mode = rt["auth_mode"]
    info = probe_connection(
        mode=mode,
        role_arn=rt.get("role_arn"),
        external_id=rt.get("external_id") or None,
        region=rt.get("region"),
    )
    ok = info.error is None
    if mode == "simulate":
        msg = "Demo mode is active — no live AWS connection is used."
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

    try:
        result = run_scan(
            mode=mode,
            role_arn=role_arn,
            external_id=external_id,
            region=region,
        )
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
    }


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
