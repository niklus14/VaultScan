"""
Scheduled scan + email alert settings (server-side).

Used by the in-process scheduler (local / always-on API) and Settings UI.
"""
from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _resolve_data_dir() -> Path:
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return Path(os.environ.get("VAULTSCAN_DATA_DIR", "/tmp/vaultscan-data"))
    return Path(os.environ.get("VAULTSCAN_DATA_DIR", Path(__file__).resolve().parent / "data"))


_DATA_DIR = _resolve_data_dir()
_STORE_PATH = _DATA_DIR / "schedule.json"
_LOCK = threading.Lock()
_SECRET_PLACEHOLDERS = {"", "••••••••", "********", "unchanged", "__UNCHANGED__"}

# Any positive interval is allowed (UI free-entry). Soft bounds for safety.
MIN_INTERVAL_MINUTES = 1
MAX_INTERVAL_MINUTES = 10080  # 7 days


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _default() -> dict[str, Any]:
    return {
        "enabled": False,
        "interval_minutes": 60,
        "email_enabled": False,
        "recipients": "",
        "gmail_address": "",
        "gmail_app_password": "",
        # Shown in Gmail inbox as the sender name (From: Name <email>)
        "from_name": "VaultScan Company",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        # always | any_findings | high_or_critical | critical_only
        "alert_when": "high_or_critical",
        "include_finding_details": True,
        "last_run_at": None,
        "next_run_at": None,
        "last_run_status": "never",  # never | ok | failed | skipped
        "last_run_message": None,
        "last_email_status": "never",
        "last_email_message": None,
        "last_email_at": None,
        "run_count": 0,
        "updated_at": None,
    }


def _read() -> dict[str, Any]:
    if not _STORE_PATH.exists():
        return _default()
    try:
        with _STORE_PATH.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            return _default()
        base = _default()
        base.update(raw)
        return base
    except (json.JSONDecodeError, OSError):
        return _default()


def _write(data: dict[str, Any]) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _STORE_PATH.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
        fh.write("\n")
    os.replace(tmp, path := _STORE_PATH)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load() -> dict[str, Any]:
    with _LOCK:
        return deepcopy(_read())


def save(profile: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        _write(profile)
        return deepcopy(profile)


def public_view(profile: dict[str, Any] | None = None) -> dict[str, Any]:
    p = profile if profile is not None else load()
    recipients = p.get("recipients") or ""
    if isinstance(recipients, list):
        recipients = ", ".join(str(x) for x in recipients if x)

    serverless = bool(
        os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    )
    return {
        "enabled": bool(p.get("enabled")),
        "interval_minutes": int(p.get("interval_minutes") or 60),
        "email_enabled": bool(p.get("email_enabled")),
        "recipients": recipients,
        # Company sender is fixed in server config — never expose password to UI
        "sender_display": "VaultScan Company",
        "system_sender_ready": True,
        "from_name": "VaultScan Company",
        "alert_when": p.get("alert_when") or "high_or_critical",
        "include_finding_details": bool(p.get("include_finding_details", True)),
        "last_run_at": p.get("last_run_at"),
        "next_run_at": p.get("next_run_at"),
        "last_run_status": p.get("last_run_status") or "never",
        "last_run_message": p.get("last_run_message"),
        "last_email_status": p.get("last_email_status") or "never",
        "last_email_message": p.get("last_email_message"),
        "last_email_at": p.get("last_email_at"),
        "run_count": int(p.get("run_count") or 0),
        "updated_at": p.get("updated_at"),
        "scheduler_supported": not serverless,
        "guidance": _guidance(p, serverless=serverless),
    }


def _guidance(p: dict[str, Any], *, serverless: bool) -> list[dict[str, str]]:
    tips: list[dict[str, str]] = []
    if serverless:
        tips.append(
            {
                "level": "warning",
                "text": (
                    "Scheduled scans need a long-running API process (local or always-on host). "
                    "On serverless (Vercel) the timer cannot stay awake — use local backend or an external cron hitting POST /api/settings/schedule/run-now."
                ),
            }
        )
    if p.get("enabled") and not serverless:
        tips.append(
            {
                "level": "info",
                "text": (
                    f"Auto-scan is ON every {int(p.get('interval_minutes') or 60)} minutes "
                    "using your saved Cloud Connection."
                ),
            }
        )
    if p.get("email_enabled"):
        if not (p.get("recipients") or "").strip():
            tips.append(
                {
                    "level": "warning",
                    "text": "Enter your Gmail so VaultScan can send alerts to you.",
                }
            )
        else:
            tips.append(
                {
                    "level": "info",
                    "text": (
                        "Alerts are sent as VaultScan Company. "
                        "You only need your own Gmail as the recipient."
                    ),
                }
            )
    return tips


def update(payload: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        current = _read()

        if "enabled" in payload and payload["enabled"] is not None:
            current["enabled"] = bool(payload["enabled"])

        if "interval_minutes" in payload and payload["interval_minutes"] is not None:
            mins = int(payload["interval_minutes"])
            mins = max(MIN_INTERVAL_MINUTES, min(mins, MAX_INTERVAL_MINUTES))
            current["interval_minutes"] = mins

        if "email_enabled" in payload and payload["email_enabled"] is not None:
            current["email_enabled"] = bool(payload["email_enabled"])

        if "recipients" in payload and payload["recipients"] is not None:
            rec = payload["recipients"]
            if isinstance(rec, list):
                rec = ", ".join(str(x).strip() for x in rec if str(x).strip())
            current["recipients"] = str(rec).strip()

        if "gmail_address" in payload and payload["gmail_address"] is not None:
            current["gmail_address"] = str(payload["gmail_address"]).strip()

        if "from_name" in payload and payload["from_name"] is not None:
            name = str(payload["from_name"]).strip()
            current["from_name"] = name or "VaultScan Company"

        if "gmail_app_password" in payload:
            val = (payload.get("gmail_app_password") or "").strip()
            if val and val not in _SECRET_PLACEHOLDERS:
                current["gmail_app_password"] = val.replace(" ", "")

        if "smtp_host" in payload and payload["smtp_host"] is not None:
            current["smtp_host"] = str(payload["smtp_host"]).strip() or "smtp.gmail.com"

        if "smtp_port" in payload and payload["smtp_port"] is not None:
            current["smtp_port"] = int(payload["smtp_port"])

        if "alert_when" in payload and payload["alert_when"] is not None:
            aw = str(payload["alert_when"]).strip()
            if aw in ("always", "any_findings", "high_or_critical", "critical_only"):
                current["alert_when"] = aw

        if "include_finding_details" in payload and payload["include_finding_details"] is not None:
            current["include_finding_details"] = bool(payload["include_finding_details"])

        # When enabling, schedule next run from now (first tick after interval, or soon)
        if current.get("enabled"):
            if not current.get("next_run_at") or payload.get("enabled") is True:
                mins = int(current.get("interval_minutes") or 60)
                # first run soon (2 min) so demos work; then every interval
                delay = 2 if payload.get("enabled") is True else mins
                nxt = datetime.now(timezone.utc) + timedelta(minutes=delay)
                current["next_run_at"] = nxt.isoformat().replace("+00:00", "Z")
        else:
            current["next_run_at"] = None

        current["updated_at"] = _utcnow()
        _write(current)
        return deepcopy(current)


def record_run(
    *,
    status: str,
    message: str,
    schedule_next: bool = True,
) -> dict[str, Any]:
    with _LOCK:
        current = _read()
        now = datetime.now(timezone.utc)
        current["last_run_at"] = now.isoformat().replace("+00:00", "Z")
        current["last_run_status"] = status
        current["last_run_message"] = message
        if status == "ok":
            current["run_count"] = int(current.get("run_count") or 0) + 1
        if schedule_next and current.get("enabled"):
            mins = int(current.get("interval_minutes") or 60)
            nxt = now + timedelta(minutes=mins)
            current["next_run_at"] = nxt.isoformat().replace("+00:00", "Z")
        _write(current)
        return deepcopy(current)


def record_email(*, status: str, message: str) -> dict[str, Any]:
    with _LOCK:
        current = _read()
        current["last_email_status"] = status
        current["last_email_message"] = message
        current["last_email_at"] = _utcnow()
        _write(current)
        return deepcopy(current)


def is_due(profile: dict[str, Any] | None = None) -> bool:
    p = profile if profile is not None else load()
    if not p.get("enabled"):
        return False
    nxt = _parse_iso(p.get("next_run_at"))
    if nxt is None:
        return True
    return datetime.now(timezone.utc) >= nxt


def parse_recipients(raw: str | list | None) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        items = [str(x).strip() for x in raw]
    else:
        items = [p.strip() for p in str(raw).replace(";", ",").split(",")]
    out: list[str] = []
    for item in items:
        if item and "@" in item and item not in out:
            out.append(item)
    return out


def should_send_alert(scan: dict[str, Any], alert_when: str) -> bool:
    summary = scan.get("summary") or {}
    critical = int(summary.get("CRITICAL") or 0)
    high = int(summary.get("HIGH") or 0)
    total = int(scan.get("total_findings") or 0)
    if alert_when == "always":
        return True
    if alert_when == "any_findings":
        return total > 0
    if alert_when == "critical_only":
        return critical > 0
    # high_or_critical (default)
    return critical > 0 or high > 0
