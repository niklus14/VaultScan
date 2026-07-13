"""
Runtime cloud-connection settings for VaultScan.

Supports AWS and Google Cloud profiles. Secrets stay server-side only.
"""
from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings


def _resolve_data_dir() -> Path:
    """Use /tmp on Vercel (read-only deployment FS); local backend/data otherwise."""
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        d = Path(os.environ.get("VAULTSCAN_DATA_DIR", "/tmp/vaultscan-data"))
    else:
        d = Path(os.environ.get("VAULTSCAN_DATA_DIR", Path(__file__).resolve().parent / "data"))
    return d


_DATA_DIR = _resolve_data_dir()
_STORE_PATH = _DATA_DIR / "connection.json"
_LOCK = threading.Lock()

_SECRET_PLACEHOLDERS = {"", "••••••••", "********", "unchanged", "__UNCHANGED__"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_profile() -> dict[str, Any]:
    return {
        "connection_name": "Primary Cloud Account",
        "provider": "aws",  # aws | gcp
        # AWS auth: assume_role | direct | simulate
        "auth_mode": "assume_role",
        "role_arn": settings.aws_role_arn,
        "external_id": settings.aws_external_id or "",
        "region": settings.aws_region or "us-east-1",
        "session_name": settings.aws_session_name or "VaultScanCSPM",
        "access_key_id": settings.aws_access_key_id or "",
        "secret_access_key": settings.aws_secret_access_key or "",
        "session_token": settings.aws_session_token or "",
        # Google Cloud
        "gcp_project_id": "",
        "gcp_service_account_email": "",
        "gcp_service_account_json": "",
        "updated_at": None,
        "last_tested_at": None,
        "last_test_status": None,
        "last_test_message": None,
        "last_account_id": None,
        "last_caller_arn": None,
    }


def _ensure_store() -> dict[str, Any]:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not _STORE_PATH.exists():
        profile = _default_profile()
        _write_raw(profile)
        return profile
    try:
        with _STORE_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        base = _default_profile()
        base.update({k: v for k, v in data.items() if v is not None})
        return base
    except (json.JSONDecodeError, OSError):
        profile = _default_profile()
        _write_raw(profile)
        return profile


def _write_raw(profile: dict[str, Any]) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _STORE_PATH.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, _STORE_PATH)
    try:
        os.chmod(_STORE_PATH, 0o600)
    except OSError:
        pass


def get_profile() -> dict[str, Any]:
    with _LOCK:
        return deepcopy(_ensure_store())


def mask_access_key(key: str) -> str | None:
    if not key:
        return None
    if len(key) <= 8:
        return "••••••••"
    return f"{key[:4]}••••••••{key[-4:]}"


def mask_email(email: str) -> str | None:
    if not email or "@" not in email:
        return email or None
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        return f"••@{domain}"
    return f"{name[:2]}•••@{domain}"


def public_view(profile: dict[str, Any] | None = None) -> dict[str, Any]:
    p = profile or get_profile()
    provider = (p.get("provider") or "aws").lower()
    has_key = bool(p.get("access_key_id"))
    has_secret = bool(p.get("secret_access_key"))
    has_token = bool(p.get("session_token"))
    has_sa = bool(p.get("gcp_service_account_json"))
    sa_email = p.get("gcp_service_account_email") or ""
    # Try extract email from stored JSON for display
    if not sa_email and has_sa:
        try:
            sa_email = json.loads(p["gcp_service_account_json"]).get("client_email") or ""
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    return {
        "connection_name": p.get("connection_name") or "Primary Cloud Account",
        "provider": provider,
        "auth_mode": p.get("auth_mode") or "assume_role",
        "role_arn": p.get("role_arn") or "",
        "external_id": p.get("external_id") or "",
        "region": p.get("region") or "us-east-1",
        "session_name": p.get("session_name") or "VaultScanCSPM",
        "access_key_id_masked": mask_access_key(p.get("access_key_id") or ""),
        "has_access_key": has_key,
        "has_secret_key": has_secret,
        "has_session_token": has_token,
        "gcp_project_id": p.get("gcp_project_id") or "",
        "gcp_service_account_email_masked": mask_email(sa_email),
        "has_gcp_service_account": has_sa,
        "credentials_configured": _credentials_configured(p),
        "updated_at": p.get("updated_at"),
        "last_tested_at": p.get("last_tested_at"),
        "last_test_status": p.get("last_test_status") or "never",
        "last_test_message": p.get("last_test_message"),
        "last_account_id": p.get("last_account_id"),
        "last_caller_arn": p.get("last_caller_arn"),
        "ready_to_scan": _ready_to_scan(p),
        "guidance": _guidance(p),
    }


def _credentials_configured(p: dict[str, Any]) -> bool:
    provider = (p.get("provider") or "aws").lower()
    if provider == "gcp":
        return bool(p.get("gcp_project_id") and p.get("gcp_service_account_json"))
    if (p.get("auth_mode") or "") == "simulate":
        return True
    return bool(p.get("access_key_id") and p.get("secret_access_key"))


def _ready_to_scan(p: dict[str, Any]) -> bool:
    provider = (p.get("provider") or "aws").lower()
    mode = p.get("auth_mode") or "assume_role"
    if mode == "simulate":
        return True
    if provider == "gcp":
        # Connection can be saved; full GCP engine is staged
        return bool(p.get("gcp_project_id") and p.get("gcp_service_account_json"))
    if mode == "direct":
        return bool(p.get("access_key_id") and p.get("secret_access_key"))
    return bool(
        p.get("role_arn")
        and p.get("access_key_id")
        and p.get("secret_access_key")
    )


def _guidance(p: dict[str, Any]) -> list[dict[str, str]]:
    provider = (p.get("provider") or "aws").lower()
    mode = p.get("auth_mode") or "assume_role"
    tips: list[dict[str, str]] = []

    if mode == "simulate":
        tips.append(
            {
                "level": "info",
                "text": "Demo mode uses a simulated cloud. No live cloud credentials are required.",
            }
        )
        return tips

    if provider == "gcp":
        if not p.get("gcp_project_id"):
            tips.append(
                {
                    "level": "warning",
                    "text": "Enter your Google Cloud Project ID (e.g. my-project-123).",
                }
            )
        if not p.get("gcp_service_account_json"):
            tips.append(
                {
                    "level": "warning",
                    "text": (
                        "Paste a Service Account JSON key. Create it in GCP Console → "
                        "IAM & Admin → Service Accounts → Keys → Add key → JSON. "
                        "Grant Viewer / Security Reviewer style roles for read-only scans."
                    ),
                }
            )
        else:
            tips.append(
                {
                    "level": "info",
                    "text": (
                        "GCP connection is stored. VaultScan validates the service account on "
                        "Test Connection. Full GCP misconfig scanning expands from this profile."
                    ),
                }
            )
        tips.append(
            {
                "level": "info",
                "text": "Secrets stay on the VaultScan server and are never returned in full.",
            }
        )
        return tips

    # AWS
    if not p.get("access_key_id") or not p.get("secret_access_key"):
        tips.append(
            {
                "level": "warning",
                "text": (
                    "Add an IAM Access Key ID and Secret Access Key for a user that is "
                    "allowed to connect. Create them in AWS IAM → Users → Security credentials."
                ),
            }
        )
    if mode == "assume_role" and not p.get("role_arn"):
        tips.append(
            {
                "level": "warning",
                "text": "Enter the IAM Role ARN VaultScan should assume in the target account.",
            }
        )
    if mode == "assume_role" and p.get("access_key_id") and p.get("role_arn"):
        tips.append(
            {
                "level": "info",
                "text": (
                    "Recommended: Access Key only needs sts:AssumeRole. "
                    "Scanning uses the role’s short-lived credentials."
                ),
            }
        )
    if mode == "direct":
        tips.append(
            {
                "level": "warning",
                "text": "Direct mode scans with the Access Key itself. Prefer Role Assumption for production.",
            }
        )
    tips.append(
        {
            "level": "info",
            "text": (
                "Secrets are stored only on the VaultScan server. "
                "Leave secret fields blank when saving to keep existing values."
            ),
        }
    )
    return tips


def validate_role_arn(role_arn: str, auth_mode: str, provider: str = "aws") -> str | None:
    if (provider or "aws").lower() != "aws":
        return None
    arn = (role_arn or "").strip()
    if auth_mode != "assume_role":
        return None
    if not arn:
        return "Role ARN is required for IAM Role assumption mode."
    if ":user/" in arn:
        return (
            "You entered an IAM User ARN (…:user/…), not a Role ARN. "
            "Use …:role/RoleName or switch to Access keys (direct)."
        )
    if not arn.startswith("arn:aws:iam::") or ":role/" not in arn:
        return "Role ARN must look like arn:aws:iam::ACCOUNT_ID:role/RoleName"
    return None


def update_profile(payload: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        current = _ensure_store()

        if payload.get("clear_credentials"):
            current["access_key_id"] = ""
            current["secret_access_key"] = ""
            current["session_token"] = ""
            current["gcp_service_account_json"] = ""
            current["gcp_service_account_email"] = ""

        for key in (
            "connection_name",
            "provider",
            "auth_mode",
            "role_arn",
            "external_id",
            "region",
            "session_name",
            "gcp_project_id",
            "gcp_service_account_email",
        ):
            if key in payload and payload[key] is not None:
                current[key] = str(payload[key]).strip()

        provider = (current.get("provider") or "aws").lower()
        if provider not in ("aws", "gcp"):
            raise ValueError("Provider must be 'aws' or 'gcp'.")
        current["provider"] = provider

        mode = current.get("auth_mode") or "assume_role"
        role_err = validate_role_arn(
            current.get("role_arn") or "", mode, provider=provider
        )
        if role_err:
            raise ValueError(role_err)

        if "access_key_id" in payload:
            val = (payload.get("access_key_id") or "").strip()
            if val and val not in _SECRET_PLACEHOLDERS and "•" not in val:
                current["access_key_id"] = val

        if "secret_access_key" in payload:
            val = (payload.get("secret_access_key") or "").strip()
            if val and val not in _SECRET_PLACEHOLDERS and "•" not in val:
                current["secret_access_key"] = val

        if "session_token" in payload:
            val = (payload.get("session_token") or "").strip()
            if val and val not in _SECRET_PLACEHOLDERS and "•" not in val:
                current["session_token"] = val
            elif payload.get("clear_session_token"):
                current["session_token"] = ""

        if "gcp_service_account_json" in payload:
            raw = (payload.get("gcp_service_account_json") or "").strip()
            if raw and raw not in _SECRET_PLACEHOLDERS and "•" not in raw[:8]:
                # Validate JSON shape
                try:
                    doc = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Service account JSON is invalid: {exc}") from exc
                if not isinstance(doc, dict) or "client_email" not in doc:
                    raise ValueError(
                        "Service account JSON must include client_email "
                        "(download the full key file from GCP Console)."
                    )
                current["gcp_service_account_json"] = raw
                current["gcp_service_account_email"] = doc.get("client_email") or ""
                if not current.get("gcp_project_id") and doc.get("project_id"):
                    current["gcp_project_id"] = doc["project_id"]

        current["updated_at"] = _utcnow()
        _write_raw(current)
        return deepcopy(current)


def record_test_result(
    *,
    ok: bool,
    message: str,
    account_id: str | None = None,
    caller_arn: str | None = None,
) -> dict[str, Any]:
    with _LOCK:
        current = _ensure_store()
        current["last_tested_at"] = _utcnow()
        current["last_test_status"] = "ok" if ok else "failed"
        current["last_test_message"] = message
        if account_id is not None:
            current["last_account_id"] = account_id
        if caller_arn is not None:
            current["last_caller_arn"] = caller_arn
        _write_raw(current)
        return deepcopy(current)


def resolve_runtime() -> dict[str, Any]:
    p = get_profile()
    return {
        "provider": (p.get("provider") or "aws").lower(),
        "auth_mode": p.get("auth_mode") or "assume_role",
        "role_arn": p.get("role_arn") or settings.aws_role_arn,
        "external_id": p.get("external_id") or "",
        "region": p.get("region") or settings.aws_region,
        "session_name": p.get("session_name") or settings.aws_session_name,
        "access_key_id": p.get("access_key_id") or "",
        "secret_access_key": p.get("secret_access_key") or "",
        "session_token": p.get("session_token") or "",
        "connection_name": p.get("connection_name") or "Primary Cloud Account",
        "gcp_project_id": p.get("gcp_project_id") or "",
        "gcp_service_account_json": p.get("gcp_service_account_json") or "",
        "gcp_service_account_email": p.get("gcp_service_account_email") or "",
    }


def test_gcp_connection(profile: dict[str, Any] | None = None) -> tuple[bool, str, str | None]:
    """
    Validate GCP service account JSON.
    Returns (ok, message, project_or_email).
    """
    p = profile or get_profile()
    project = (p.get("gcp_project_id") or "").strip()
    raw = (p.get("gcp_service_account_json") or "").strip()
    if not project:
        return False, "GCP Project ID is required.", None
    if not raw:
        return False, "Service Account JSON key is required.", None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return False, f"Invalid service account JSON: {exc}", None
    email = doc.get("client_email")
    pid = doc.get("project_id") or project
    if not email:
        return False, "JSON key missing client_email.", None
    if not doc.get("private_key"):
        return False, "JSON key missing private_key.", None

    # Optional live token if google-auth installed
    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request

        creds = service_account.Credentials.from_service_account_info(
            doc,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        creds.refresh(Request())
        return (
            True,
            f"Google Cloud credentials valid for {email} (project {pid}).",
            pid,
        )
    except ImportError:
        return (
            True,
            f"Service account JSON looks valid ({email}, project {pid}). "
            "Install google-auth for live token verification.",
            pid,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"GCP credential test failed: {exc}", None
