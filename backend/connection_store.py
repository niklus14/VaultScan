"""
Runtime cloud-connection settings for VaultScan.

Credentials entered in the product Settings UI are stored server-side only
(data/connection.json). Secrets are never returned in full via the API —
only presence flags and masked previews.
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

_DATA_DIR = Path(__file__).resolve().parent / "data"
_STORE_PATH = _DATA_DIR / "connection.json"
_LOCK = threading.Lock()

# Placeholders the UI may send when the user did not change a secret field
_SECRET_PLACEHOLDERS = {"", "••••••••", "********", "unchanged", "__UNCHANGED__"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_profile() -> dict[str, Any]:
    return {
        "connection_name": "Primary AWS Account",
        "provider": "aws",
        # assume_role | direct | simulate
        "auth_mode": "assume_role",
        "role_arn": settings.aws_role_arn,
        "external_id": settings.aws_external_id or "",
        "region": settings.aws_region or "us-east-1",
        "session_name": settings.aws_session_name or "VaultScanCSPM",
        # Base identity used to call STS (or direct scan)
        "access_key_id": settings.aws_access_key_id or "",
        "secret_access_key": settings.aws_secret_access_key or "",
        "session_token": settings.aws_session_token or "",
        "updated_at": None,
        "last_tested_at": None,
        "last_test_status": None,  # ok | failed | never
        "last_test_message": None,
        "last_account_id": None,
        "last_caller_arn": None,
    }


def _ensure_store() -> dict[str, Any]:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not _STORE_PATH.exists():
        profile = _default_profile()
        # Prefer env defaults on first boot
        _write_raw(profile)
        return profile
    try:
        with _STORE_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Merge missing keys from defaults
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
    # Restrict permissions on Unix
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


def public_view(profile: dict[str, Any] | None = None) -> dict[str, Any]:
    """Safe payload for the Settings UI — never includes secret material."""
    p = profile or get_profile()
    has_key = bool(p.get("access_key_id"))
    has_secret = bool(p.get("secret_access_key"))
    has_token = bool(p.get("session_token"))
    return {
        "connection_name": p.get("connection_name") or "Primary AWS Account",
        "provider": p.get("provider") or "aws",
        "auth_mode": p.get("auth_mode") or "assume_role",
        "role_arn": p.get("role_arn") or "",
        "external_id": p.get("external_id") or "",
        "region": p.get("region") or "us-east-1",
        "session_name": p.get("session_name") or "VaultScanCSPM",
        "access_key_id_masked": mask_access_key(p.get("access_key_id") or ""),
        "has_access_key": has_key,
        "has_secret_key": has_secret,
        "has_session_token": has_token,
        "credentials_configured": has_key and has_secret,
        "updated_at": p.get("updated_at"),
        "last_tested_at": p.get("last_tested_at"),
        "last_test_status": p.get("last_test_status") or "never",
        "last_test_message": p.get("last_test_message"),
        "last_account_id": p.get("last_account_id"),
        "last_caller_arn": p.get("last_caller_arn"),
        "ready_to_scan": _ready_to_scan(p),
        "guidance": _guidance(p),
    }


def _ready_to_scan(p: dict[str, Any]) -> bool:
    mode = p.get("auth_mode") or "assume_role"
    if mode == "simulate":
        return True
    if mode == "direct":
        return bool(p.get("access_key_id") and p.get("secret_access_key"))
    # assume_role
    return bool(
        p.get("role_arn")
        and p.get("access_key_id")
        and p.get("secret_access_key")
    )


def _guidance(p: dict[str, Any]) -> list[dict[str, str]]:
    mode = p.get("auth_mode") or "assume_role"
    tips: list[dict[str, str]] = []
    if mode == "simulate":
        tips.append(
            {
                "level": "info",
                "text": "Demo mode uses a simulated cloud. No real AWS credentials are required.",
            }
        )
        return tips

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
                    "Recommended setup: the Access Key only needs permission to call "
                    "sts:AssumeRole. Scanning runs with the Role’s short-lived credentials."
                ),
            }
        )

    if mode == "direct":
        tips.append(
            {
                "level": "warning",
                "text": (
                    "Direct mode scans with the Access Key itself. Prefer Role Assumption "
                    "for production accounts."
                ),
            }
        )

    tips.append(
        {
            "level": "info",
            "text": (
                "Secrets are stored only on the VaultScan server and never shown again in full. "
                "Leave a secret field blank when saving if you do not want to replace it."
            ),
        }
    )
    return tips


def validate_role_arn(role_arn: str, auth_mode: str) -> str | None:
    """
    Return an error message if Role ARN is invalid for assume_role mode.
    IAM *user* ARNs cannot be assumed with sts:AssumeRole.
    """
    arn = (role_arn or "").strip()
    if auth_mode != "assume_role":
        return None
    if not arn:
        return "Role ARN is required for IAM Role assumption mode."
    if ":user/" in arn:
        return (
            "You entered an IAM *User* ARN (…:user/…), not a Role ARN. "
            "sts:AssumeRole only works on roles (…:role/…). "
            "Either paste a Role ARN such as "
            "arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role, "
            "or switch Connection Method to “Access keys (direct)” if you only have a user."
        )
    if not arn.startswith("arn:aws:iam::") or ":role/" not in arn:
        return (
            "Role ARN must look like "
            "arn:aws:iam::ACCOUNT_ID:role/RoleName "
            "(must contain :role/, not :user/)."
        )
    return None


def update_profile(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Merge Settings form payload into stored profile.

    Secret fields: omit or send empty / placeholder to keep the previous value.
    Send clear_credentials=true to wipe access keys.
    """
    with _LOCK:
        current = _ensure_store()

        if payload.get("clear_credentials"):
            current["access_key_id"] = ""
            current["secret_access_key"] = ""
            current["session_token"] = ""

        for key in (
            "connection_name",
            "provider",
            "auth_mode",
            "role_arn",
            "external_id",
            "region",
            "session_name",
        ):
            if key in payload and payload[key] is not None:
                current[key] = str(payload[key]).strip()

        # Validate role ARN after merge so we see the effective auth_mode + arn
        mode = current.get("auth_mode") or "assume_role"
        role_err = validate_role_arn(current.get("role_arn") or "", mode)
        if role_err:
            raise ValueError(role_err)

        # Access key id can be updated when a non-placeholder value is provided
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
    """Values used by the scanner / aws_client (includes secrets — internal only)."""
    p = get_profile()
    return {
        "auth_mode": p.get("auth_mode") or "assume_role",
        "role_arn": p.get("role_arn") or settings.aws_role_arn,
        "external_id": p.get("external_id") or "",
        "region": p.get("region") or settings.aws_region,
        "session_name": p.get("session_name") or settings.aws_session_name,
        "access_key_id": p.get("access_key_id") or "",
        "secret_access_key": p.get("secret_access_key") or "",
        "session_token": p.get("session_token") or "",
        "connection_name": p.get("connection_name") or "Primary AWS Account",
    }
