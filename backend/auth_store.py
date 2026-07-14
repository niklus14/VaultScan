"""
Simple login sessions for VaultScan.

- Default demo accounts (overridable via env)
- Tokens stored server-side; frontend keeps token in localStorage
- Remember-me extends token lifetime
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from config import settings


def _resolve_data_dir() -> Path:
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return Path(os.environ.get("VAULTSCAN_DATA_DIR", "/tmp/vaultscan-data"))
    return Path(os.environ.get("VAULTSCAN_DATA_DIR", Path(__file__).resolve().parent / "data"))


_DATA_DIR = _resolve_data_dir()
_SESSIONS_PATH = _DATA_DIR / "sessions.json"
_LOCK = threading.Lock()

# Session lengths
SESSION_HOURS = 24
REMEMBER_DAYS = 30


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    ).hex()
    return salt, digest


def _verify_password(password: str, salt: str, digest: str) -> bool:
    _, check = _hash_password(password, salt)
    return hmac.compare_digest(check, digest)


def _default_users() -> list[dict[str, Any]]:
    """Seed accounts — change via env for real deployments."""
    user = (os.getenv("VAULTSCAN_AUTH_USER") or "admin").strip() or "admin"
    password = os.getenv("VAULTSCAN_AUTH_PASSWORD") or "vaultscan"
    salt, digest = _hash_password(password)
    users = [
        {
            "username": user.lower(),
            "display_name": "VaultScan Admin",
            "salt": salt,
            "password_hash": digest,
            "role": "admin",
        }
    ]
    # Second convenient demo account
    if user.lower() != "vaultscan":
        s2, d2 = _hash_password("vaultscan")
        users.append(
            {
                "username": "vaultscan",
                "display_name": "VaultScan Operator",
                "salt": s2,
                "password_hash": d2,
                "role": "operator",
            }
        )
    return users


def _read_sessions() -> dict[str, Any]:
    if not _SESSIONS_PATH.exists():
        return {"sessions": {}, "users": _default_users()}
    try:
        with _SESSIONS_PATH.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            return {"sessions": {}, "users": _default_users()}
        if not raw.get("users"):
            raw["users"] = _default_users()
        if "sessions" not in raw or not isinstance(raw["sessions"], dict):
            raw["sessions"] = {}
        return raw
    except (json.JSONDecodeError, OSError):
        return {"sessions": {}, "users": _default_users()}


def _write_sessions(data: dict[str, Any]) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _SESSIONS_PATH.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
        fh.write("\n")
    os.replace(tmp, _SESSIONS_PATH)
    try:
        os.chmod(_SESSIONS_PATH, 0o600)
    except OSError:
        pass


def _find_user(username: str, users: list[dict[str, Any]]) -> dict[str, Any] | None:
    u = username.strip().lower()
    for row in users:
        if str(row.get("username") or "").lower() == u:
            return row
    return None


def login(
    username: str,
    password: str,
    *,
    remember: bool = True,
) -> dict[str, Any]:
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        raise ValueError("Username and password are required.")

    with _LOCK:
        data = _read_sessions()
        user = _find_user(username, data.get("users") or [])
        if not user or not _verify_password(
            password, str(user.get("salt") or ""), str(user.get("password_hash") or "")
        ):
            raise ValueError("Invalid username or password.")

        token = secrets.token_urlsafe(32)
        now = _utcnow()
        exp = now + (
            timedelta(days=REMEMBER_DAYS) if remember else timedelta(hours=SESSION_HOURS)
        )
        data["sessions"][token] = {
            "username": user["username"],
            "display_name": user.get("display_name") or user["username"],
            "role": user.get("role") or "user",
            "created_at": _iso(now),
            "expires_at": _iso(exp),
            "remember": bool(remember),
        }
        # prune expired
        alive = {}
        for t, sess in (data.get("sessions") or {}).items():
            exp_dt = _parse_iso(sess.get("expires_at"))
            if exp_dt and exp_dt > now:
                alive[t] = sess
        data["sessions"] = alive
        _write_sessions(data)

        return {
            "token": token,
            "username": user["username"],
            "display_name": user.get("display_name") or user["username"],
            "role": user.get("role") or "user",
            "expires_at": _iso(exp),
            "remember": bool(remember),
        }


def logout(token: str | None) -> None:
    if not token:
        return
    with _LOCK:
        data = _read_sessions()
        data.get("sessions", {}).pop(token, None)
        _write_sessions(data)


def validate_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    token = token.strip()
    if not token:
        return None
    with _LOCK:
        data = _read_sessions()
        sess = (data.get("sessions") or {}).get(token)
        if not sess:
            return None
        exp = _parse_iso(sess.get("expires_at"))
        if not exp or exp <= _utcnow():
            data["sessions"].pop(token, None)
            _write_sessions(data)
            return None
        return deepcopy(sess)


def public_auth_info() -> dict[str, Any]:
    """Non-sensitive hints for the login page."""
    return {
        "auth_required": True,
        "hint": "Default: admin / vaultscan  (or vaultscan / vaultscan)",
        "remember_days": REMEMBER_DAYS,
    }
