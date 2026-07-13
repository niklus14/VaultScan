"""AWS session factory — uses Settings UI credentials + AssumeRole."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from config import settings
from connection_store import resolve_runtime


@dataclass
class AwsConnectionInfo:
    mode: str  # "assume_role" | "direct" | "simulate"
    account_id: str | None = None
    arn: str | None = None
    role_arn: str | None = None
    region: str = "us-east-1"
    user_id: str | None = None
    error: str | None = None
    connection_name: str | None = None


def _runtime(
    *,
    mode: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    rt = resolve_runtime()
    if mode:
        rt["auth_mode"] = mode
    if role_arn:
        rt["role_arn"] = role_arn
    if external_id is not None:
        rt["external_id"] = external_id
    if region:
        rt["region"] = region
    return rt


def _base_session(rt: dict[str, Any]) -> boto3.Session:
    """Session for the operator identity (keys from Settings UI)."""
    kwargs: dict[str, Any] = {"region_name": rt["region"]}
    if rt.get("access_key_id") and rt.get("secret_access_key"):
        kwargs["aws_access_key_id"] = rt["access_key_id"]
        kwargs["aws_secret_access_key"] = rt["secret_access_key"]
        if rt.get("session_token"):
            kwargs["aws_session_token"] = rt["session_token"]
    return boto3.Session(**kwargs)


def assume_role(rt: dict[str, Any] | None = None) -> tuple[boto3.Session, AwsConnectionInfo]:
    rt = rt or _runtime()
    role_arn = rt["role_arn"]
    region = rt["region"]
    external_id = rt.get("external_id") or ""
    session_name = rt.get("session_name") or settings.aws_session_name

    if not rt.get("access_key_id") or not rt.get("secret_access_key"):
        raise RuntimeError(
            "No AWS credentials configured. Open Settings → Cloud Connection "
            "and add an Access Key ID and Secret Access Key."
        )
    if not role_arn:
        raise RuntimeError(
            "No IAM Role ARN configured. Open Settings → Cloud Connection "
            "and enter the target Role ARN."
        )
    if ":user/" in role_arn:
        raise RuntimeError(
            f"Invalid target: '{role_arn}' is an IAM User ARN, not a Role. "
            "Role assumption requires arn:aws:iam::ACCOUNT:role/RoleName. "
            "If you only have the demo-scanner-user access keys, switch Settings → "
            "Connection Method to “Access keys (direct)” and leave Role ARN empty."
        )
    if ":role/" not in role_arn:
        raise RuntimeError(
            f"Invalid Role ARN: '{role_arn}'. Expected form "
            "arn:aws:iam::ACCOUNT_ID:role/RoleName"
        )

    base = _base_session(rt)
    sts = base.client("sts", config=Config(retries={"max_attempts": 3}))

    params: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": 3600,
    }
    if external_id:
        params["ExternalId"] = external_id

    try:
        resp = sts.assume_role(**params)
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(
            f"Failed to assume role {role_arn}: {exc}. "
            "Confirm the Access Key user is trusted by the role and has sts:AssumeRole."
        ) from exc

    creds = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )

    identity = session.client("sts").get_caller_identity()
    info = AwsConnectionInfo(
        mode="assume_role",
        account_id=identity.get("Account"),
        arn=identity.get("Arn"),
        role_arn=role_arn,
        region=region,
        user_id=identity.get("UserId"),
        connection_name=rt.get("connection_name"),
    )
    return session, info


def direct_session(rt: dict[str, Any] | None = None) -> tuple[boto3.Session, AwsConnectionInfo]:
    rt = rt or _runtime(mode="direct")
    region = rt["region"]

    if not rt.get("access_key_id") or not rt.get("secret_access_key"):
        raise RuntimeError(
            "No AWS credentials configured. Open Settings → Cloud Connection "
            "and add an Access Key ID and Secret Access Key."
        )

    session = _base_session(rt)
    try:
        identity = session.client("sts", region_name=region).get_caller_identity()
        info = AwsConnectionInfo(
            mode="direct",
            account_id=identity.get("Account"),
            arn=identity.get("Arn"),
            region=region,
            user_id=identity.get("UserId"),
            connection_name=rt.get("connection_name"),
        )
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"AWS credentials rejected: {exc}") from exc
    return session, info


def get_scan_session(
    mode: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
) -> tuple[boto3.Session | None, AwsConnectionInfo]:
    rt = _runtime(
        mode=mode,
        role_arn=role_arn,
        external_id=external_id,
        region=region,
    )
    auth_mode = rt["auth_mode"]

    if auth_mode == "simulate":
        return None, AwsConnectionInfo(
            mode="simulate",
            account_id="000000000000",
            arn="arn:aws:iam::000000000000:user/vaultscan-sim",
            region=rt["region"],
            connection_name=rt.get("connection_name"),
        )

    if auth_mode == "direct":
        return direct_session(rt)

    return assume_role(rt)


def get_remediate_session(
    *,
    allow_write: bool = False,
    remediator_role_arn: str | None = None,
) -> tuple[boto3.Session | None, str, str | None]:
    """
    Session used to APPLY fixes (writes).

    Returns (session, mode_label, error).

    Priority for real AWS:
    1. Optional remediator_role_arn
    2. **Same AssumeRole as scan** (lab roles often have write; resources live in that account)
    3. Base Access Key session (direct) — same account as the keys
    """
    rt = resolve_runtime()
    auth_mode = rt.get("auth_mode") or "simulate"
    region = rt.get("region") or "us-east-1"

    if auth_mode == "simulate":
        return None, "simulate", None

    if not allow_write:
        return (
            None,
            auth_mode,
            "Write remediations require allow_write=true.",
        )

    if not rt.get("access_key_id") or not rt.get("secret_access_key"):
        return (
            None,
            auth_mode,
            "No Access Key/Secret in Settings. Save IAM credentials that can modify the target account.",
        )

    base = _base_session(rt)
    errors: list[str] = []

    def _assume(role_arn: str, label: str) -> tuple[boto3.Session | None, str, str | None]:
        try:
            sts = base.client("sts", config=Config(retries={"max_attempts": 3}))
            params: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": (rt.get("session_name") or "VaultScanRemediate")[:64],
                "DurationSeconds": 3600,
            }
            ext = rt.get("external_id") or ""
            if ext:
                params["ExternalId"] = ext
            resp = sts.assume_role(**params)
            creds = resp["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
            # prove identity
            session.client("sts").get_caller_identity()
            return session, label, None
        except (ClientError, BotoCoreError) as exc:
            return None, label, str(exc)

    # 1) Explicit remediator role
    role = (remediator_role_arn or rt.get("remediator_role_arn") or "").strip()
    if role and ":role/" in role:
        sess, label, err = _assume(role, "remediator_role")
        if sess:
            return sess, label, None
        if err:
            errors.append(f"remediator role: {err}")

    # 2) Same role used for scanning (resources are in that account; lab admin roles can write)
    scan_role = (rt.get("role_arn") or "").strip()
    if auth_mode == "assume_role" and scan_role and ":role/" in scan_role:
        sess, label, err = _assume(scan_role, "scan_assume_role")
        if sess:
            return sess, label, None
        if err:
            errors.append(f"scan role assume: {err}")

    # 3) Base access keys (must be same account as the resources)
    try:
        sts = base.client("sts")
        ident = sts.get_caller_identity()
        return base, f"direct_keys:{ident.get('Account')}", None
    except (ClientError, BotoCoreError) as exc:
        errors.append(f"direct keys: {exc}")
        return None, "direct_keys", " | ".join(errors)


def probe_connection(
    mode: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
) -> AwsConnectionInfo:
    try:
        _, info = get_scan_session(
            mode=mode,
            role_arn=role_arn,
            external_id=external_id,
            region=region,
        )
        return info
    except Exception as exc:  # noqa: BLE001
        rt = _runtime(mode=mode, role_arn=role_arn, region=region)
        return AwsConnectionInfo(
            mode=rt["auth_mode"],
            role_arn=rt.get("role_arn"),
            region=rt.get("region") or "us-east-1",
            connection_name=rt.get("connection_name"),
            error=str(exc),
        )
