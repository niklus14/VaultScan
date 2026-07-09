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
