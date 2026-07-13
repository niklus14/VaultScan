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

    # Remember the Access Key user so trust-policy fixes can keep this principal
    try:
        base_ident = sts.get_caller_identity()
        base_arn = base_ident.get("Arn") or ""
        if ":user/" in base_arn:
            try:
                from connection_store import update_profile

                update_profile({"operator_arn": base_arn})
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        base_arn = ""

    try:
        resp = sts.assume_role(**params)
    except (ClientError, BotoCoreError) as exc:
        err = str(exc)
        recovery = ""
        if "AccessDenied" in err or "not authorized" in err.lower():
            recovery = (
                " Likely cause: the role trust was tightened (Principal * removed) "
                "and no longer trusts your Access Key user. "
                f"Operator: {base_arn or 'unknown'}. "
                "In the LAB account (the account that owns the Role ARN), restore trust "
                "so your user can sts:AssumeRole again, e.g. add Principal AWS = your user ARN "
                "(not *). Then re-test connection. "
                "CLI (run with admin keys of the lab account 850919910218):\n"
                "  aws iam update-assume-role-policy --role-name demo-test-vulnerable-ec2-role "
                "--policy-document file://trust-with-operator.json"
            )
        raise RuntimeError(
            f"Failed to assume role {role_arn}: {exc}. "
            "Confirm the Access Key user is trusted by the role and has sts:AssumeRole."
            f"{recovery}"
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
    Session used to APPLY fixes (writes) for **real AWS**.

    Returns (session, mode_label, error).

    With Access Key + Secret + Role ARN (assume_role) — the normal lab setup —
    fixes MUST run **after AssumeRole into that Role ARN**. Findings live in the
    role's account; calling IAM with only the base keys often returns NoSuchEntity
    when the role (or other resources) are not in the key user's home account view.

    Priority:
    1. remediator_role_arn if set
    2. Settings Role ARN (same as scan) when auth_mode is assume_role **or** a role ARN is set
    3. direct Access Keys only when auth_mode is direct
    """
    rt = resolve_runtime()
    auth_mode = (rt.get("auth_mode") or "assume_role").strip()
    region = rt.get("region") or "us-east-1"

    if auth_mode == "simulate":
        return None, "simulate", None

    if not allow_write:
        return (
            None,
            auth_mode,
            "Write remediations require allow_write=true.",
        )

    # Fall back to process env if Settings UI store is empty (e.g. Vercel cold start)
    access_key = (rt.get("access_key_id") or settings.aws_access_key_id or "").strip()
    secret_key = (rt.get("secret_access_key") or settings.aws_secret_access_key or "").strip()
    session_token = (rt.get("session_token") or settings.aws_session_token or "").strip()
    role_arn = (
        remediator_role_arn
        or rt.get("remediator_role_arn")
        or rt.get("role_arn")
        or settings.aws_role_arn
        or ""
    ).strip()
    external_id = (rt.get("external_id") or settings.aws_external_id or "").strip()

    if not access_key or not secret_key:
        return (
            None,
            auth_mode,
            "No Access Key/Secret loaded. Re-save them in Settings (server storage is ephemeral on Vercel) or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY on the backend.",
        )

    base_kwargs: dict[str, Any] = {
        "region_name": region,
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }
    if session_token:
        base_kwargs["aws_session_token"] = session_token
    base = boto3.Session(**base_kwargs)

    def _assume(target_role: str, label: str) -> tuple[boto3.Session | None, str, str | None]:
        try:
            sts = base.client("sts", config=Config(retries={"max_attempts": 3}))
            params: dict[str, Any] = {
                "RoleArn": target_role,
                "RoleSessionName": (rt.get("session_name") or "VaultScanRemediate")[:64],
                "DurationSeconds": 3600,
            }
            if external_id:
                params["ExternalId"] = external_id
            resp = sts.assume_role(**params)
            creds = resp["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
            ident = session.client("sts").get_caller_identity()
            return (
                session,
                f"{label}:account={ident.get('Account')}:arn={ident.get('Arn')}",
                None,
            )
        except (ClientError, BotoCoreError) as exc:
            return None, label, str(exc)

    # Prefer any role ARN for fixes (same account as scan findings)
    if role_arn and ":role/" in role_arn:
        sess, label, err = _assume(role_arn, "assume_role")
        if sess:
            return sess, label, None
        # Do not silently fall back to base keys for assume_role mode —
        # that is exactly what caused NoSuchEntity on cross-account / role resources.
        if auth_mode == "assume_role":
            return (
                None,
                "assume_role",
                (
                    f"Could not AssumeRole for fixes using {role_arn}: {err}. "
                    "Scan and Fix both need this Role ARN to work. "
                    "If you just fixed IAM-TRUST-WILDCARD, the role may no longer trust "
                    "your Access Key user (Principal * was removed). "
                    "In the LAB account that owns the role, add your user ARN to the trust "
                    "policy (not *), then Test Connection again."
                ),
            )
        # direct mode with optional role: fall through to keys after recording error
        assume_err = err
    else:
        assume_err = None

    if auth_mode == "direct" or not role_arn:
        try:
            sts = base.client("sts")
            ident = sts.get_caller_identity()
            return (
                base,
                f"direct_keys:account={ident.get('Account')}:arn={ident.get('Arn')}",
                None,
            )
        except (ClientError, BotoCoreError) as exc:
            msg = str(exc)
            if assume_err:
                msg = f"{assume_err} | direct keys: {msg}"
            return None, "direct_keys", msg

    return (
        None,
        auth_mode,
        assume_err
        or "Could not build a remediation session. Check Access Key, Secret, and Role ARN in Settings.",
    )


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
