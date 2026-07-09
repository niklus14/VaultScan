"""Load VaultScan backend configuration from environment / .env."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(_ENV_PATH)

DEFAULT_ROLE_ARN = "arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role"


class Settings:
    grok_api_key: str = os.getenv("GROK_API_KEY", "")
    grok_model: str = os.getenv("GROK_MODEL", "grok-3-mini")
    grok_base_url: str = os.getenv("GROK_BASE_URL", "https://api.x.ai/v1").rstrip("/")

    aws_role_arn: str = os.getenv("AWS_ROLE_ARN", DEFAULT_ROLE_ARN)
    aws_external_id: str = os.getenv("AWS_EXTERNAL_ID", "")
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    aws_session_name: str = os.getenv("AWS_SESSION_NAME", "VaultScanCSPM")

    # Base credentials (optional — boto3 also reads env / instance profile / ~/.aws)
    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    aws_session_token: str = os.getenv("AWS_SESSION_TOKEN", "")

    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    cors_origins: list[str] = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        ).split(",")
        if o.strip()
    ]


settings = Settings()
