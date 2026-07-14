"""
In-process background scheduler for VaultScan auto-scans.

Runs while the FastAPI process is alive (local / always-on hosts).
Not reliable on pure serverless (Vercel cold starts).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Callable

import schedule_store

log = logging.getLogger("vaultscan.scheduler")

_thread: threading.Thread | None = None
_stop = threading.Event()
_running_scan = threading.Lock()
_scan_fn: Callable[[], dict[str, Any]] | None = None
_POLL_SECONDS = 20


def _serverless() -> bool:
    return bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def _loop() -> None:
    log.info("VaultScan scheduler loop started")
    while not _stop.is_set():
        try:
            if schedule_store.is_due():
                run_scheduled_scan(reason="interval")
        except Exception:  # noqa: BLE001
            log.exception("scheduler tick failed")
        _stop.wait(_POLL_SECONDS)
    log.info("VaultScan scheduler loop stopped")


def start(scan_fn: Callable[[], dict[str, Any]]) -> None:
    """Start background thread once."""
    global _thread, _scan_fn
    _scan_fn = scan_fn
    if _serverless():
        log.warning("Scheduler disabled on serverless runtime")
        return
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="vaultscan-scheduler", daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()


def run_scheduled_scan(*, reason: str = "manual") -> dict[str, Any]:
    """
    Execute one scheduled scan (+ optional email).
    Returns {ok, message, scan?, email?}.
    """
    import email_alerts

    if _scan_fn is None:
        return {"ok": False, "message": "Scheduler not initialized."}

    if not _running_scan.acquire(blocking=False):
        return {"ok": False, "message": "A scheduled scan is already running."}

    try:
        try:
            scan = _scan_fn()
        except Exception as exc:  # noqa: BLE001
            msg = f"Scheduled scan failed: {exc}"
            schedule_store.record_run(status="failed", message=msg)
            return {"ok": False, "message": msg}

        score = scan.get("score")
        total = scan.get("total_findings")
        msg = f"Scan OK ({reason}): score={score}, findings={total}"
        schedule_store.record_run(status="ok", message=msg)

        email_result = email_alerts.maybe_alert_after_scan(
            scan, source=f"schedule:{reason}"
        )

        return {
            "ok": True,
            "message": msg,
            "scan_id": scan.get("scan_id"),
            "score": score,
            "total_findings": total,
            "email": email_result,
            "settings": schedule_store.public_view(),
        }
    finally:
        _running_scan.release()
