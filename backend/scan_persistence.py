"""
Persist scan results and the last full report package to disk.

Allows re-opening reports and exporting PDF/DOCX without running a new scan,
as long as the underlying scan record is still available.
"""
from __future__ import annotations

import json
import os
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).resolve().parent / "data"
_SCANS_PATH = _DATA_DIR / "scans.json"
_REPORTS_PATH = _DATA_DIR / "reports.json"
_LOCK = threading.Lock()
_MAX_SCANS = 50
_MAX_REPORTS = 30


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return deepcopy(default)
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return deepcopy(default)


def _write_json(path: Path, data: Any) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
        fh.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_scans() -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Return (history newest-first, latest_scan)."""
    with _LOCK:
        raw = _read_json(_SCANS_PATH, {"scans": [], "latest_id": None})
        scans = raw.get("scans") or []
        if not isinstance(scans, list):
            scans = []
        latest_id = raw.get("latest_id")
        latest = None
        if latest_id:
            for s in scans:
                if s.get("scan_id") == latest_id:
                    latest = s
                    break
        if latest is None and scans:
            latest = scans[0]
        return deepcopy(scans), deepcopy(latest)


def save_scan(scan: dict[str, Any], history: list[dict[str, Any]]) -> None:
    """Persist full scan history after a new scan."""
    with _LOCK:
        scans = deepcopy(history)[:_MAX_SCANS]
        payload = {
            "latest_id": scan.get("scan_id"),
            "scans": scans,
        }
        _write_json(_SCANS_PATH, payload)


def get_scan(scan_id: str | None, history: list[dict[str, Any]], latest: dict | None) -> dict | None:
    if scan_id:
        for s in history:
            if s.get("scan_id") == scan_id:
                return s
        # Disk fallback if memory is empty/stale
        disk, _ = load_scans()
        for s in disk:
            if s.get("scan_id") == scan_id:
                return s
        return None
    if latest:
        return latest
    disk, disk_latest = load_scans()
    return disk_latest or (disk[0] if disk else None)


def save_report_package(scan_id: str, package: dict[str, Any]) -> None:
    """Cache the full UI report package (narrative + tables) for re-open/export."""
    with _LOCK:
        raw = _read_json(_REPORTS_PATH, {"by_scan": {}, "latest_id": None})
        by_scan = raw.get("by_scan") or {}
        by_scan[scan_id] = package
        # Cap size
        if len(by_scan) > _MAX_REPORTS:
            # drop oldest keys (dict order is insert order in py3.7+)
            for key in list(by_scan.keys())[: len(by_scan) - _MAX_REPORTS]:
                if key != scan_id:
                    by_scan.pop(key, None)
        raw["by_scan"] = by_scan
        raw["latest_id"] = scan_id
        _write_json(_REPORTS_PATH, raw)


def load_report_package(scan_id: str | None = None) -> dict[str, Any] | None:
    with _LOCK:
        raw = _read_json(_REPORTS_PATH, {"by_scan": {}, "latest_id": None})
        by_scan = raw.get("by_scan") or {}
        sid = scan_id or raw.get("latest_id")
        if not sid:
            return None
        pkg = by_scan.get(sid)
        return deepcopy(pkg) if pkg else None
