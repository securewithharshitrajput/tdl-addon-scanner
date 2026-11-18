"""
reputation.py — Institutional memory for reviewed add-ons.

Records the hash + verdict of add-ons you've reviewed so that, on a later scan,
the tool can say one of three things about a file:

    new       — never seen this add-on (by name) before
    known     — seen before and the content is UNCHANGED since it was recorded
    CHANGED   — seen before but the content is DIFFERENT now (an update — which is
                exactly when a previously-clean add-on can turn malicious)

The store is a small JSON file keyed by the add-on's file name. It holds no code,
only a fingerprint (SHA-256) and the recorded verdict/metadata.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path


STATUS_NEW = "new"
STATUS_KNOWN = "known"
STATUS_CHANGED = "CHANGED"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def load(db_path: str | Path) -> dict:
    p = Path(db_path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save(db_path: str | Path, db: dict) -> None:
    Path(db_path).write_text(json.dumps(db, indent=2, sort_keys=True), encoding="utf-8")


def _now() -> str:
    return datetime.datetime.now().replace(microsecond=0).isoformat()


def status(db: dict, key: str, digest: str) -> tuple[str, dict | None]:
    """Return (status, previous_record). previous_record is None when new."""
    rec = db.get(key)
    if rec is None:
        return STATUS_NEW, None
    if rec.get("hash") == digest:
        return STATUS_KNOWN, rec
    return STATUS_CHANGED, rec


def remember(db: dict, key: str, digest: str, *, verdict: str,
             risk_score: int, capabilities: list[str]) -> dict:
    """Insert/refresh the record for `key`, preserving first_seen. Returns record."""
    prev = db.get(key)
    now = _now()
    record = {
        "hash": digest,
        "verdict": verdict,
        "risk_score": risk_score,
        "capabilities": capabilities,
        "first_seen": prev.get("first_seen", now) if prev else now,
        "last_recorded": now,
    }
    db[key] = record
    return record
