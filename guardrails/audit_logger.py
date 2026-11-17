"""Local hash-chained audit metadata store for demonstration.

Do not store raw customer messages, credentials, OTPs, PAN, Aadhaar or account data.
This is tamper-evident for accidental/unauthorized edits, not a substitute for
centralized immutable/WORM logging or a regulated production audit platform.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(os.getenv("SECUREFIN_AUDIT_DB", "data/securefin_audit.db"))
GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _connect(db_path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            verdict TEXT NOT NULL,
            rule_ids TEXT NOT NULL,
            correlation_id TEXT,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def log_event(
    event_type: str,
    verdict: str,
    rule_ids: list[str] | None = None,
    correlation_id: str | None = None,
    db_path: str | Path = DEFAULT_DB,
) -> dict[str, Any]:
    """Append metadata only; callers must never pass message bodies or secrets."""
    if not event_type or not verdict:
        raise ValueError("event_type and verdict are required.")
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = row[0] if row else GENESIS
        payload = {
            "event_id": str(uuid.uuid4()),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": str(event_type)[:80],
            "verdict": str(verdict)[:40],
            "rule_ids": [str(x)[:100] for x in (rule_ids or [])],
            "correlation_id": str(correlation_id)[:100] if correlation_id else None,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT INTO audit_events
            (event_id,timestamp_utc,event_type,verdict,rule_ids,correlation_id,previous_hash,event_hash)
            VALUES (?,?,?,?,?,?,?,?)""",
            (
                payload["event_id"], payload["timestamp_utc"], payload["event_type"],
                payload["verdict"], json.dumps(payload["rule_ids"]),
                payload["correlation_id"], previous_hash, event_hash,
            ),
        )
        conn.commit()
        return {**payload, "event_hash": event_hash}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def read_events(limit: int = 100, db_path: str | Path = DEFAULT_DB) -> list[dict[str, Any]]:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000.")
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT sequence,event_id,timestamp_utc,event_type,verdict,rule_ids,
            correlation_id,previous_hash,event_hash
            FROM audit_events ORDER BY sequence DESC LIMIT ?""", (limit,)
        ).fetchall()
        keys = ["sequence","event_id","timestamp_utc","event_type","verdict",
                "rule_ids","correlation_id","previous_hash","event_hash"]
        result = []
        for row in rows:
            item = dict(zip(keys, row))
            item["rule_ids"] = json.loads(item["rule_ids"])
            result.append(item)
        return result
    finally:
        conn.close()


def verify_chain(db_path: str | Path = DEFAULT_DB) -> dict[str, Any]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT event_id,timestamp_utc,event_type,verdict,rule_ids,
            correlation_id,previous_hash,event_hash
            FROM audit_events ORDER BY sequence ASC"""
        ).fetchall()
    finally:
        conn.close()

    previous = GENESIS
    for index, row in enumerate(rows, start=1):
        event_id, timestamp, event_type, verdict, rule_ids, correlation_id, stored_previous, stored_hash = row
        payload = {
            "event_id": event_id,
            "timestamp_utc": timestamp,
            "event_type": event_type,
            "verdict": verdict,
            "rule_ids": json.loads(rule_ids),
            "correlation_id": correlation_id,
            "previous_hash": stored_previous,
        }
        calculated = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
        if stored_previous != previous or calculated != stored_hash:
            return {"valid": False, "checked_events": index, "failed_sequence": index}
        previous = stored_hash
    return {"valid": True, "checked_events": len(rows), "failed_sequence": None}
