"""SQLite persistence for normalized Cowrie security events."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

_DEFAULT_DATABASE_PATH = "data/security_events.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    session_id TEXT,
    username TEXT,
    event_type TEXT NOT NULL,
    command TEXT,
    login_result TEXT
)
"""


_ALERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    timestamp TEXT,
    source_ip TEXT,
    session_id TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    mitre_tactic TEXT,
    mitre_explanation TEXT,
    mapped_behavior TEXT,
    description TEXT NOT NULL,
    related_event_ids_json TEXT NOT NULL,
    risk_factors_json TEXT NOT NULL
)
"""
def get_database_path(database_path: str | Path | None = None) -> str:
    """Return the explicit path, environment path, or project default."""
    configured_path = database_path or os.environ.get(
        "HONEYPOT_DATABASE_PATH", _DEFAULT_DATABASE_PATH
    )
    return str(configured_path)


def _connect(database_path: str | Path | None = None) -> sqlite3.Connection:
    path = get_database_path(database_path)
    if path != ":memory:":
        expanded_path = Path(path).expanduser()
        expanded_path.parent.mkdir(parents=True, exist_ok=True)
        path = str(expanded_path)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(database_path: str | Path | None = None) -> None:
    """Create the security event table if it does not already exist."""
    with closing(_connect(database_path)) as connection:
        with connection:
            connection.execute(_SCHEMA)
            connection.execute(_ALERTS_SCHEMA)


def insert_event(
    event: Mapping[str, Any], database_path: str | Path | None = None
) -> int:
    """Persist one normalized event and return its database ID."""
    return insert_events([event], database_path)[0]


def insert_events(
    events: Iterable[Mapping[str, Any]], database_path: str | Path | None = None
) -> list[int]:
    """Persist normalized events in one transaction; initialize schema first."""
    event_list = list(events)
    if not event_list:
        initialize_database(database_path)
        return []

    inserted_ids: list[int] = []
    with closing(_connect(database_path)) as connection:
        with connection:
            connection.execute(_SCHEMA)
            connection.execute(_ALERTS_SCHEMA)
            for event in event_list:
                cursor = connection.execute(
                    """INSERT INTO security_events
                       (timestamp, source_ip, session_id, username, event_type,
                        command, login_result)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.get("timestamp"),
                        event.get("source_ip"),
                        event.get("session_id"),
                        event.get("username"),
                        event.get("event_type"),
                        event.get("command"),
                        event.get("login_result"),
                    ),
                )
                inserted_ids.append(int(cursor.lastrowid))
    return inserted_ids


def get_event(
    event_id: int, database_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Retrieve one event by ID, or return None if it does not exist."""
    initialize_database(database_path)
    with closing(_connect(database_path)) as connection:
        row = connection.execute(
            "SELECT * FROM security_events WHERE id = ?", (event_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def get_events(database_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return all persisted events in insertion order."""
    initialize_database(database_path)
    with closing(_connect(database_path)) as connection:
        rows = connection.execute(
            "SELECT * FROM security_events ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


def insert_alerts(
    alerts: Iterable[Mapping[str, Any]], database_path: str | Path | None = None
) -> int:
    """Insert or refresh alerts by stable ID without making duplicate rows."""
    alert_list = list(alerts)
    initialize_database(database_path)
    inserted = 0
    with closing(_connect(database_path)) as connection:
        with connection:
            for alert in alert_list:
                cursor = connection.execute(
                    """INSERT INTO security_alerts (
                       alert_id, alert_type, timestamp, source_ip, session_id,
                       severity, risk_score, risk_level, mitre_technique_id,
                       mitre_technique_name, mitre_tactic, mitre_explanation,
                       mapped_behavior, description, related_event_ids_json,
                       risk_factors_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alert_id) DO UPDATE SET
                        alert_type=excluded.alert_type,
                        timestamp=excluded.timestamp,
                        source_ip=excluded.source_ip,
                        session_id=excluded.session_id,
                        severity=excluded.severity,
                        risk_score=excluded.risk_score,
                        risk_level=excluded.risk_level,
                        mitre_technique_id=excluded.mitre_technique_id,
                        mitre_technique_name=excluded.mitre_technique_name,
                        mitre_tactic=excluded.mitre_tactic,
                        mitre_explanation=excluded.mitre_explanation,
                        mapped_behavior=excluded.mapped_behavior,
                        description=excluded.description,
                        related_event_ids_json=excluded.related_event_ids_json,
                        risk_factors_json=excluded.risk_factors_json""",
                    (
                        alert["alert_id"],
                        alert["alert_type"],
                        alert.get("timestamp"),
                        alert.get("source_ip"),
                        alert.get("session_id"),
                        alert["severity"],
                        alert["risk_score"],
                        alert["risk_level"],
                        alert.get("mitre_technique_id"),
                        alert.get("mitre_technique_name"),
                        alert.get("mitre_tactic"),
                        alert.get("mitre_explanation"),
                        alert.get("mapped_behavior"),
                        alert["description"],
                        json.dumps(alert.get("related_event_ids", [])),
                        json.dumps(alert.get("risk_factors", {}), sort_keys=True),
                    ),
                )
                inserted += max(cursor.rowcount, 0)
    return inserted


def get_alerts(database_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return persisted enriched alerts with decoded JSON fields."""
    initialize_database(database_path)
    with closing(_connect(database_path)) as connection:
        rows = connection.execute(
            "SELECT * FROM security_alerts ORDER BY timestamp, alert_id"
        ).fetchall()
    alerts = []
    for row in rows:
        alert = dict(row)
        alert["related_event_ids"] = json.loads(alert.pop("related_event_ids_json"))
        alert["risk_factors"] = json.loads(alert.pop("risk_factors_json"))
        alerts.append(alert)
    return alerts


