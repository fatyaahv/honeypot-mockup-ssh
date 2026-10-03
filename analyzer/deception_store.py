"""Persistence for selected fictional Cowrie profiles, separate from event rows."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analyzer.database import get_database_path
from analyzer.deception_profiles import profile_as_dict


_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_deception_profiles (
    session_id TEXT PRIMARY KEY,
    profile_name TEXT NOT NULL,
    selection_reason TEXT NOT NULL,
    analysis_status TEXT NOT NULL,
    analysis_json TEXT,
    profile_json TEXT NOT NULL,
    selected_at TEXT NOT NULL
)
"""


def save_profile_selection(
    session_id: str,
    profile_name: str,
    selection_reason: str,
    analysis_status: str,
    analysis: dict[str, Any] | None,
    database_path: str | Path | None = None,
) -> dict[str, Any]:
    """Upsert allowlisted profile data and the AI result into the configured SQLite DB."""
    path = get_database_path(database_path)
    if path != ":memory:":
        expanded = Path(path).expanduser()
        expanded.parent.mkdir(parents=True, exist_ok=True)
        path = str(expanded)
    selected_at = datetime.now(timezone.utc).isoformat()
    analysis_json = json.dumps(analysis, sort_keys=True) if analysis is not None else None
    # Never persist a caller-supplied profile body; materialize only this fixed catalog.
    profile_data = profile_as_dict(profile_name)
    profile_json = json.dumps(profile_data, sort_keys=True)
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            connection.execute(_SCHEMA)
            connection.execute(
                """INSERT INTO session_deception_profiles
               (session_id, profile_name, selection_reason, analysis_status,
                analysis_json, profile_json, selected_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET
                 profile_name=excluded.profile_name,
                 selection_reason=excluded.selection_reason,
                 analysis_status=excluded.analysis_status,
                 analysis_json=excluded.analysis_json,
                 profile_json=excluded.profile_json,
                 selected_at=excluded.selected_at""",
                (session_id, profile_name, selection_reason, analysis_status,
                 analysis_json, profile_json, selected_at),
            )
    return {
        "session_id": session_id,
        "profile_name": profile_name,
        "selection_reason": selection_reason,
        "analysis_status": analysis_status,
        "analysis": analysis,
        "profile": profile_data,
        "selected_at": selected_at,
    }


def get_profile_selections(database_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Read saved profile choices and decoded JSON values from SQLite."""
    path = get_database_path(database_path)
    if path != ":memory:" and not Path(path).expanduser().exists():
        return []
    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            ("session_deception_profiles",),
        ).fetchone()
        if table_exists is None:
            return []
        rows = connection.execute(
            "SELECT * FROM session_deception_profiles ORDER BY selected_at, session_id"
        ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["analysis"] = json.loads(item.pop("analysis_json")) if item.get("analysis_json") else None
        item["profile"] = json.loads(item.pop("profile_json"))
        results.append(item)
    return results
