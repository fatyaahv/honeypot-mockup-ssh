"""Read Cowrie logs, normalize supported events, and persist them to SQLite."""

from __future__ import annotations

from pathlib import Path

from analyzer.cowrie_parser import parse_file
from analyzer.database import insert_events


def collect_cowrie_log(
    log_path: str | Path, database_path: str | Path | None = None
) -> int:
    """Parse one Cowrie JSON Lines log and store all supported events.

    Returns the number of normalized events persisted.
    """
    events = parse_file(log_path)
    insert_events(events, database_path)
    return len(events)
