"""Normalize Cowrie JSON audit events for later security analysis."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

_EVENT_TYPES = {
    "cowrie.session.connect": "session_start",
    "cowrie.session.closed": "session_end",
    "cowrie.login.success": "login_success",
    "cowrie.login.failed": "login_failed",
    "cowrie.command.input": "command",
    "cowrie.command.success": "command",
    "cowrie.command.failed": "command",
}


def normalize_event(raw_event: Mapping[str, Any]) -> dict[str, Any] | None:
    """Convert one Cowrie JSON event to a normalized event.

    Unsupported Cowrie event IDs return None. Credential fields such as
    ``password`` are intentionally never copied to the normalized output.
    """
    event_id = raw_event.get("eventid")
    event_type = _EVENT_TYPES.get(event_id)
    if event_type is None:
        return None

    event: dict[str, Any] = {
        "timestamp": raw_event.get("timestamp"),
        "source_ip": raw_event.get("src_ip"),
        "session_id": raw_event.get("session"),
        "event_type": event_type,
    }

    username = raw_event.get("username")
    if username is not None:
        event["username"] = username

    if event_type == "command":
        command = raw_event.get("input")
        if command is not None:
            event["command"] = command
        realm = raw_event.get("realm")
        if realm is not None:
            event["realm"] = realm

    if event_type in {"login_success", "login_failed"}:
        event["login_result"] = "success" if event_type == "login_success" else "failed"

    return event


def parse_lines(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Yield normalized events from Cowrie JSON Lines, skipping other event IDs."""
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw_event = json.loads(line.lstrip("\ufeff"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid Cowrie JSON on line {line_number}: {exc.msg}") from exc
        if not isinstance(raw_event, dict):
            raise ValueError(f"Cowrie event on line {line_number} must be a JSON object")
        event = normalize_event(raw_event)
        if event is not None:
            yield event


def parse_file(path: str | Path) -> list[dict[str, Any]]:
    """Read a Cowrie JSON Lines log file and return its supported events."""
    with Path(path).open("r", encoding="utf-8-sig") as log_file:
        return list(parse_lines(log_file))

