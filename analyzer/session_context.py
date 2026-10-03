"""Build compact, credential-redacted per-session analysis context."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

MAX_CONTEXT_EVENTS = 250

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key)\s*=\s*)([^\s;&|]+)"
)
_SECRET_OPTION = re.compile(
    r"(?i)(--(?:password|passwd|token|secret|api-key)(?:=|\s+))([^\s;&|]+)"
)
_USER_OPTION = re.compile(r"(?i)((?:--user|-u)\s+)([^\s;&|]+)")
_SSHPASS_OPTION = re.compile(r"(?i)(sshpass\s+-p\s+)([^\s;&|]+)")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/@\s]+@")


def redact_command(command: str) -> str:
    """Remove common inline secret forms before commands leave the host."""
    redacted = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", command)
    for pattern in (_SECRET_ASSIGNMENT, _SECRET_OPTION, _USER_OPTION, _SSHPASS_OPTION):
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted[:1000]


def _event_sort_key(event: dict[str, Any]) -> tuple[str, int]:
    return (str(event.get("timestamp") or ""), int(event.get("id") or 0))


def aggregate_sessions(
    events: list[dict[str, Any]], alerts: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Group normalized events and earlier-stage detections into safe contexts."""
    by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        session_id = event.get("session_id")
        if session_id:
            by_session[str(session_id)].append(event)

    contexts = []
    for session_id, session_events in by_session.items():
        context = build_session_context(session_id, session_events, alerts or [])
        if context is not None:
            contexts.append(context)
    return sorted(contexts, key=lambda context: context["session_id"])


def build_session_context(
    session_id: str,
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Produce a compact session summary; do not copy raw Cowrie records."""
    session_events = sorted(
        [event for event in events if str(event.get("session_id") or "") == session_id],
        key=_event_sort_key,
    )
    if not session_events:
        return None

    included_events = session_events[-MAX_CONTEXT_EVENTS:]
    source_ip = next(
        (event.get("source_ip") for event in session_events if event.get("source_ip")),
        None,
    )
    usernames = list(dict.fromkeys(
        str(event["username"])
        for event in session_events
        if event.get("username") is not None
    ))
    auth_events = [
        event for event in included_events
        if event.get("event_type") in {"login_success", "login_failed"}
    ]
    authentication_activity = [
        {
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "result": event.get("login_result") or (
                "success" if event.get("event_type") == "login_success" else "failed"
            ),
            "username": event.get("username"),
        }
        for event in auth_events
    ]
    commands = [
        {
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "command": redact_command(str(event["command"])),
        }
        for event in included_events
        if event.get("event_type") == "command" and event.get("command")
    ]
    event_sequence = [
        {
            "event_id": event.get("id"),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
        }
        for event in included_events
    ]
    event_ids = {event.get("id") for event in session_events if event.get("id") is not None}
    session_alerts = [
        alert for alert in (alerts or [])
        if alert.get("session_id") == session_id
        or bool(event_ids.intersection(alert.get("related_event_ids", [])))
    ]
    detections = [
        {
            "alert_id": alert.get("alert_id"),
            "alert_type": alert.get("alert_type"),
            "timestamp": alert.get("timestamp"),
            "severity": alert.get("severity"),
            "risk_score": alert.get("risk_score"),
            "risk_level": alert.get("risk_level"),
            "mitre_technique_id": alert.get("mitre_technique_id"),
            "mitre_technique_name": alert.get("mitre_technique_name"),
            "mitre_tactic": alert.get("mitre_tactic"),
            "related_event_ids": alert.get("related_event_ids", []),
        }
        for alert in session_alerts
    ]
    technique_ids = list(dict.fromkeys(
        alert.get("mitre_technique_id")
        for alert in session_alerts
        if alert.get("mitre_technique_id")
    ))
    scores = [
        alert["risk_score"] for alert in session_alerts
        if isinstance(alert.get("risk_score"), (int, float))
    ]
    first_timestamp = session_events[0].get("timestamp")
    last_timestamp = session_events[-1].get("timestamp")

    return {
        "session_id": session_id,
        "source_ip": source_ip,
        "usernames": usernames,
        "started_at": first_timestamp,
        "last_activity_at": last_timestamp,
        "authentication_activity": authentication_activity,
        "commands": commands,
        "event_sequence": event_sequence,
        "existing_detections": detections,
        "mitre_technique_ids": technique_ids,
        "deterministic_risk_score": max(scores) if scores else None,
        "events_truncated": len(session_events) > len(included_events),
    }
