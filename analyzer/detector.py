"""Explainable rule-based detections over normalized Cowrie events."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from analyzer.database import get_events


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds and time windows for the initial detection rules."""

    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    success_after_failures_threshold: int = 3
    success_after_failures_window_seconds: int = 600
    command_burst_threshold: int = 10
    command_burst_window_seconds: int = 60

    def __post_init__(self) -> None:
        for name in (
            "brute_force_threshold",
            "success_after_failures_threshold",
            "command_burst_threshold",
        ):
            if getattr(self, name) < 2:
                raise ValueError(f"{name} must be at least 2")
        for name in (
            "brute_force_window_seconds",
            "success_after_failures_window_seconds",
            "command_burst_window_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


def _event_time(event: dict[str, Any]) -> datetime:
    value = event.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("Security event timestamp must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid security event timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=lambda event: (_event_time(event), event.get("id", 0)))


def _related_ids(events: list[dict[str, Any]]) -> list[int | str]:
    return [event["id"] for event in events if event.get("id") is not None]


def _alert(
    *,
    alert_type: str,
    event: dict[str, Any],
    severity: str,
    description: str,
    related_events: list[dict[str, Any]],
    session_id: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "alert_type": alert_type,
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("source_ip"),
        "session_id": session_id if session_id is not None else event.get("session_id"),
        "severity": severity,
        "description": description,
        "related_event_ids": _related_ids(related_events),
    }
    return result


def _failed_logins(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event for event in events
        if event.get("event_type") == "login_failed" and event.get("source_ip")
    ]


def _detect_brute_force(
    events: list[dict[str, Any]], config: DetectionConfig
) -> list[dict[str, Any]]:
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in _failed_logins(events):
        by_ip[event["source_ip"]].append(event)

    alerts = []
    window = timedelta(seconds=config.brute_force_window_seconds)
    for source_ip, attempts in by_ip.items():
        attempts = _sort_events(attempts)
        start = 0
        while start + config.brute_force_threshold <= len(attempts):
            end = start
            while end < len(attempts) and (
                _event_time(attempts[end]) - _event_time(attempts[start]) <= window
            ):
                end += 1
            if end - start >= config.brute_force_threshold:
                group = attempts[start:end]
                trigger_event = group[config.brute_force_threshold - 1]
                alerts.append(_alert(
                    alert_type="brute_force",
                    event=trigger_event,
                    severity="medium",
                    description=(
                        f"Observed {len(group)} failed login attempts from {source_ip} "
                        f"within {config.brute_force_window_seconds} seconds. "
                        "This pattern may also result from repeated user error."
                    ),
                    related_events=group,
                ))
                start = end
            else:
                start += 1
    return alerts


def _detect_success_after_failures(
    events: list[dict[str, Any]], config: DetectionConfig
) -> list[dict[str, Any]]:
    failed_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    successes = []
    for event in events:
        if event.get("event_type") == "login_failed" and event.get("source_ip"):
            failed_by_ip[event["source_ip"]].append(event)
        elif event.get("event_type") == "login_success" and event.get("source_ip"):
            successes.append(event)

    alerts = []
    window = timedelta(seconds=config.success_after_failures_window_seconds)
    for success in _sort_events(successes):
        success_time = _event_time(success)
        recent_failures = [
            failure for failure in failed_by_ip[success["source_ip"]]
            if timedelta(0) < success_time - _event_time(failure) <= window
        ]
        if len(recent_failures) >= config.success_after_failures_threshold:
            related = recent_failures + [success]
            alerts.append(_alert(
                alert_type="success_after_repeated_failures",
                event=success,
                severity="high",
                description=(
                    f"A successful login followed {len(recent_failures)} failed login "
                    f"attempts from {success['source_ip']} within "
                    f"{config.success_after_failures_window_seconds} seconds. "
                    "Review the sequence; this alone does not prove compromise."
                ),
                related_events=related,
            ))
    return alerts


_COMMAND_TOKEN = re.compile(r"[a-z0-9_./-]+", re.IGNORECASE)
_HIGHER_INTEREST = {"wget", "curl", "chmod", "bash", "nc", "ncat"}
_RECON_COMMANDS = {"whoami", "uname", "id", "ifconfig", "ls", "find"}


def _command_indicators(command: str) -> tuple[list[str], str | None]:
    indicators: list[str] = []
    severity = "low"
    command_segments = re.split(r"(?:&&|\|\||[;|&])", command.lower())

    for segment in command_segments:
        tokens = [token.lower() for token in _COMMAND_TOKEN.findall(segment)]
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1]

        if executable in _RECON_COMMANDS:
            indicators.append(executable)
        elif executable == "ip" and len(tokens) > 1 and tokens[1] == "addr":
            indicators.append("ip addr")
        elif executable == "cat" and "/etc/passwd" in tokens[1:]:
            indicators.append("cat /etc/passwd")
            severity = "medium"
        elif executable in _HIGHER_INTEREST:
            indicators.append(executable)
            severity = "medium"
        elif re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
            indicators.append(executable)
            severity = "medium"

    return list(dict.fromkeys(indicators)), severity if indicators else None

def _detect_suspicious_commands(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    alerts = []
    for event in events:
        if event.get("event_type") != "command" or not event.get("command"):
            continue
        indicators, severity = _command_indicators(str(event["command"]))
        if not indicators:
            continue
        command = str(event["command"])
        alerts.append(_alert(
            alert_type="suspicious_command",
            event=event,
            severity=severity or "low",
            description=(
                f"Observed command {command!r} matching indicators: "
                f"{', '.join(indicators)}. This is recorded for review and is not "
                "classified as malicious by itself."
            ),
            related_events=[event],
        ))
    return alerts


def _detect_command_bursts(
    events: list[dict[str, Any]], config: DetectionConfig
) -> list[dict[str, Any]]:
    by_session: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        session_id = event.get("session_id")
        source_ip = event.get("source_ip")
        if event.get("event_type") == "command" and session_id and source_ip:
            by_session[(source_ip, session_id)].append(event)

    alerts = []
    window = timedelta(seconds=config.command_burst_window_seconds)
    for (source_ip, session_id), commands in by_session.items():
        commands = _sort_events(commands)
        start = 0
        while start + config.command_burst_threshold <= len(commands):
            end = start
            while end < len(commands) and (
                _event_time(commands[end]) - _event_time(commands[start]) <= window
            ):
                end += 1
            if end - start >= config.command_burst_threshold:
                group = commands[start:end]
                trigger_event = group[config.command_burst_threshold - 1]
                alerts.append(_alert(
                    alert_type="command_burst",
                    event=trigger_event,
                    severity="medium",
                    description=(
                        f"Observed {len(group)} commands in session {session_id} "
                        f"within {config.command_burst_window_seconds} seconds. "
                        "This activity rate may be legitimate automation."
                    ),
                    related_events=group,
                    session_id=session_id,
                ))
                start = end
            else:
                start += 1
    return alerts


def detect_events(
    events: list[dict[str, Any]], config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Run all initial rules against normalized security event dictionaries."""
    active_config = config or DetectionConfig()
    ordered_events = _sort_events(events)
    alerts = (
        _detect_brute_force(ordered_events, active_config)
        + _detect_success_after_failures(ordered_events, active_config)
        + _detect_suspicious_commands(ordered_events)
        + _detect_command_bursts(ordered_events, active_config)
    )
    return sorted(
        alerts,
        key=lambda alert: (
            alert.get("timestamp") or "",
            alert["alert_type"],
            tuple(alert["related_event_ids"]),
        ),
    )


def detect_database_events(
    database_path: str | Path | None = None, config: DetectionConfig | None = None
) -> list[dict[str, Any]]:
    """Load stored normalized events and return their deterministic alerts."""
    return detect_events(get_events(database_path), config)



