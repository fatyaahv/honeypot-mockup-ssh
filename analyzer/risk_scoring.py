"""Transparent internal prioritization scores for enriched alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class RiskScoringConfig:
    """Weights and windows used by the deterministic risk score."""

    related_alert_window_seconds: int = 300

    def __post_init__(self) -> None:
        if self.related_alert_window_seconds <= 0:
            raise ValueError("related_alert_window_seconds must be positive")


_SEVERITY_POINTS = {"low": 10, "medium": 25, "high": 40, "critical": 55}


def risk_level_for_score(score: int) -> str:
    """Convert a clamped 0–100 score into its documented priority category."""
    bounded_score = max(0, min(100, int(score)))
    if bounded_score < 25:
        return "Low"
    if bounded_score < 50:
        return "Medium"
    if bounded_score < 75:
        return "High"
    return "Critical"


def _event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def calculate_risk(
    alert: dict[str, Any],
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]] | None = None,
    config: RiskScoringConfig | None = None,
) -> dict[str, Any]:
    """Return score, level, and a point-by-point explanation for one alert.

    This is a prioritization heuristic, not a probability of compromise.
    """
    active_config = config or RiskScoringConfig()
    event_lookup = {event.get("id"): event for event in events if event.get("id") is not None}
    related_ids = list(dict.fromkeys(alert.get("related_event_ids", [])))
    related_events = [event_lookup[event_id] for event_id in related_ids if event_id in event_lookup]

    base = _SEVERITY_POINTS.get(str(alert.get("severity", "low")).lower(), 10)
    repeated = min(15, max(0, len(related_ids) - 1) * 5)
    successful_auth = 20 if any(
        event.get("event_type") == "login_success" for event in related_events
    ) else 0
    suspicious_command = 10 if alert.get("alert_type") == "suspicious_command" else 0

    session_id = alert.get("session_id")
    source_ip = alert.get("source_ip")
    session_events = [
        event for event in events
        if session_id
        and event.get("session_id") == session_id
        and (not source_ip or event.get("source_ip") == source_ip)
    ]
    session_activity = min(10, max(0, len(session_events) - 1) * 2)

    alert_time = _event_time(alert)
    related_alert_count = 0
    for other in alerts or []:
        if other is alert:
            continue
        same_session = bool(session_id and other.get("session_id") == session_id)
        same_source = bool(source_ip and other.get("source_ip") == source_ip)
        other_time = _event_time(other)
        within_window = (
            alert_time is None
            or other_time is None
            or abs(alert_time - other_time)
            <= timedelta(seconds=active_config.related_alert_window_seconds)
        )
        if (same_session or same_source) and within_window:
            related_alert_count += 1
    related_alerts = min(10, related_alert_count * 5)

    factors = {
        "base_severity": base,
        "repeated_related_activity": repeated,
        "successful_authentication": successful_auth,
        "suspicious_command": suspicious_command,
        "related_alerts": related_alerts,
        "session_activity": session_activity,
    }
    score = min(100, sum(factors.values()))
    return {
        "risk_score": score,
        "risk_level": risk_level_for_score(score),
        "risk_factors": factors,
    }
