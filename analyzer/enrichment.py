"""Generate, enrich, and persist MITRE-tagged, risk-scored alerts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from analyzer.database import get_events, insert_alerts
from analyzer.detector import DetectionConfig, detect_events
from analyzer.mitre_mapping import map_alert
from analyzer.risk_scoring import RiskScoringConfig, calculate_risk


def _alert_id(alert: dict[str, Any]) -> str:
    identity = {
        "alert_type": alert.get("alert_type"),
        "timestamp": alert.get("timestamp"),
        "source_ip": alert.get("source_ip"),
        "session_id": alert.get("session_id"),
        "related_event_ids": alert.get("related_event_ids", []),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "alert-" + hashlib.sha256(encoded).hexdigest()[:24]


def enrich_alerts(
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    risk_config: RiskScoringConfig | None = None,
) -> list[dict[str, Any]]:
    """Add a stable ID, best-supported ATT&CK mapping, and transparent score."""
    enriched = []
    for alert in alerts:
        result = dict(alert)
        result["alert_id"] = _alert_id(alert)
        result.update(map_alert(alert, events))
        result.update(calculate_risk(alert, events, alerts, risk_config))
        enriched.append(result)
    return enriched


def analyze_database(
    database_path: str | Path | None = None,
    detection_config: DetectionConfig | None = None,
    risk_config: RiskScoringConfig | None = None,
) -> list[dict[str, Any]]:
    """Detect stored events, enrich alerts, and persist alerts without duplicates."""
    events = get_events(database_path)
    detections = detect_events(events, detection_config)
    enriched = enrich_alerts(detections, events, risk_config)
    insert_alerts(enriched, database_path)
    return enriched
