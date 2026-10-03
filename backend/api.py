"""Read-focused API routes over existing SQLite events, alerts, and analyses."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from analyzer.database import get_alerts, get_events
from analyzer.deception_store import get_profile_selections
from analyzer.session_context import aggregate_sessions

Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["Low", "Medium", "High", "Critical"]
EventType = Literal["session_start", "session_end", "login_success", "login_failed", "command"]
AlertType = Literal[
    "brute_force", "success_after_repeated_failures", "suspicious_command", "command_burst"
]


def create_api_router(database_path: str | Path | None = None) -> APIRouter:
    router = APIRouter(prefix="/api")

    def data():
        events = get_events(database_path)
        alerts = get_alerts(database_path)
        profiles = get_profile_selections(database_path)
        return events, alerts, profiles

    @router.get("/stats/overview")
    def overview_stats():
        events, alerts, _ = data()
        scores = [int(alert.get("risk_score", 0)) for alert in alerts]
        return {
            "total_events": len(events),
            "total_sessions": len({event["session_id"] for event in events if event.get("session_id")}),
            "unique_source_ips": len({event["source_ip"] for event in events if event.get("source_ip")}),
            "total_alerts": len(alerts),
            "high_critical_alerts": sum(
                alert.get("risk_level") in {"High", "Critical"} for alert in alerts
            ),
            "average_risk_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        }

    @router.get("/events")
    def list_events(
        source_ip: str | None = Query(default=None, min_length=1, max_length=64),
        session_id: str | None = Query(default=None, min_length=1, max_length=256),
        event_type: EventType | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ):
        events, _, _ = data()
        filtered = [
            event for event in events
            if (source_ip is None or event.get("source_ip") == source_ip)
            and (session_id is None or event.get("session_id") == session_id)
            and (event_type is None or event.get("event_type") == event_type)
        ]
        filtered.sort(key=lambda event: (event.get("timestamp") or "", event.get("id", 0)), reverse=True)
        return {"items": filtered[offset:offset + limit], "total": len(filtered), "limit": limit, "offset": offset}

    @router.get("/alerts")
    def list_alerts(
        severity: Severity | None = None,
        risk_level: RiskLevel | None = None,
        source_ip: str | None = Query(default=None, min_length=1, max_length=64),
        alert_type: AlertType | None = None,
        session_id: str | None = Query(default=None, min_length=1, max_length=256),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ):
        _, alerts, _ = data()
        filtered = [
            alert for alert in alerts
            if (severity is None or str(alert.get("severity", "")).lower() == severity)
            and (risk_level is None or alert.get("risk_level") == risk_level)
            and (source_ip is None or alert.get("source_ip") == source_ip)
            and (alert_type is None or alert.get("alert_type") == alert_type)
            and (session_id is None or alert.get("session_id") == session_id)
        ]
        filtered.sort(key=lambda alert: (alert.get("timestamp") or "", alert.get("alert_id", "")), reverse=True)
        return {"items": filtered[offset:offset + limit], "total": len(filtered), "limit": limit, "offset": offset}

    @router.get("/sessions")
    def list_sessions(
        source_ip: str | None = Query(default=None, min_length=1, max_length=64),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ):
        events, alerts, profiles = data()
        profile_by_session = {item["session_id"]: item for item in profiles}
        summaries = [_session_summary(context, profile_by_session.get(context["session_id"]))
                     for context in aggregate_sessions(events, alerts)]
        if source_ip:
            summaries = [item for item in summaries if item.get("source_ip") == source_ip]
        summaries.sort(key=lambda item: (item.get("last_activity_at") or "", item["session_id"]), reverse=True)
        return {"items": summaries[offset:offset + limit], "total": len(summaries), "limit": limit, "offset": offset}

    @router.get("/sessions/{session_id}")
    def session_detail(session_id: str):
        events, alerts, profiles = data()
        contexts = aggregate_sessions(events, alerts)
        context = next((item for item in contexts if item["session_id"] == session_id), None)
        if context is None:
            raise HTTPException(status_code=404, detail="Session not found")
        profile = next((item for item in profiles if item["session_id"] == session_id), None)
        session_events = [event for event in events if event.get("session_id") == session_id]
        return {
            **_session_summary(context, profile),
            "authentication_activity": context["authentication_activity"],
            "command_sequence": context["commands"],
            "event_sequence": context["event_sequence"],
            "related_alerts": context["existing_detections"],
            "mitre_techniques": _techniques_from_alerts(context["existing_detections"]),
            "events": session_events,
        }

    @router.get("/sessions/{session_id}/ai")
    def session_ai(session_id: str):
        _, _, profiles = data()
        item = next((row for row in profiles if row["session_id"] == session_id), None)
        if item is None or item.get("analysis") is None:
            raise HTTPException(status_code=404, detail="AI analysis not found for session")
        return {"session_id": session_id, "status": item["analysis_status"], "analysis": item["analysis"]}

    @router.get("/sessions/{session_id}/deception")
    def session_deception(session_id: str):
        _, _, profiles = data()
        item = next((row for row in profiles if row["session_id"] == session_id), None)
        if item is None:
            raise HTTPException(status_code=404, detail="Deception profile not found for session")
        return {"session_id": session_id, "profile_name": item["profile_name"], "profile": item["profile"]}

    @router.get("/sources")
    def source_summary():
        events, alerts, _ = data()
        by_source: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            if event.get("source_ip"):
                by_source[event["source_ip"]].append(event)
        result = []
        for source_ip, source_events in by_source.items():
            source_alerts = [alert for alert in alerts if alert.get("source_ip") == source_ip]
            max_risk = max((int(alert.get("risk_score", 0)) for alert in source_alerts), default=0)
            result.append({
                "source_ip": source_ip,
                "event_count": len(source_events),
                "session_count": len({event.get("session_id") for event in source_events if event.get("session_id")}),
                "alert_count": len(source_alerts),
                "max_risk_score": max_risk,
                "risk_level": next((alert.get("risk_level") for alert in source_alerts
                                     if int(alert.get("risk_score", 0)) == max_risk), None),
                "last_seen": max((event.get("timestamp") or "" for event in source_events), default=None),
            })
        return sorted(result, key=lambda item: (item["max_risk_score"], item["event_count"]), reverse=True)

    @router.get("/mitre/techniques")
    def mitre_summary():
        _, alerts, _ = data()
        counts: Counter[tuple[str, str, str]] = Counter()
        for alert in alerts:
            technique_id = alert.get("mitre_technique_id")
            if technique_id:
                key = (technique_id, alert.get("mitre_technique_name") or "Unknown technique",
                       alert.get("mitre_tactic") or "Unknown tactic")
                counts[key] += 1
        return [
            {"technique_id": key[0], "technique_name": key[1], "tactic": key[2], "occurrences": count}
            for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0][0]))
        ]

    @router.get("/risk-distribution")
    def risk_distribution():
        _, alerts, _ = data()
        counts = Counter(alert.get("risk_level") for alert in alerts)
        levels = ("Low", "Medium", "High", "Critical")
        return [{"risk_level": level, "count": counts.get(level, 0)} for level in levels]

    @router.get("/ai-analyses")
    def ai_analyses():
        _, _, profiles = data()
        return [
            {"session_id": item["session_id"], "status": item["analysis_status"],
             "analysis": item["analysis"], "selected_profile": item["profile_name"],
             "selected_at": item["selected_at"]}
            for item in profiles
        ]

    return router


def _session_summary(context: dict, profile: dict | None) -> dict:
    alerts = context["existing_detections"]
    max_risk = max((int(alert.get("risk_score", 0)) for alert in alerts), default=None)
    profile_data = profile or {}
    analysis = profile_data.get("analysis") or {}
    return {
        "session_id": context["session_id"],
        "source_ip": context["source_ip"],
        "username": ", ".join(context["usernames"]) or None,
        "usernames": context["usernames"],
        "started_at": context["started_at"],
        "ended_at": next((item["timestamp"] for item in reversed(context["event_sequence"])
                          if item.get("event_type") == "session_end"), None),
        "last_activity_at": context["last_activity_at"],
        "event_count": len(context["event_sequence"]),
        "authentication_count": len(context["authentication_activity"]),
        "command_count": len(context["commands"]),
        "alert_count": len(alerts),
        "mitre_technique_ids": context["mitre_technique_ids"],
        "risk_score": max_risk,
        "risk_level": next((alert.get("risk_level") for alert in alerts
                             if alert.get("risk_score") == max_risk), None),
        "ai_behavior_summary": analysis.get("behavior_summary"),
        "ai_confidence": analysis.get("confidence"),
        "deception_profile": profile_data.get("profile_name"),
        "deception_profile_data": profile_data.get("profile"),
    }


def _techniques_from_alerts(alerts: list[dict]) -> list[dict]:
    unique = {}
    for alert in alerts:
        technique_id = alert.get("mitre_technique_id")
        if technique_id:
            unique[technique_id] = {
                "technique_id": technique_id,
                "technique_name": alert.get("mitre_technique_name"),
                "tactic": alert.get("mitre_tactic"),
            }
    return list(unique.values())
