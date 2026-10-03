"""Run optional, session-level AI analysis after deterministic enrichment."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analyzer.ai_provider import AIProvider, AIProviderError, provider_from_environment
from analyzer.ai_schema import AIResponseValidationError, parse_analysis_response
from analyzer.database import get_alerts, get_events
from analyzer.deception_profiles import select_profile
from analyzer.deception_store import save_profile_selection
from analyzer.detector import DetectionConfig
from analyzer.enrichment import analyze_database
from analyzer.session_context import aggregate_sessions


def analyze_session_contexts(
    contexts: list[dict[str, Any]], provider: AIProvider
) -> list[dict[str, Any]]:
    """Return one safe result per session; failures never modify deterministic alerts."""
    results = []
    for context in contexts:
        event_ids = {
            item["event_id"]
            for item in context.get("event_sequence", [])
            if type(item.get("event_id")) is int
        }
        try:
            raw_response = provider.analyze(context)
            analysis = parse_analysis_response(raw_response, event_ids)
        except AIResponseValidationError:
            results.append({
                "session_id": context["session_id"],
                "status": "invalid_response",
                "analysis": None,
                "error": "AI output did not satisfy the session analysis schema.",
            })
        except Exception as exc:
            # Provider exception text can contain request or service details; do not expose it.
            results.append({
                "session_id": context["session_id"],
                "status": "unavailable",
                "analysis": None,
                "error": "AI behavioral analysis could not be completed.",
            })
        else:
            results.append({
                "session_id": context["session_id"],
                "status": "ok",
                "analysis": analysis,
                "error": None,
            })
    return results


def analyze_database_sessions(
    database_path: str | Path | None = None,
    provider: AIProvider | None = None,
    detection_config: DetectionConfig | None = None,
) -> list[dict[str, Any]]:
    """Refresh deterministic detections, then analyze aggregated sessions.

    The AI result is returned separately and is never used to change scores or alerts.
    """
    analyze_database(database_path, detection_config)
    contexts = aggregate_sessions(get_events(database_path), get_alerts(database_path))
    if not contexts:
        return []
    try:
        active_provider = provider or provider_from_environment()
    except AIProviderError:
        return [
            {
                "session_id": context["session_id"],
                "status": "unavailable",
                "analysis": None,
                "error": "AI behavioral analysis is not configured.",
            }
            for context in contexts
        ]
    return analyze_session_contexts(contexts, active_provider)


def adapt_database_sessions(
    database_path: str | Path | None = None,
    provider: AIProvider | None = None,
    detection_config: DetectionConfig | None = None,
) -> list[dict[str, Any]]:
    """Run Phases 5–7, constrain suggestions to static profiles, and persist choices."""
    results = analyze_database_sessions(database_path, provider, detection_config)
    if not results:
        return []
    contexts = {
        context["session_id"]: context
        for context in aggregate_sessions(get_events(database_path), get_alerts(database_path))
    }
    adapted = []
    for result in results:
        context = contexts.get(result["session_id"], {})
        analysis = result.get("analysis") if result.get("status") == "ok" else None
        selection = select_profile(context, analysis)
        saved = save_profile_selection(
            result["session_id"], selection["profile"], selection["reason"],
            result["status"], analysis, database_path,
        )
        adapted.append({**result, "deception": saved})
    return adapted
