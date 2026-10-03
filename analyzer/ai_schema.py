"""Schema and local validation for session-level AI analysis results."""

from __future__ import annotations

import json
from typing import Any

from analyzer.deception_profiles import ALLOWED_PROFILE_NAMES


class AIResponseValidationError(ValueError):
    """Raised when a model response is malformed or does not match the contract."""


PATTERN_TYPES = [
    "reconnaissance",
    "system_discovery",
    "credential_discovery",
    "network_discovery",
    "payload_download",
    "command_sequence",
    "repeated_attempts",
    "activity_escalation",
    "other",
]
ATTACK_STAGES = [
    "reconnaissance",
    "initial_access",
    "discovery",
    "credential_access",
    "execution",
    "payload_delivery",
    "command_and_control",
    "post_access",
    "unknown",
]

ANALYSIS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "behavior_summary": {"type": "string"},
        "attack_stage": {"type": "string", "enum": ATTACK_STAGES},
        "observed_facts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "event_ids": {"type": "array", "items": {"type": "integer"}},
                    "fact": {"type": "string"},
                },
                "required": ["event_ids", "fact"],
                "additionalProperties": False,
            },
        },
        "observed_patterns": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "enum": PATTERN_TYPES},
                    "event_ids": {"type": "array", "items": {"type": "integer"}},
                    "interpretation": {"type": "string"},
                },
                "required": ["pattern", "event_ids", "interpretation"],
                "additionalProperties": False,
            },
        },
        "likely_objective": {"type": "string"},
        "recommended_profile": {"type": "string", "enum": list(ALLOWED_PROFILE_NAMES)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "uncertainty": {"type": "string"},
        "analyst_summary": {"type": "string"},
    },
    "required": [
        "behavior_summary",
        "attack_stage",
        "observed_facts",
        "observed_patterns",
        "likely_objective",
        "recommended_profile",
        "confidence",
        "uncertainty",
        "analyst_summary",
    ],
    "additionalProperties": False,
}

_REQUIRED_FIELDS = set(ANALYSIS_JSON_SCHEMA["required"])


def parse_analysis_response(
    response_text: str, allowed_event_ids: set[int] | None = None
) -> dict[str, Any]:
    """Parse JSON and enforce the analysis contract and evidence references."""
    try:
        data = json.loads(response_text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise AIResponseValidationError("Response was not valid JSON.") from exc

    if not isinstance(data, dict):
        raise AIResponseValidationError("Response must be a JSON object.")
    missing = _REQUIRED_FIELDS - data.keys()
    extra = data.keys() - _REQUIRED_FIELDS
    if missing:
        raise AIResponseValidationError("Response is missing required fields.")
    if extra:
        raise AIResponseValidationError("Response contains unsupported fields.")

    for field in (
        "behavior_summary", "likely_objective", "uncertainty", "analyst_summary"
    ):
        if not isinstance(data[field], str) or not data[field].strip():
            raise AIResponseValidationError(f"{field} must be a non-empty string.")
    if data["attack_stage"] not in ATTACK_STAGES:
        raise AIResponseValidationError("attack_stage is not supported.")
    if data["recommended_profile"] not in ALLOWED_PROFILE_NAMES:
        raise AIResponseValidationError("recommended_profile is not supported.")
    confidence = data["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise AIResponseValidationError("confidence must be a number from 0 to 1.")
    if not 0 <= confidence <= 1:
        raise AIResponseValidationError("confidence must be a number from 0 to 1.")
    if not isinstance(data["observed_facts"], list):
        raise AIResponseValidationError("observed_facts must be a list.")
    if not isinstance(data["observed_patterns"], list):
        raise AIResponseValidationError("observed_patterns must be a list.")

    for fact in data["observed_facts"]:
        if (
            not isinstance(fact, dict)
            or set(fact) != {"event_ids", "fact"}
            or not isinstance(fact["event_ids"], list)
            or not all(type(event_id) is int for event_id in fact["event_ids"])
            or not isinstance(fact["fact"], str)
            or not fact["fact"].strip()
        ):
            raise AIResponseValidationError("An observed fact has an invalid shape.")
        _validate_evidence_ids(fact["event_ids"], allowed_event_ids)

    for pattern in data["observed_patterns"]:
        if (
            not isinstance(pattern, dict)
            or set(pattern) != {"pattern", "event_ids", "interpretation"}
            or pattern["pattern"] not in PATTERN_TYPES
            or not isinstance(pattern["event_ids"], list)
            or not all(type(event_id) is int for event_id in pattern["event_ids"])
            or not isinstance(pattern["interpretation"], str)
            or not pattern["interpretation"].strip()
        ):
            raise AIResponseValidationError("An observed pattern has an invalid shape.")
        _validate_evidence_ids(pattern["event_ids"], allowed_event_ids)

    return data


def _validate_evidence_ids(
    event_ids: list[int], allowed_event_ids: set[int] | None
) -> None:
    if allowed_event_ids is not None and not set(event_ids).issubset(allowed_event_ids):
        raise AIResponseValidationError("Response referenced an event ID outside this session.")
