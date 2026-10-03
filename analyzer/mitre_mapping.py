"""Resolve alert behavior to a curated MITRE ATT&CK mapping."""

from __future__ import annotations

import re
from typing import Any

from analyzer.mitre_mapping_data import BEHAVIOR_MAPPINGS, DETECTION_MAPPINGS, TECHNIQUES

_COMMAND = re.compile(r"[a-z0-9_./-]+", re.IGNORECASE)


def _command_behavior(command: str) -> str | None:
    """Return the first explicitly supported behavior present in a command."""
    for segment in re.split(r"(?:&&|\|\||[;|&])", command.lower()):
        tokens = [token.lower() for token in _COMMAND.findall(segment)]
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1]
        if executable in {"whoami", "id"}:
            return "system_user_discovery"
        if executable == "uname":
            return "system_information_discovery"
        if executable in {"ip", "ifconfig"} and (
            executable == "ifconfig" or (len(tokens) > 1 and tokens[1] == "addr")
        ):
            return "network_configuration_discovery"
        if executable in {"ls", "find"}:
            return "file_directory_discovery"
        if executable == "cat" and "/etc/passwd" in tokens[1:]:
            return "passwd_file_access"
        if executable in {"wget", "curl"}:
            return "download_command"
        if executable == "chmod":
            return "permission_modification"
        if executable == "bash":
            return "unix_shell_execution"
        if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
            return "python_interpreter_execution"
        if executable in {"nc", "ncat"}:
            return "network_utility_usage"
    return None


def map_alert(
    alert: dict[str, Any], events: list[dict[str, Any]]
) -> dict[str, str | None]:
    """Return MITRE fields for an alert, or explicit None fields if unmapped."""
    event_lookup = {event.get("id"): event for event in events if event.get("id") is not None}
    behavior_key = DETECTION_MAPPINGS.get(alert.get("alert_type"))

    if behavior_key is None and alert.get("alert_type") == "suspicious_command":
        for event_id in alert.get("related_event_ids", []):
            event = event_lookup.get(event_id)
            if event and event.get("command"):
                behavior_key = _command_behavior(str(event["command"]))
                if behavior_key:
                    break

    behavior = BEHAVIOR_MAPPINGS.get(behavior_key) if behavior_key else None
    if behavior is None:
        return {
            "mitre_technique_id": None,
            "mitre_technique_name": None,
            "mitre_tactic": None,
            "mitre_explanation": None,
            "mapped_behavior": None,
        }

    technique_id = behavior["technique_id"]
    technique = TECHNIQUES[technique_id]
    return {
        "mitre_technique_id": technique_id,
        "mitre_technique_name": technique["name"],
        "mitre_tactic": technique["tactic"],
        "mitre_explanation": behavior["explanation"],
        "mapped_behavior": behavior_key,
    }
