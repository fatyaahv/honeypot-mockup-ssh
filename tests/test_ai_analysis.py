"""Mocked tests for safe, session-level AI behavioral analysis."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import URLError

from analyzer.ai_provider import AIProviderError, OpenAIResponsesProvider
from analyzer.behavior_analyzer import (
    analyze_database_sessions,
    analyze_session_contexts,
)
from analyzer.database import get_alerts, get_events, insert_events
from analyzer.session_context import aggregate_sessions, build_session_context


def make_event(event_id, event_type="command", command="whoami", **updates):
    event = {
        "id": event_id,
        "timestamp": f"2026-10-04T10:00:{event_id:02d}Z",
        "source_ip": "192.0.2.8",
        "session_id": "session-a",
        "username": "root",
        "event_type": event_type,
        "command": command if event_type == "command" else None,
        "login_result": None,
        "raw": {"password": "must-not-be-copied"},
    }
    event.update(updates)
    return event


def valid_response(event_ids=(1, 2)):
    return json.dumps({
        "behavior_summary": "The session includes authentication attempts followed by host discovery.",
        "attack_stage": "discovery",
        "observed_facts": [
            {"event_ids": [event_ids[-1]], "fact": "A host discovery command was entered."}
        ],
        "observed_patterns": [
            {
                "pattern": "system_discovery",
                "event_ids": list(event_ids),
                "interpretation": "The command sequence is consistent with system discovery.",
            }
        ],
        "likely_objective": "The operator may be orienting themselves in the simulated host.",
        "recommended_profile": "generic_linux",
        "confidence": 0.58,
        "uncertainty": "The short session does not establish the operator's objective.",
        "analyst_summary": "Observed discovery behavior; interpretation remains tentative.",
    })


class FakeProvider:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else valid_response()
        self.error = error
        self.contexts = []

    def analyze(self, context):
        self.contexts.append(context)
        if self.error:
            raise self.error
        return self.response


class AIBehaviorAnalysisTests(unittest.TestCase):
    def test_session_aggregation_and_context_include_multiple_detections(self):
        events = [
            make_event(1, "login_failed", login_result="failed"),
            make_event(2, command="uname -a"),
        ]
        alerts = [
            {"alert_id": "a1", "alert_type": "suspicious_command", "session_id": "session-a",
             "severity": "low", "risk_score": 20, "risk_level": "Low",
             "mitre_technique_id": "T1082", "mitre_technique_name": "System Information Discovery",
             "mitre_tactic": "discovery", "related_event_ids": [2]},
            {"alert_id": "a2", "alert_type": "failed_login_burst", "session_id": "session-a",
             "severity": "medium", "risk_score": 35, "risk_level": "Medium",
             "mitre_technique_id": "T1110", "mitre_technique_name": "Brute Force",
             "mitre_tactic": "credential-access", "related_event_ids": [1]},
        ]
        contexts = aggregate_sessions(events, alerts)
        self.assertEqual(len(contexts), 1)
        context = contexts[0]
        self.assertEqual([item["event_id"] for item in context["event_sequence"]], [1, 2])
        self.assertEqual(len(context["existing_detections"]), 2)
        self.assertEqual(context["mitre_technique_ids"], ["T1082", "T1110"])
        self.assertEqual(context["deterministic_risk_score"], 35)
        self.assertNotIn("raw", context)
        self.assertNotIn("password", json.dumps(context))

    def test_sensitive_command_arguments_are_redacted(self):
        context = build_session_context("session-a", [
            make_event(1, command="curl --token abc123 https://example.test"),
            make_event(2, command="sshpass -p dontsend ssh user@host"),
            make_event(3, command="curl -u alice:secret https://example.test"),
        ])
        commands = [entry["command"] for entry in context["commands"]]
        self.assertTrue(all(secret not in " ".join(commands) for secret in ("abc123", "dontsend", "alice:secret")))
        self.assertIn("[REDACTED]", " ".join(commands))

    def test_valid_structured_response_is_returned(self):
        provider = FakeProvider()
        result = analyze_session_contexts(aggregate_sessions([make_event(1), make_event(2)]), provider)
        self.assertEqual(result[0]["status"], "ok")
        self.assertEqual(result[0]["analysis"]["attack_stage"], "discovery")
        self.assertEqual(len(provider.contexts), 1)

    def test_malformed_and_missing_field_responses_are_safe(self):
        contexts = aggregate_sessions([make_event(1), make_event(2)])
        for response in ("not json", json.dumps({"behavior_summary": "missing fields"})):
            with self.subTest(response=response):
                result = analyze_session_contexts(contexts, FakeProvider(response=response))[0]
                self.assertEqual(result["status"], "invalid_response")
                self.assertIsNone(result["analysis"])
                self.assertNotIn(response, json.dumps(result))

    def test_untrusted_event_reference_is_rejected(self):
        response = valid_response(event_ids=(1, 999))
        context = aggregate_sessions([make_event(1), make_event(2)])
        result = analyze_session_contexts(context, FakeProvider(response=response))[0]
        self.assertEqual(result["status"], "invalid_response")

    def test_provider_failure_is_safe(self):
        contexts = aggregate_sessions([make_event(1)])
        result = analyze_session_contexts(
            contexts, FakeProvider(error=AIProviderError("secret service detail"))
        )[0]
        self.assertEqual(result["status"], "unavailable")
        self.assertNotIn("secret service detail", result["error"])

    def test_openai_provider_uses_mocked_structured_response(self):
        response_text = valid_response()
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({
            "status": "completed",
            "output": [{"type": "message", "content": [
                {"type": "output_text", "text": response_text}
            ]}],
        }).encode("utf-8")
        provider = OpenAIResponsesProvider(api_key="test-key", model="test-model")
        with patch("analyzer.ai_provider.urlopen", return_value=response) as mocked:
            self.assertEqual(provider.analyze({"session_id": "session-a"}), response_text)
        request = mocked.call_args.args[0]
        request_body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(request_body["text"]["format"]["type"], "json_schema")
        self.assertTrue(request_body["text"]["format"]["strict"])
        self.assertNotIn("tools", request_body)

    def test_openai_api_error_is_wrapped_without_leaking_details(self):
        provider = OpenAIResponsesProvider(api_key="test-key")
        with patch("analyzer.ai_provider.urlopen", side_effect=URLError("sensitive detail")):
            with self.assertRaisesRegex(AIProviderError, "request failed"):
                provider.analyze({"session_id": "session-a"})

    def test_empty_sessions_do_not_call_provider(self):
        provider = FakeProvider()
        self.assertEqual(aggregate_sessions([], []), [])
        self.assertEqual(analyze_session_contexts([], provider), [])
        self.assertEqual(provider.contexts, [])

    def test_database_flow_keeps_ai_separate_from_deterministic_alerts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "events.sqlite3"
            insert_events([
                {"timestamp": "2026-10-04T10:00:00Z", "source_ip": "192.0.2.8",
                 "session_id": "session-a", "username": "root", "event_type": "command",
                 "command": "uname -a", "login_result": None},
                {"timestamp": "2026-10-04T10:00:01Z", "source_ip": "192.0.2.8",
                 "session_id": "session-a", "username": "root", "event_type": "command",
                 "command": "whoami", "login_result": None},
            ], database)
            provider = FakeProvider(response=valid_response((1, 2)))
            result = analyze_database_sessions(database, provider)
            self.assertEqual(result[0]["status"], "ok")
            self.assertEqual(len(provider.contexts[0]["existing_detections"]), 2)
            self.assertEqual(len(get_events(database)), 2)
            self.assertEqual(len(get_alerts(database)), 2)
            self.assertEqual(result[0]["analysis"]["confidence"], 0.58)

    def test_empty_database_does_not_need_provider_configuration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = analyze_database_sessions(Path(temp_dir) / "empty.sqlite3")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
