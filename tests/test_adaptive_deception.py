"""Tests for fixed, safe deception profiles and constrained adaptation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzer.ai_schema import AIResponseValidationError, parse_analysis_response
from analyzer.behavior_analyzer import adapt_database_sessions
from analyzer.database import insert_events
from analyzer.deception_profiles import (
    ALLOWED_PROFILE_NAMES,
    PROFILES,
    get_profile,
    profile_as_dict,
    select_profile,
)
from analyzer.deception_store import get_profile_selections


def ai_result(recommendation="generic_linux", ids=(1, 2)):
    return json.dumps({
        "behavior_summary": "A short session contains system discovery activity.",
        "attack_stage": "discovery",
        "observed_facts": [{"event_ids": [ids[-1]], "fact": "A system command was entered."}],
        "observed_patterns": [{
            "pattern": "system_discovery", "event_ids": list(ids),
            "interpretation": "The sequence is consistent with discovery.",
        }],
        "likely_objective": "The operator may be inspecting the simulated host.",
        "recommended_profile": recommendation,
        "confidence": 0.4,
        "uncertainty": "Evidence is limited and does not establish intent.",
        "analyst_summary": "Observed discovery; objective remains uncertain.",
    })


class MockProvider:
    def __init__(self, response):
        self.response = response

    def analyze(self, context):
        return self.response


class AdaptiveDeceptionTests(unittest.TestCase):
    def test_profiles_are_finite_and_contain_only_fictional_static_data(self):
        self.assertEqual(set(PROFILES), set(ALLOWED_PROFILE_NAMES))
        for name in ALLOWED_PROFILE_NAMES:
            with self.subTest(profile=name):
                profile = profile_as_dict(name)
                self.assertTrue(profile["hostname"])
                self.assertTrue(profile["users"])
                self.assertTrue(profile["directories"])
                self.assertTrue(profile["files"])
                self.assertTrue(profile["artifacts"])
                self.assertNotIn("password", json.dumps(profile).lower())
                self.assertNotIn("command", profile)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            get_profile("host_filesystem")
        with self.assertRaises(TypeError):
            PROFILES["host_filesystem"] = PROFILES["generic_linux"]

    def test_ai_unsupported_recommendation_is_rejected_by_schema_and_falls_back(self):
        with self.assertRaises(AIResponseValidationError):
            parse_analysis_response(ai_result("host_filesystem"), {1, 2})
        selection = select_profile({"commands": [], "existing_detections": []}, {
            "recommended_profile": "host_filesystem",
            "observed_patterns": [],
            "likely_objective": "uncertain",
        })
        self.assertEqual(selection["profile"], "generic_linux")
        self.assertIn("rejected", selection["reason"])

    def test_reconnaissance_falls_back_to_generic(self):
        selection = select_profile({
            "commands": [{"command": "whoami"}, {"command": "uname -a"}],
            "existing_detections": [], "mitre_technique_ids": ["T1033", "T1082"],
        })
        self.assertEqual(selection["profile"], "generic_linux")

    def test_behavior_patterns_select_distinct_profiles(self):
        cases = [
            ("psql -l", "database_server"),
            ("cat /etc/nginx/nginx.conf", "web_server"),
            ("git status", "developer_workstation"),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                selection = select_profile({"commands": [{"command": command}]})
                self.assertEqual(selection["profile"], expected)

    def test_valid_ai_recommendation_must_still_be_allowlisted(self):
        selection = select_profile(
            {"commands": [{"command": "whoami"}], "existing_detections": []},
            {"recommended_profile": "web_server", "observed_patterns": []},
        )
        self.assertEqual(selection["profile"], "web_server")

    def test_deterministic_specific_evidence_overrides_ai_recommendation(self):
        selection = select_profile(
            {"commands": [{"command": "psql -l"}]},
            {"recommended_profile": "web_server", "observed_patterns": []},
        )
        self.assertEqual(selection["profile"], "database_server")

    def test_selection_never_executes_commands_or_reads_host_files(self):
        with patch("builtins.open", side_effect=AssertionError("file access")), \
             patch.object(Path, "read_text", side_effect=AssertionError("file access")), \
             patch("os.system", side_effect=AssertionError("command execution")), \
             patch("subprocess.run", side_effect=AssertionError("command execution")):
            result = select_profile({"commands": [{"command": "git status"}]})
            self.assertEqual(result["profile"], "developer_workstation")

    def test_adaptation_persists_profile_and_ai_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "events.sqlite3"
            insert_events([
                {"timestamp": "2026-10-04T10:00:00Z", "source_ip": "192.0.2.9",
                 "session_id": "session-db", "username": "operator", "event_type": "command",
                 "command": "psql -l", "login_result": None},
                {"timestamp": "2026-10-04T10:00:01Z", "source_ip": "192.0.2.9",
                 "session_id": "session-db", "username": "operator", "event_type": "command",
                 "command": "ls /var/lib/postgresql", "login_result": None},
            ], database)
            results = adapt_database_sessions(
                database, MockProvider(ai_result("web_server", ids=(1, 2)))
            )
            self.assertEqual(results[0]["deception"]["profile_name"], "database_server")
            stored = get_profile_selections(database)
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["profile_name"], "database_server")
            self.assertEqual(stored[0]["analysis"]["recommended_profile"], "web_server")
            self.assertEqual(stored[0]["profile"]["hostname"], "db-01")

    def test_unsupported_ai_response_uses_generic_safe_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "events.sqlite3"
            insert_events([{
                "timestamp": "2026-10-04T10:00:00Z", "source_ip": "192.0.2.9",
                "session_id": "session-unknown", "username": "root", "event_type": "command",
                "command": "whoami", "login_result": None,
            }], database)
            result = adapt_database_sessions(
                database, MockProvider(ai_result("host_filesystem", ids=(1, 1)))
            )[0]
            self.assertEqual(result["status"], "invalid_response")
            self.assertEqual(result["deception"]["profile_name"], "generic_linux")


if __name__ == "__main__":
    unittest.main()
