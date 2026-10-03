import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyzer.database import get_alerts, insert_events
from analyzer.detector import DetectionConfig
from analyzer.enrichment import analyze_database, enrich_alerts
from analyzer.mitre_mapping import map_alert
from analyzer.risk_scoring import calculate_risk, risk_level_for_score


STAMP = "2026-10-04T10:00:00Z"


def make_event(event_id, event_type="command", **values):
    timestamp = values.pop("timestamp", STAMP)
    return {
        "id": event_id,
        "timestamp": timestamp,
        "source_ip": values.pop("source_ip", "192.0.2.44"),
        "session_id": values.pop("session_id", "sess-44"),
        "event_type": event_type,
        **values,
    }


def make_alert(alert_type="brute_force", severity="medium", related_ids=None, **values):
    return {
        "alert_type": alert_type,
        "timestamp": values.pop("timestamp", STAMP),
        "source_ip": values.pop("source_ip", "192.0.2.44"),
        "session_id": values.pop("session_id", "sess-44"),
        "severity": severity,
        "description": "Example detection",
        "related_event_ids": related_ids or [],
        **values,
    }


class MitreAndRiskTests(unittest.TestCase):
    def test_brute_force_maps_to_password_guessing(self):
        mapping = map_alert(make_alert("brute_force"), [])
        self.assertEqual(mapping["mitre_technique_id"], "T1110.001")
        self.assertEqual(mapping["mitre_technique_name"], "Password Guessing")
        self.assertEqual(mapping["mitre_tactic"], "Credential Access")

    def test_behavior_commands_map_to_expected_techniques(self):
        cases = {
            "whoami": "T1033",
            "uname -a": "T1082",
            "ip addr": "T1016",
            "find /etc": "T1083",
            "cat /etc/passwd": "T1003.008",
            "wget https://example.invalid/tool": "T1105",
            "bash -c id": "T1059.004",
            "python -V": "T1059.006",
            "chmod +x file": "T1222.002",
            "nc -l 4444": "T1095",
        }
        for command, technique_id in cases.items():
            with self.subTest(command=command):
                raw_event = make_event(1, command=command)
                alert = make_alert("suspicious_command", related_ids=[1])
                mapping = map_alert(alert, [raw_event])
                self.assertEqual(mapping["mitre_technique_id"], technique_id)

    def test_success_mapping_caveat_and_unmapped_behavior(self):
        successful_login = map_alert(make_alert("success_after_repeated_failures"), [])
        self.assertEqual(successful_login["mitre_technique_id"], "T1078")
        self.assertIn("does not verify", successful_login["mitre_explanation"])

        unmapped = map_alert(make_alert("command_burst"), [])
        self.assertIsNone(unmapped["mitre_technique_id"])
        self.assertIsNone(unmapped["mitre_technique_name"])

    def test_suspicious_command_without_known_behavior_is_unmapped(self):
        alert = make_alert("suspicious_command", related_ids=[1])
        event = make_event(1, command="custom-shell --inspect")
        mapping = map_alert(alert, [event])
        self.assertIsNone(mapping["mitre_technique_id"])
        self.assertIsNone(mapping["mapped_behavior"])

    def test_risk_level_boundaries(self):
        boundaries = {
            0: "Low", 24: "Low", 25: "Medium", 49: "Medium",
            50: "High", 74: "High", 75: "Critical", 100: "Critical",
        }
        for score, level in boundaries.items():
            with self.subTest(score=score):
                self.assertEqual(risk_level_for_score(score), level)
        self.assertEqual(risk_level_for_score(140), "Critical")
        self.assertEqual(risk_level_for_score(-5), "Low")

    def test_risk_score_includes_transparent_factors_and_caps_at_100(self):
        event = make_event(1, "login_failed")
        alert = make_alert("brute_force", "medium", [1])
        scored = calculate_risk(alert, [event])
        self.assertEqual(scored["risk_score"], 25)
        self.assertEqual(scored["risk_factors"]["base_severity"], 25)
        self.assertEqual(scored["risk_factors"]["repeated_related_activity"], 0)

        max_alert = make_alert("suspicious_command", "critical", [1, 2, 3, 4, 5, 6])
        max_events = [make_event(i, "login_success") for i in range(1, 7)]
        capped = calculate_risk(max_alert, max_events, [max_alert])
        self.assertEqual(capped["risk_score"], 100)
        self.assertEqual(capped["risk_level"], "Critical")

    def test_repeated_activity_increases_risk(self):
        events = [make_event(i, "login_failed") for i in range(1, 4)]
        one = calculate_risk(make_alert(related_ids=[1]), events)
        repeated = calculate_risk(make_alert(related_ids=[1, 2, 3]), events)
        self.assertGreater(repeated["risk_score"], one["risk_score"])
        self.assertEqual(repeated["risk_factors"]["repeated_related_activity"], 10)

    def test_successful_authentication_increases_risk(self):
        failed = make_event(1, "login_failed")
        success = make_event(2, "login_success")
        alert = make_alert("success_after_repeated_failures", "high", [1, 2])
        without_success = calculate_risk(alert, [failed])
        with_success = calculate_risk(alert, [failed, success])
        self.assertEqual(with_success["risk_factors"]["successful_authentication"], 20)
        self.assertGreater(with_success["risk_score"], without_success["risk_score"])

    def test_related_alerts_and_session_activity_increase_risk(self):
        events = [make_event(1, "login_failed"), make_event(2, "command")]
        alert = make_alert(related_ids=[1])
        base = calculate_risk(alert, events, [alert])
        other = make_alert("suspicious_command", related_ids=[2])
        with_related = calculate_risk(alert, events, [alert, other])
        self.assertGreater(with_related["risk_score"], base["risk_score"])
        self.assertEqual(with_related["risk_factors"]["related_alerts"], 5)
        self.assertEqual(with_related["risk_factors"]["session_activity"], 2)

    def test_enrichment_adds_required_fields_and_mapping(self):
        event = make_event(11, command="whoami")
        alert = make_alert("suspicious_command", "low", [11])
        enriched = enrich_alerts([alert], [event])[0]
        self.assertTrue(enriched["alert_id"].startswith("alert-"))
        self.assertEqual(enriched["mitre_technique_id"], "T1033")
        self.assertEqual(enriched["risk_score"], 20)
        for field in (
            "alert_id", "alert_type", "timestamp", "source_ip", "session_id",
            "severity", "risk_score", "risk_level", "mitre_technique_id",
            "mitre_technique_name", "mitre_tactic", "description",
            "related_event_ids",
        ):
            self.assertIn(field, enriched)

    def test_database_analysis_persists_enriched_alerts_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "phase6.sqlite3"
            insert_events(
                [
                    make_event(1, "login_failed", timestamp="2026-10-04T10:00:00Z"),
                    make_event(2, "login_failed", timestamp="2026-10-04T10:00:05Z"),
                    make_event(3, "login_failed", timestamp="2026-10-04T10:00:10Z"),
                ],
                database_path,
            )
            config = DetectionConfig(
                brute_force_threshold=3,
                brute_force_window_seconds=60,
                success_after_failures_threshold=3,
                success_after_failures_window_seconds=60,
                command_burst_threshold=3,
                command_burst_window_seconds=30,
            )
            first_run = analyze_database(database_path, config)
            second_run = analyze_database(database_path, config)
            stored = get_alerts(database_path)

        self.assertEqual(first_run[0]["alert_type"], "brute_force")
        self.assertEqual(first_run[0]["mitre_technique_id"], "T1110.001")
        self.assertEqual(first_run[0]["risk_score"], second_run[0]["risk_score"])
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["alert_id"], first_run[0]["alert_id"])
        self.assertEqual(stored[0]["related_event_ids"], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()

