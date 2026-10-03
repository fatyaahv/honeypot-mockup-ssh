import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyzer.database import insert_events
from analyzer.detector import DetectionConfig, detect_database_events, detect_events


BASE_TIME = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
CONFIG = DetectionConfig(
    brute_force_threshold=3,
    brute_force_window_seconds=60,
    success_after_failures_threshold=3,
    success_after_failures_window_seconds=120,
    command_burst_threshold=3,
    command_burst_window_seconds=30,
)


def event(event_id, event_type, seconds=0, **fields):
    timestamp = BASE_TIME + timedelta(seconds=seconds)
    return {
        "id": event_id,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "source_ip": fields.pop("source_ip", "192.0.2.10"),
        "session_id": fields.pop("session_id", "session-a"),
        "event_type": event_type,
        **fields,
    }


class DetectionRuleTests(unittest.TestCase):
    def test_brute_force_positive(self):
        events = [event(i, "login_failed", i * 10) for i in range(1, 4)]
        alerts = detect_events(events, CONFIG)
        brute_force = [alert for alert in alerts if alert["alert_type"] == "brute_force"]
        self.assertEqual(len(brute_force), 1)
        self.assertEqual(brute_force[0]["severity"], "medium")
        self.assertEqual(brute_force[0]["related_event_ids"], [1, 2, 3])

    def test_brute_force_negative_when_attempts_are_spread_out(self):
        events = [event(i, "login_failed", i * 40) for i in range(1, 4)]
        alerts = detect_events(events, CONFIG)
        self.assertFalse(any(alert["alert_type"] == "brute_force" for alert in alerts))

    def test_success_after_repeated_failures_positive(self):
        events = [event(i, "login_failed", i * 5) for i in range(1, 4)]
        events.append(event(4, "login_success", 25, username="admin"))
        alerts = detect_events(events, CONFIG)
        alert = next(a for a in alerts if a["alert_type"] == "success_after_repeated_failures")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["related_event_ids"], [1, 2, 3, 4])

    def test_success_after_failures_negative_for_different_ip(self):
        events = [event(i, "login_failed", i * 5) for i in range(1, 4)]
        events.append(event(4, "login_success", 25, source_ip="198.51.100.8"))
        alerts = detect_events(events, CONFIG)
        self.assertFalse(any(
            alert["alert_type"] == "success_after_repeated_failures" for alert in alerts
        ))

    def test_suspicious_command_positive_and_neutral_severity(self):
        events = [event(1, "command", command="whoami")]
        alert = detect_events(events, CONFIG)[0]
        self.assertEqual(alert["alert_type"], "suspicious_command")
        self.assertEqual(alert["severity"], "low")
        self.assertIn("not classified as malicious", alert["description"])

    def test_suspicious_command_negative_for_unlisted_command(self):
        for command in ("pwd", "echo whoami"):
            with self.subTest(command=command):
                alerts = detect_events([event(1, "command", command=command)], CONFIG)
                self.assertFalse(any(alert["alert_type"] == "suspicious_command" for alert in alerts))

    def test_supported_command_indicators(self):
        for command in (
            "whoami", "uname -a", "id", "ip addr", "ifconfig", "ls", "find", "cat /etc/passwd",
            "wget https://example.invalid/file", "curl https://example.invalid",
            "chmod 755 file", "bash -c whoami", "python -V", "nc -l 4444",
        ):
            with self.subTest(command=command):
                alerts = detect_events([event(1, "command", command=command)], CONFIG)
                self.assertTrue(any(a["alert_type"] == "suspicious_command" for a in alerts))

    def test_command_burst_positive(self):
        events = [event(i, "command", i * 5, command="pwd") for i in range(1, 4)]
        alerts = detect_events(events, CONFIG)
        burst = [alert for alert in alerts if alert["alert_type"] == "command_burst"]
        self.assertEqual(len(burst), 1)
        self.assertEqual(burst[0]["severity"], "medium")
        self.assertEqual(burst[0]["session_id"], "session-a")
        self.assertEqual(burst[0]["related_event_ids"], [1, 2, 3])

    def test_command_burst_negative_when_commands_are_spread_out(self):
        events = [event(i, "command", i * 20, command="pwd") for i in range(1, 4)]
        alerts = detect_events(events, CONFIG)
        self.assertFalse(any(alert["alert_type"] == "command_burst" for alert in alerts))

    def test_detect_database_events_reads_persisted_events(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "security.sqlite3"
            insert_events(
                [event(i, "login_failed", i * 5) for i in range(1, 4)],
                database_path,
            )
            alerts = detect_database_events(database_path, CONFIG)

        self.assertTrue(any(alert["alert_type"] == "brute_force" for alert in alerts))
    def test_alert_has_minimum_required_fields(self):
        alert = detect_events([event(1, "command", command="uname -a")], CONFIG)[0]
        self.assertEqual(
            set(alert),
            {
                "alert_type", "timestamp", "source_ip", "session_id", "severity",
                "description", "related_event_ids",
            },
        )


if __name__ == "__main__":
    unittest.main()




