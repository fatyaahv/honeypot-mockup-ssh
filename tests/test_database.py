import tempfile
import unittest
from pathlib import Path

from analyzer.collector import collect_cowrie_log
from analyzer.database import get_event, get_events, insert_event


class SecurityEventDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "events.sqlite3"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_insert_and_retrieve_security_event(self):
        event = {
            "timestamp": "2026-10-03T09:00:10.000000Z",
            "source_ip": "192.0.2.10",
            "session_id": "sample-session-1",
            "username": "root",
            "event_type": "command",
            "command": "whoami",
            "login_result": None,
        }

        event_id = insert_event(event, self.database_path)
        retrieved = get_event(event_id, self.database_path)

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["source_ip"], "192.0.2.10")
        self.assertEqual(retrieved["session_id"], "sample-session-1")
        self.assertEqual(retrieved["username"], "root")
        self.assertEqual(retrieved["event_type"], "command")
        self.assertEqual(retrieved["command"], "whoami")
        self.assertIsNone(retrieved["login_result"])

    def test_collector_parses_and_persists_cowrie_sample(self):
        fixture = Path(__file__).with_name("sample_cowrie.jsonl")
        count = collect_cowrie_log(fixture, self.database_path)

        self.assertEqual(count, 5)
        stored_events = get_events(self.database_path)
        self.assertEqual(len(stored_events), 5)
        self.assertEqual(stored_events[3]["command"], "whoami")
        self.assertEqual(stored_events[1]["login_result"], "failed")


if __name__ == "__main__":
    unittest.main()
