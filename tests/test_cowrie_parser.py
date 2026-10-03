import unittest
from pathlib import Path

from analyzer.cowrie_parser import parse_file, parse_lines


class CowrieParserTests(unittest.TestCase):
    def test_sample_log_normalizes_supported_events_and_omits_passwords(self):
        fixture = Path(__file__).with_name("sample_cowrie.jsonl")
        events = parse_file(fixture)

        self.assertEqual(
            [event["event_type"] for event in events],
            ["session_start", "login_failed", "login_success", "command", "session_end"],
        )
        self.assertEqual(events[1]["username"], "admin")
        self.assertEqual(events[1]["login_result"], "failed")
        self.assertEqual(events[3]["command"], "whoami")
        self.assertNotIn("password", events[1])
        self.assertEqual(events[0]["source_ip"], "192.0.2.10")
        self.assertEqual(events[0]["session_id"], "sample-session-1")

    def test_ignores_unsupported_cowrie_event_ids(self):
        self.assertEqual(list(parse_lines(['{"eventid":"cowrie.client.version"}'])), [])

    def test_invalid_json_reports_line_number(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            list(parse_lines(['{}', 'not json']))


if __name__ == "__main__":
    unittest.main()
