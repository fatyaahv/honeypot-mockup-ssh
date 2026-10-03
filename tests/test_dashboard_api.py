"""Read-only dashboard API tests using temporary SQLite databases."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from analyzer.database import insert_alerts, insert_events
from analyzer.deception_store import save_profile_selection
from backend.main import create_app


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "api.sqlite3"
        self.client = TestClient(create_app(self.database))

    def tearDown(self):
        self.client.close()
        self.temp_dir.cleanup()

    def seed(self):
        ids = insert_events([
            {"timestamp": "2026-10-04T10:00:00Z", "source_ip": "203.0.113.10",
             "session_id": "session-one", "username": "root", "event_type": "command",
             "command": "uname -a", "login_result": None},
            {"timestamp": "2026-10-04T10:00:02Z", "source_ip": "203.0.113.10",
             "session_id": "session-one", "username": "root", "event_type": "login_failed",
             "command": None, "login_result": "failed"},
            {"timestamp": "2026-10-04T11:00:00Z", "source_ip": "203.0.113.20",
             "session_id": "session-two", "username": "guest", "event_type": "command",
             "command": "ls", "login_result": None},
        ], self.database)
        insert_alerts([
            {"alert_id": "alert-one", "alert_type": "suspicious_command",
             "timestamp": "2026-10-04T10:00:00Z", "source_ip": "203.0.113.10",
             "session_id": "session-one", "severity": "low", "risk_score": 30,
             "risk_level": "Medium", "mitre_technique_id": "T1082",
             "mitre_technique_name": "System Information Discovery", "mitre_tactic": "discovery",
             "description": "Observed uname", "related_event_ids": [ids[0]], "risk_factors": {}},
            {"alert_id": "alert-two", "alert_type": "suspicious_command",
             "timestamp": "2026-10-04T11:00:00Z", "source_ip": "203.0.113.20",
             "session_id": "session-two", "severity": "high", "risk_score": 80,
             "risk_level": "Critical", "mitre_technique_id": "T1083",
             "mitre_technique_name": "File and Directory Discovery", "mitre_tactic": "discovery",
             "description": "Observed ls", "related_event_ids": [ids[2]], "risk_factors": {}},
        ], self.database)
        analysis = {
            "behavior_summary": "The session performed basic system discovery.",
            "attack_stage": "discovery", "observed_facts": [], "observed_patterns": [],
            "likely_objective": "Host discovery", "recommended_profile": "generic_linux",
            "confidence": 0.62, "uncertainty": "Short session; intent is unclear.",
            "analyst_summary": "Basic discovery observed.",
        }
        save_profile_selection(
            "session-one", "generic_linux", "test seed", "ok", analysis, self.database
        )
        return ids

    def test_health_and_dashboard_are_served(self):
        self.assertEqual(self.client.get("/health").json(), {"status": "ok"})
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Threat overview", page.text)
        self.assertEqual(self.client.get("/assets/app.js").status_code, 200)

    def test_empty_database_responses(self):
        self.assertEqual(self.client.get("/api/stats/overview").json(), {
            "total_events": 0, "total_sessions": 0, "unique_source_ips": 0,
            "total_alerts": 0, "high_critical_alerts": 0, "average_risk_score": 0.0,
        })
        self.assertEqual(self.client.get("/api/events").json()["items"], [])
        self.assertEqual(self.client.get("/api/alerts").json()["items"], [])
        self.assertEqual(self.client.get("/api/sessions").json()["items"], [])
        self.assertEqual(self.client.get("/api/sources").json(), [])
        self.assertEqual(self.client.get("/api/mitre/techniques").json(), [])
        self.assertEqual(self.client.get("/api/ai-analyses").json(), [])
        self.assertEqual(self.client.get("/api/risk-distribution").json(), [
            {"risk_level": "Low", "count": 0}, {"risk_level": "Medium", "count": 0},
            {"risk_level": "High", "count": 0}, {"risk_level": "Critical", "count": 0},
        ])

    def test_event_and_alert_retrieval_and_filters(self):
        ids = self.seed()
        result = self.client.get("/api/events", params={"source_ip": "203.0.113.10", "limit": 1})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["total"], 2)
        self.assertEqual(result.json()["items"][0]["source_ip"], "203.0.113.10")
        self.assertEqual(result.json()["limit"], 1)
        self.assertEqual(self.client.get("/api/events", params={"session_id": "session-one"}).json()["total"], 2)
        self.assertEqual(self.client.get("/api/events", params={"event_type": "login_failed"}).json()["total"], 1)
        filtered = self.client.get("/api/alerts", params={"risk_level": "Critical", "source_ip": "203.0.113.20"})
        self.assertEqual(filtered.json()["total"], 1)
        self.assertEqual(filtered.json()["items"][0]["alert_id"], "alert-two")
        self.assertEqual(self.client.get("/api/alerts", params={"severity": "low"}).json()["total"], 1)
        self.assertEqual(ids, [1, 2, 3])

    def test_statistics_and_summaries(self):
        self.seed()
        stats = self.client.get("/api/stats/overview").json()
        self.assertEqual(stats, {
            "total_events": 3, "total_sessions": 2, "unique_source_ips": 2,
            "total_alerts": 2, "high_critical_alerts": 1, "average_risk_score": 55.0,
        })
        distribution = self.client.get("/api/risk-distribution").json()
        self.assertEqual(distribution[-1], {"risk_level": "Critical", "count": 1})
        self.assertEqual(len(self.client.get("/api/sources").json()), 2)
        technique = self.client.get("/api/mitre/techniques").json()[0]
        self.assertEqual(technique["technique_id"], "T1082")
        self.assertEqual(technique["occurrences"], 1)

    def test_session_investigation_includes_ai_profile_alerts_and_commands(self):
        self.seed()
        result = self.client.get("/api/sessions/session-one")
        self.assertEqual(result.status_code, 200)
        data = result.json()
        self.assertEqual(data["source_ip"], "203.0.113.10")
        self.assertEqual(data["event_count"], 2)
        self.assertIsNone(data["ended_at"])
        self.assertEqual(data["command_sequence"][0]["command"], "uname -a")
        self.assertEqual(data["authentication_activity"][0]["result"], "failed")
        self.assertEqual(data["related_alerts"][0]["alert_type"], "suspicious_command")
        self.assertEqual(data["ai_behavior_summary"], "The session performed basic system discovery.")
        self.assertEqual(data["ai_confidence"], 0.62)
        self.assertEqual(data["deception_profile"], "generic_linux")
        self.assertEqual(self.client.get("/api/sessions/session-one/ai").status_code, 200)
        self.assertEqual(self.client.get("/api/sessions/session-one/deception").json()["profile_name"], "generic_linux")
        self.assertEqual(self.client.get("/api/ai-analyses").json()[0]["session_id"], "session-one")

    def test_unknown_session_resources_return_404(self):
        self.assertEqual(self.client.get("/api/sessions/unknown").status_code, 404)
        self.assertEqual(self.client.get("/api/sessions/unknown/ai").status_code, 404)
        self.assertEqual(self.client.get("/api/sessions/unknown/deception").status_code, 404)

    def test_invalid_parameters_return_422(self):
        for url in (
            "/api/events?limit=0", "/api/events?offset=-1", "/api/alerts?limit=501",
            "/api/alerts?severity=urgent", "/api/alerts?risk_level=Extreme",
            "/api/alerts?alert_type=unrecognized", "/api/events?event_type=alien_event",
            "/api/events?source_ip=", "/api/sessions?limit=0",
        ):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 422)

    def test_api_is_read_only(self):
        self.assertEqual(self.client.post("/api/events", json={}).status_code, 405)


if __name__ == "__main__":
    unittest.main()
