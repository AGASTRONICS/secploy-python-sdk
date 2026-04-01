import unittest
from unittest.mock import patch

from secploy import SecployClient


class _FakeDistribution:
    def __init__(self, name, version):
        self.metadata = {"Name": name}
        self.version = version


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class DependencyInsightsTests(unittest.TestCase):
    def _build_client(self):
        client = object.__new__(SecployClient)
        client.api_url = "https://api.secploy.com"
        client.ingest_url = "https://ingest.secploy.com"
        return client

    @patch("importlib.metadata.distributions")
    @patch("secploy.client.requests.post")
    @patch("secploy.client.requests.get")
    def test_dependency_health_report_includes_outdated_and_issue_counts(
        self,
        get_mock,
        post_mock,
        distributions_mock,
    ):
        distributions_mock.return_value = [
            _FakeDistribution("requests", "2.31.0"),
            _FakeDistribution("urllib3", "2.2.0"),
        ]

        def _fake_get(url, timeout=8):
            if "requests" in url:
                return _FakeResponse(200, {"info": {"version": "2.32.3"}})
            if "urllib3" in url:
                return _FakeResponse(200, {"info": {"version": "2.2.0"}})
            return _FakeResponse(404, {})

        def _fake_post(url, json=None, timeout=8):
            package = (json or {}).get("package", {}).get("name")
            version = (json or {}).get("version")
            if package == "requests" and version == "2.31.0":
                return _FakeResponse(
                    200,
                    {
                        "vulns": [
                            {
                                "id": "OSV-REQ-1",
                                "summary": "TLS parsing flaw",
                                "published": "2026-01-12T10:00:00Z",
                                "modified": "2026-01-14T10:00:00Z",
                            }
                        ]
                    },
                )
            return _FakeResponse(200, {"vulns": []})

        get_mock.side_effect = _fake_get
        post_mock.side_effect = _fake_post

        report = self._build_client().dependency_health_report(
            include_current_issues=True,
            include_latest_issues=True,
            incidents_limit=2,
        )

        self.assertEqual(report["summary"]["total_dependencies"], 2)
        self.assertEqual(report["summary"]["outdated_dependencies"], 1)
        self.assertEqual(report["summary"]["dependencies_with_current_issues"], 1)

        requests_item = next(d for d in report["dependencies"] if d["name"] == "requests")
        urllib3_item = next(d for d in report["dependencies"] if d["name"] == "urllib3")

        self.assertTrue(requests_item["is_outdated"])
        self.assertEqual(requests_item["latest_version"], "2.32.3")
        self.assertEqual(requests_item["current_issue_count"], 1)
        self.assertEqual(requests_item["recent_incidents"][0]["id"], "OSV-REQ-1")

        self.assertFalse(urllib3_item["is_outdated"])
        self.assertEqual(urllib3_item["latest_version"], "2.2.0")
        self.assertEqual(urllib3_item["current_issue_count"], 0)

    def test_dependency_health_report_rejects_invalid_limit(self):
        client = self._build_client()
        with self.assertRaises(ValueError):
            client.dependency_health_report(limit=0)

    @patch.object(SecployClient, "send_event")
    @patch.object(SecployClient, "dependency_health_report")
    def test_emit_dependency_health_report_embeds_report_inside_context(
        self,
        health_report_mock,
        send_event_mock,
    ):
        health_report_mock.return_value = {
            "summary": {"total_dependencies": 1, "outdated_dependencies": 0},
            "dependencies": [{"name": "requests", "current_version": "2.31.0"}],
        }
        send_event_mock.return_value = True

        client = self._build_client()
        sent = client.emit_dependency_health_report(limit=1, incidents_limit=1)

        self.assertTrue(sent)
        send_event_mock.assert_called_once()
        _, payload = send_event_mock.call_args[0]
        self.assertIn("context", payload)
        self.assertIn("summary", payload["context"])
        self.assertIn("dependencies", payload["context"])


if __name__ == "__main__":
    unittest.main()
