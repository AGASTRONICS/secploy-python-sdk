import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from secploy.identity_reporter import IdentityReporter


def reporter(**kwargs):
    return IdentityReporter("https://api.secploy.com", lambda: {}, **kwargs)


AUTH = {
    "identity_key": "user-1",
    "user_id": "user-1",
    "email": "a@example.com",
    "session_id": "sess-1",
    "ip_address": "1.2.3.4",
    "is_authenticated": True,
}


def ok(status_code=202):
    return SimpleNamespace(status_code=status_code)


class DeduplicationTests(unittest.TestCase):
    def test_first_sighting_is_queued(self):
        r = reporter()
        self.assertTrue(r.record(AUTH))
        self.assertEqual(r.pending_count, 1)

    def test_repeat_sighting_is_suppressed(self):
        r = reporter()
        r.record(AUTH)
        # This is the property that matters: steady traffic from a known user
        # must not produce one report per request.
        for _ in range(500):
            self.assertFalse(r.record(AUTH))
        self.assertEqual(r.pending_count, 1)

    def test_changed_identity_is_re_reported(self):
        r = reporter()
        r.record(AUTH)
        changed = dict(AUTH, ip_address="9.9.9.9")
        self.assertTrue(r.record(changed))

    def test_changed_session_is_re_reported(self):
        r = reporter()
        r.record(AUTH)
        self.assertTrue(r.record(dict(AUTH, session_id="sess-2")))

    def test_sighting_is_re_reported_once_the_interval_lapses(self):
        r = reporter(report_interval=0)
        r.record(AUTH)
        self.assertTrue(r.record(AUTH))

    def test_distinct_identities_are_tracked_separately(self):
        r = reporter()
        r.record(AUTH)
        r.record(dict(AUTH, identity_key="user-2", user_id="user-2"))
        self.assertEqual(r.pending_count, 2)

    def test_anonymous_and_empty_identities_are_ignored(self):
        r = reporter()
        self.assertFalse(r.record(None))
        self.assertFalse(r.record({}))
        self.assertFalse(r.record({"identity_key": "anonymous"}))
        self.assertFalse(r.record({"identity_key": "   "}))
        self.assertEqual(r.pending_count, 0)

    def test_user_id_is_used_when_identity_key_is_absent(self):
        r = reporter()
        self.assertTrue(r.record({"user_id": "user-9"}))

    def test_tracking_table_is_bounded(self):
        # A high-cardinality identity key must not grow memory without bound.
        r = reporter(max_tracked=10)
        for i in range(50):
            r.record({"identity_key": f"user-{i}"})
        self.assertLessEqual(len(r._seen), 10)


class MergeTests(unittest.TestCase):
    @patch("secploy.identity_reporter.requests.post")
    def test_a_sparse_sighting_merges_into_the_richer_one(self, mock_post):
        mock_post.return_value = ok()
        r = reporter()
        r.record(AUTH)
        r.record({"identity_key": "user-1", "name": "Ada L."})

        sent = mock_post.call_args.kwargs["json"]["identities"] if mock_post.called else None
        r.flush()
        sent = mock_post.call_args.kwargs["json"]["identities"]
        self.assertEqual(len(sent), 1)
        record = sent[0]
        # Regression: the sparse sighting used to replace the whole record.
        self.assertEqual(record["name"], "Ada L.")
        self.assertEqual(record["email"], "a@example.com")
        self.assertEqual(record["ip_address"], "1.2.3.4")
        self.assertEqual(record["session_id"], "sess-1")

    @patch("secploy.identity_reporter.requests.post")
    def test_absent_fields_are_not_sent_as_null(self, mock_post):
        mock_post.return_value = ok()
        r = reporter()
        r.record({"identity_key": "user-9"})
        r.flush()
        record = mock_post.call_args.kwargs["json"]["identities"][0]
        # Sending nulls would let a sparse sighting blank fields server-side.
        self.assertNotIn("email", record)
        self.assertNotIn("name", record)

    @patch("secploy.identity_reporter.requests.post")
    def test_explicit_false_is_carried(self, mock_post):
        mock_post.return_value = ok()
        r = reporter()
        r.record({"identity_key": "user-9", "is_authenticated": False})
        r.flush()
        record = mock_post.call_args.kwargs["json"]["identities"][0]
        self.assertIn("is_authenticated", record)
        self.assertFalse(record["is_authenticated"])


class FlushTests(unittest.TestCase):
    @patch("secploy.identity_reporter.requests.post")
    def test_flush_sends_pending_identities(self, mock_post):
        mock_post.return_value = ok()
        r = reporter()
        r.record(AUTH)
        self.assertEqual(r.flush(), 1)
        body = mock_post.call_args.kwargs["json"]
        self.assertEqual(len(body["identities"]), 1)
        self.assertEqual(body["identities"][0]["identity_key"], "user-1")
        self.assertIn("last_seen_at", body["identities"][0])
        self.assertEqual(r.pending_count, 0)

    @patch("secploy.identity_reporter.requests.post")
    def test_flush_with_nothing_pending_makes_no_request(self, mock_post):
        self.assertEqual(reporter().flush(), 0)
        mock_post.assert_not_called()

    @patch("secploy.identity_reporter.requests.post", side_effect=Exception("boom"))
    def test_network_failure_requeues_the_batch(self, _mock_post):
        r = reporter()
        r.record(AUTH)
        self.assertEqual(r.flush(), 0)
        self.assertEqual(r.pending_count, 1)

    @patch("secploy.identity_reporter.requests.post")
    def test_server_error_requeues(self, mock_post):
        mock_post.return_value = ok(503)
        r = reporter()
        r.record(AUTH)
        r.flush()
        self.assertEqual(r.pending_count, 1)

    @patch("secploy.identity_reporter.requests.post")
    def test_client_error_does_not_requeue(self, mock_post):
        mock_post.return_value = ok(401)
        r = reporter()
        r.record(AUTH)
        r.flush()
        # Retrying a rejected batch forever would just leak memory.
        self.assertEqual(r.pending_count, 0)

    @patch("secploy.identity_reporter.requests.post")
    def test_batch_is_capped(self, mock_post):
        mock_post.return_value = ok()
        r = reporter(max_batch=5)
        for i in range(5):
            r.record({"identity_key": f"user-{i}"})
        # Hitting the cap flushes on its own rather than growing unbounded.
        self.assertLessEqual(len(mock_post.call_args.kwargs["json"]["identities"]), 5)

    @patch("secploy.identity_reporter.requests.post")
    def test_recording_never_raises_into_the_caller(self, mock_post):
        mock_post.return_value = ok()
        r = reporter()
        r._get_headers = Mock(side_effect=Exception("no creds"))
        r.record(AUTH)
        self.assertEqual(r.flush(), 0)  # swallowed, not raised


class ClientIntegrationTests(unittest.TestCase):
    def test_cached_gate_records_the_identity(self):
        from secploy.client import SecployClient
        from secploy.policy_cache import PolicySnapshot, SecurityPolicyCache

        client = object.__new__(SecployClient)
        client.gate_mode = "cached"
        client.api_key = "pk-1"
        client.environment_key = "ek-1"
        client.security_policy = SecurityPolicyCache("https://api.secploy.com", lambda: {})
        client.security_policy._snapshot = PolicySnapshot({
            "version": "v1", "ttl_seconds": 300,
            "blocked_endpoints": [], "controls": [],
        })
        client.identities = Mock()

        client.get_endpoint_decision("GET", "/profile", auth=AUTH)

        # Without this, caching the gate would silently stop identity telemetry.
        client.identities.record.assert_called_once_with(AUTH)


if __name__ == "__main__":
    unittest.main()
