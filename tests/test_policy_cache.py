import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from secploy.client import SecployClient
from secploy.policy_cache import PolicySnapshot, SecurityPolicyCache


def iso(dt):
    return dt.isoformat()


def make_payload(rules=None, controls=None, version="v1"):
    return {
        "version": version,
        "generated_at": iso(datetime.now(timezone.utc)),
        "ttl_seconds": 300,
        "blocked_endpoints": rules or [],
        "controls": controls or [],
    }


def rule(method="POST", pattern="^/admin", rule_id="r1"):
    return {
        "id": rule_id,
        "method": method,
        "path_pattern": pattern,
        "reason": "manual block",
        "is_active": True,
    }


def control(
    target_type="identity",
    target="user-1",
    control_id="c1",
    status="applied",
    expires_at=None,
    metadata=None,
):
    return {
        "id": control_id,
        "action_type": "block_identity",
        "target_type": target_type,
        "target": target,
        "reason": "risk",
        "status": status,
        "source": "automated",
        "identity_key": target,
        "session_id": None,
        "auth_provider": None,
        "risk_score": 90.0,
        "expires_at": expires_at,
        "executed_at": None,
        "execution_result": {},
        "metadata": metadata if metadata is not None else {},
        "created_by": None,
    }


def cache_with(payload):
    cache = SecurityPolicyCache("https://api.secploy.com", lambda: {})
    cache._snapshot = PolicySnapshot(payload)
    return cache


class RuleMatchingTests(unittest.TestCase):
    def test_matching_rule_blocks(self):
        c = cache_with(make_payload(rules=[rule()]))
        result = c.evaluate("POST", "/admin/users")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["reason"], "blocked_by_endpoint_rule")
        self.assertEqual(result["rule"]["id"], "r1")

    def test_method_is_part_of_the_match(self):
        c = cache_with(make_payload(rules=[rule(method="POST")]))
        self.assertFalse(c.evaluate("GET", "/admin/users")["blocked"])

    def test_non_matching_path_is_allowed(self):
        c = cache_with(make_payload(rules=[rule()]))
        result = c.evaluate("POST", "/public/health")
        self.assertFalse(result["blocked"])
        self.assertNotIn("reason", result)

    def test_first_rule_in_snapshot_order_wins(self):
        # The backend orders rules newest-first and takes the first match, so the
        # snapshot order decides which rule is reported.
        c = cache_with(make_payload(rules=[
            rule(pattern="^/admin", rule_id="newer"),
            rule(pattern="^/admin/users", rule_id="older"),
        ]))
        self.assertEqual(c.evaluate("POST", "/admin/users")["rule"]["id"], "newer")

    def test_invalid_regex_falls_back_to_exact_match(self):
        # Mirrors the server's re.error fallback.
        c = cache_with(make_payload(rules=[rule(pattern="[unclosed")]))
        self.assertTrue(c.evaluate("POST", "[unclosed")["blocked"])
        self.assertFalse(c.evaluate("POST", "/admin")["blocked"])


class ControlMatchingTests(unittest.TestCase):
    def test_identity_control_matches_identity_key(self):
        c = cache_with(make_payload(controls=[control(target="user-1")]))
        result = c.evaluate("GET", "/x", auth={"identity_key": "user-1"})
        self.assertTrue(result["blocked"])
        self.assertEqual(result["reason"], "blocked_by_control_action")

    def test_identity_control_matches_user_id(self):
        c = cache_with(make_payload(controls=[control(target="user-1")]))
        self.assertTrue(c.evaluate("GET", "/x", auth={"user_id": "user-1"})["blocked"])

    def test_session_control_matches_session_id(self):
        c = cache_with(make_payload(controls=[control("session", "sess-9")]))
        self.assertTrue(c.evaluate("GET", "/x", auth={"session_id": "sess-9"})["blocked"])

    def test_ip_control_matches_either_ip_field(self):
        c = cache_with(make_payload(controls=[control("ip", "1.2.3.4")]))
        self.assertTrue(c.evaluate("GET", "/x", auth={"ip_address": "1.2.3.4"})["blocked"])
        self.assertTrue(c.evaluate("GET", "/x", auth={"remote_addr": "1.2.3.4"})["blocked"])

    def test_api_key_control_matches_project_or_environment_key(self):
        c = cache_with(make_payload(controls=[control("api_key", "pk-1")]))
        self.assertTrue(c.evaluate("GET", "/x", project_key="pk-1")["blocked"])
        c2 = cache_with(make_payload(controls=[control("api_key", "ek-1")]))
        self.assertTrue(c2.evaluate("GET", "/x", env_key="ek-1")["blocked"])

    def test_no_identity_means_no_control_lookup(self):
        c = cache_with(make_payload(controls=[control(target="user-1")]))
        self.assertFalse(c.evaluate("GET", "/x")["blocked"])

    def test_inactive_control_is_ignored(self):
        c = cache_with(make_payload(controls=[control(status="expired")]))
        self.assertFalse(c.evaluate("GET", "/x", auth={"identity_key": "user-1"})["blocked"])

    def test_expired_control_is_ignored_even_if_still_in_the_snapshot(self):
        # A snapshot can outlive a control's expiry, so expiry is re-checked
        # locally. Enforcing a lapsed control blocks a request that should pass.
        past = iso(datetime.now(timezone.utc) - timedelta(minutes=5))
        c = cache_with(make_payload(controls=[control(expires_at=past)]))
        self.assertFalse(c.evaluate("GET", "/x", auth={"identity_key": "user-1"})["blocked"])

    def test_unexpired_control_still_applies(self):
        future = iso(datetime.now(timezone.utc) + timedelta(minutes=5))
        c = cache_with(make_payload(controls=[control(expires_at=future)]))
        self.assertTrue(c.evaluate("GET", "/x", auth={"identity_key": "user-1"})["blocked"])

    def test_a_control_matched_twice_is_returned_once(self):
        c = cache_with(make_payload(controls=[control(target="user-1")]))
        result = c.evaluate(
            "GET", "/x", auth={"identity_key": "user-1", "user_id": "user-1"}
        )
        self.assertEqual(len(result["controls"]), 1)


class EndpointScopeTests(unittest.TestCase):
    def scoped(self, scope):
        return cache_with(make_payload(controls=[
            control(metadata={"endpoint_scope": scope})
        ]))

    def test_scoped_control_applies_on_matching_path(self):
        c = self.scoped({"method": "POST", "path_pattern": "^/pay"})
        self.assertTrue(
            c.evaluate("POST", "/pay/charge", auth={"identity_key": "user-1"})["blocked"]
        )

    def test_scoped_control_skipped_on_other_path(self):
        c = self.scoped({"method": "POST", "path_pattern": "^/pay"})
        self.assertFalse(
            c.evaluate("POST", "/profile", auth={"identity_key": "user-1"})["blocked"]
        )

    def test_scoped_control_skipped_on_other_method(self):
        c = self.scoped({"method": "POST", "path_pattern": "^/pay"})
        self.assertFalse(
            c.evaluate("GET", "/pay/charge", auth={"identity_key": "user-1"})["blocked"]
        )

    def test_method_only_scope_applies_to_every_path(self):
        c = self.scoped({"method": "DELETE"})
        self.assertTrue(
            c.evaluate("DELETE", "/anything", auth={"identity_key": "user-1"})["blocked"]
        )

    def test_control_without_scope_is_project_wide(self):
        c = cache_with(make_payload(controls=[control()]))
        self.assertTrue(
            c.evaluate("GET", "/anything", auth={"identity_key": "user-1"})["blocked"]
        )


class SnapshotTests(unittest.TestCase):
    def test_rules_are_bucketed_and_compiled_once(self):
        snap = PolicySnapshot(make_payload(rules=[rule("POST"), rule("GET", rule_id="r2")]))
        self.assertEqual(set(snap.rules_by_method), {"POST", "GET"})
        self.assertEqual(snap.rule_count, 2)
        compiled, raw, _ = snap.rules_by_method["POST"][0]
        self.assertIsNotNone(compiled)
        self.assertEqual(raw, "^/admin")

    def test_inactive_controls_are_dropped_at_build_time(self):
        snap = PolicySnapshot(make_payload(controls=[
            control(control_id="a", status="applied"),
            control(control_id="b", status="expired"),
        ]))
        self.assertEqual(snap.control_count, 1)

    def test_evaluate_returns_none_without_a_snapshot(self):
        cache = SecurityPolicyCache("https://api.secploy.com", lambda: {})
        self.assertIsNone(cache.evaluate("GET", "/x"))


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.cache = SecurityPolicyCache("https://api.secploy.com", lambda: {})

    @patch("secploy.policy_cache.requests.get")
    def test_successful_fetch_installs_a_snapshot(self, mock_get):
        mock_get.return_value = SimpleNamespace(
            status_code=200, ok=True, json=lambda: make_payload(rules=[rule()])
        )
        snap = self.cache.fetch()
        self.assertEqual(snap.version, "v1")
        self.assertTrue(self.cache.is_loaded)

    @patch("secploy.policy_cache.requests.get")
    def test_fetch_sends_if_none_match_once_a_version_is_known(self, mock_get):
        mock_get.return_value = SimpleNamespace(
            status_code=200, ok=True, json=lambda: make_payload(version="v7")
        )
        self.cache.fetch()
        mock_get.return_value = SimpleNamespace(status_code=304, ok=False, json=dict)
        self.cache.fetch()
        self.assertEqual(
            mock_get.call_args.kwargs["headers"]["If-None-Match"], '"v7"'
        )

    @patch("secploy.policy_cache.requests.get")
    def test_304_keeps_the_existing_snapshot(self, mock_get):
        mock_get.return_value = SimpleNamespace(
            status_code=200, ok=True, json=lambda: make_payload(version="v1")
        )
        first = self.cache.fetch()
        mock_get.return_value = SimpleNamespace(status_code=304, ok=False, json=dict)
        second = self.cache.fetch()
        self.assertIs(first, second)

    @patch("secploy.policy_cache.requests.get", side_effect=Exception("boom"))
    def test_network_failure_keeps_enforcing_the_last_snapshot(self, _mock_get):
        self.cache._snapshot = PolicySnapshot(make_payload(rules=[rule()]))
        # An outage must not disarm the gate — that is the whole point of caching.
        self.cache.fetch()
        self.assertTrue(self.cache.is_loaded)
        self.assertTrue(self.cache.evaluate("POST", "/admin")["blocked"])

    @patch("secploy.policy_cache.requests.get")
    def test_error_status_keeps_the_previous_snapshot(self, mock_get):
        self.cache._snapshot = PolicySnapshot(make_payload(version="good"))
        mock_get.return_value = SimpleNamespace(status_code=500, ok=False, json=dict)
        self.cache.fetch()
        self.assertEqual(self.cache.version, "good")


    @patch("secploy.policy_cache.requests.get")
    def test_non_dict_body_keeps_the_previous_snapshot(self, mock_get):
        self.cache._snapshot = PolicySnapshot(make_payload(version="good"))
        mock_get.return_value = SimpleNamespace(
            status_code=200, ok=True, json=lambda: ["not", "a", "dict"]
        )
        self.cache.fetch()
        self.assertEqual(self.cache.version, "good")

    @patch("secploy.policy_cache.requests.get")
    def test_malformed_rows_do_not_break_the_snapshot(self, mock_get):
        payload = make_payload(version="v2", rules=[rule()])
        payload["blocked_endpoints"].append("not a dict")
        payload["controls"] = ["also not a dict", control()]
        mock_get.return_value = SimpleNamespace(status_code=200, ok=True, json=lambda: payload)
        self.cache.fetch()
        # Junk rows are skipped rather than poisoning the whole policy.
        self.assertEqual(self.cache.version, "v2")
        self.assertEqual(self.cache.snapshot.rule_count, 1)
        self.assertEqual(self.cache.snapshot.control_count, 1)

    def test_headers_callback_failure_is_survivable(self):
        cache = SecurityPolicyCache(
            "https://api.secploy.com",
            Mock(side_effect=Exception("no creds")),
        )
        cache._snapshot = PolicySnapshot(make_payload(version="good"))
        cache.fetch()
        self.assertEqual(cache.version, "good")


class GateModeTests(unittest.TestCase):
    def build_client(self, mode, snapshot_payload=None):
        client = object.__new__(SecployClient)
        client.gate_mode = mode
        client.api_key = "pk-1"
        client.environment_key = "ek-1"
        client.send_event = Mock(return_value=True)
        client.security_policy = SecurityPolicyCache("https://api.secploy.com", lambda: {})
        if snapshot_payload is not None:
            client.security_policy._snapshot = PolicySnapshot(snapshot_payload)
        client._remote_endpoint_decision = Mock(return_value={
            "allowed": True, "blocked": False, "method": "POST",
            "endpoint": "/admin", "url": "/admin", "reason": "allowed",
            "rule": {}, "controls": [], "raw": {},
        })
        return client

    def test_remote_mode_always_calls_the_api(self):
        client = self.build_client("remote", make_payload(rules=[rule()]))
        client.get_endpoint_decision("POST", "/admin")
        client._remote_endpoint_decision.assert_called_once()

    def test_cached_mode_makes_no_network_call(self):
        client = self.build_client("cached", make_payload(rules=[rule()]))
        decision = client.get_endpoint_decision("POST", "/admin")
        client._remote_endpoint_decision.assert_not_called()
        self.assertTrue(decision["blocked"])
        self.assertEqual(decision["reason"], "blocked_by_endpoint_rule")

    def test_cached_mode_falls_back_while_the_snapshot_is_loading(self):
        client = self.build_client("cached", snapshot_payload=None)
        client.get_endpoint_decision("POST", "/admin")
        # Falling back is what keeps the first requests after start-up correct
        # instead of waving them through.
        client._remote_endpoint_decision.assert_called_once()

    def test_shadow_mode_returns_the_remote_decision(self):
        client = self.build_client("shadow", make_payload(rules=[rule()]))
        decision = client.get_endpoint_decision("POST", "/admin")
        client._remote_endpoint_decision.assert_called_once()
        self.assertFalse(decision["blocked"])  # remote said allow, and it wins

    def test_shadow_mode_reports_a_mismatch(self):
        client = self.build_client("shadow", make_payload(rules=[rule()]))
        client.get_endpoint_decision("POST", "/admin")
        client.send_event.assert_called_once()
        event_type, payload = client.send_event.call_args.args
        self.assertEqual(event_type, "secploy.gate.shadow_mismatch")
        self.assertTrue(payload["local"]["blocked"])
        self.assertFalse(payload["remote"]["blocked"])

    def test_shadow_mode_is_quiet_when_both_agree(self):
        client = self.build_client("shadow", make_payload())
        client.get_endpoint_decision("POST", "/admin")
        client.send_event.assert_not_called()

    def test_shadow_mode_does_not_report_when_the_remote_lookup_failed(self):
        client = self.build_client("shadow", make_payload(rules=[rule()]))
        client._remote_endpoint_decision.return_value["reason"] = "lookup_unavailable"
        client.get_endpoint_decision("POST", "/admin")
        # A failed remote lookup is not evidence the cache is wrong.
        client.send_event.assert_not_called()


class DecisionParityTests(unittest.TestCase):
    """The cached path and the remote path must build identical decisions."""

    def setUp(self):
        self.client = object.__new__(SecployClient)
        self.client.api_key = "pk-1"
        self.client.environment_key = "ek-1"
        self.client.security_policy = cache_with(make_payload(rules=[rule()]))

    def test_cached_decision_has_the_same_shape_as_a_remote_one(self):
        remote_payload = {
            "blocked": True,
            "method": "POST",
            "endpoint": "/admin",
            "rule": rule(),
            "reason": "blocked_by_endpoint_rule",
        }
        remote = self.client._decision_from_payload(
            remote_payload, "POST", "/admin", "/admin"
        )
        cached = self.client._cached_endpoint_decision("POST", "/admin")

        self.assertEqual(set(remote), set(cached))
        for key in ("allowed", "blocked", "method", "endpoint", "reason"):
            self.assertEqual(remote[key], cached[key], key)
        self.assertEqual(remote["rule"]["id"], cached["rule"]["id"])

    def test_signature_ignores_incidental_payload_differences(self):
        a = self.client._decision_from_payload(
            {"blocked": True, "rule": rule(), "reason": "blocked_by_endpoint_rule"},
            "POST", "/admin", "/admin",
        )
        b = self.client._cached_endpoint_decision("POST", "/admin")
        self.assertEqual(
            self.client._decision_signature(a),
            self.client._decision_signature(b),
        )


if __name__ == "__main__":
    unittest.main()
