import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from secploy.scrubbing import hash_session_id
from secploy import SecployClient, SecployGate, SecurityGateBlocked
from secploy.gates import GateDecision, GateRequest, SecployGate as CompatSecployGate
from secploy.gates import SecurityGateException


def build_client(
    blocked: bool = False,
    with_controls: bool = False,
    send_event_side_effect: Exception | None = None,
) -> SecployClient:
    client = object.__new__(SecployClient)
    client.send_event = Mock(return_value=True)
    if send_event_side_effect is not None:
        client.send_event.side_effect = send_event_side_effect
    client.get_endpoint_decision = lambda method, endpoint, auth=None, timeout=5: {
        "allowed": not blocked,
        "blocked": blocked,
        "method": method,
        "endpoint": endpoint,
        "reason": "blocked_by_rule" if blocked else "allowed",
        "rule": {"reason": "blocked_by_rule"} if blocked else {},
        "controls": [
            {
                "action_type": "block_identity",
                "target": "user_123",
            }
        ]
        if blocked and with_controls
        else [],
        "raw": {},
    }
    return client


class SecployGateRuntimeTests(unittest.TestCase):
    def test_client_register_identity_returns_normalized_auth_context(self) -> None:
        auth = SecployClient.register_identity(
            id="user_123",
            name="Test User",
            username="tester",
            email="test@example.com",
            auth_provider="bearer",
            session_id="sess_1",
            remote_addr="127.0.0.1",
            is_authenticated=True,
        )

        self.assertEqual(auth["identity_key"], "user_123")
        self.assertEqual(auth["name"], "Test User")
        self.assertEqual(auth["username"], "tester")
        self.assertEqual(auth["email"], "test@example.com")
        self.assertEqual(auth["auth_provider"], "bearer")
        self.assertEqual(auth["session_id"], "sess_1")
        self.assertEqual(auth["remote_addr"], "127.0.0.1")
        self.assertTrue(auth["is_authenticated"])

    def test_client_register_identity_uses_anonymous_when_id_missing(self) -> None:
        auth = SecployClient.register_identity(id=None)
        self.assertEqual(auth["identity_key"], "anonymous")

    def test_gate_returns_original_request_when_allowed(self) -> None:
        gate = SecployGate(client=build_client(blocked=False))
        request = {
            "method": "POST",
            "url": "https://api.example.com/orders",
            "headers": {"Authorization": "Bearer abc"},
        }

        allowed = gate(request=request)

        self.assertIs(allowed, request)

    def test_gate_request_executes_transport_when_allowed(self) -> None:
        gate = SecployGate(client=build_client(blocked=False))

        with patch("secploy.handlers.requests.request", return_value="ok") as request_mock:
            response = gate.request(
                "POST",
                "https://api.example.com/orders",
                headers={"Authorization": "Bearer abc"},
                json={"id": 1},
            )

        self.assertEqual(response, "ok")
        request_mock.assert_called_once_with(
            "POST",
            "https://api.example.com/orders",
            headers={"Authorization": "Bearer abc"},
            json={"id": 1},
        )

    def test_gate_tracks_allowed_request_decision(self) -> None:
        client = build_client(blocked=False)
        gate = SecployGate(client=client)

        gate(request={"method": "GET", "url": "https://api.example.com/orders"})

        client.send_event.assert_called_once()
        event_name, payload = client.send_event.call_args.args
        self.assertEqual(event_name, "info")
        self.assertEqual(payload["method"], "GET")
        self.assertEqual(payload["endpoint"], "/orders")
        ctx = payload["context"]
        self.assertFalse(ctx["secploy_gate"]["blocked"])
        self.assertEqual(ctx["http_status"], 200)

    def test_gate_event_context_flattens_auth_fields(self) -> None:
        client = build_client(blocked=False)
        gate = SecployGate(client=client)

        gate(
            request={"method": "POST", "url": "https://api.example.com/data"},
            auth={"user_id": "u_42", "session_id": "sess_99", "auth_provider": "bearer", "remote_addr": "10.0.0.1"},
        )

        _, payload = client.send_event.call_args.args
        ctx = payload["context"]
        self.assertEqual(ctx["user_id"], "u_42")
        # Hashed on the way out. A session identifier is a live credential:
        # whoever reads one out of an event store can replay it. The hash keeps
        # what the product needs - a stable, unique handle - and removes what it
        # never needed.
        self.assertEqual(ctx["session_id"], hash_session_id("sess_99"))
        self.assertNotEqual(ctx["session_id"], "sess_99")
        self.assertEqual(ctx["auth_provider"], "bearer")
        self.assertEqual(ctx["remote_addr"], "10.0.0.1")

    def test_gate_defaults_to_anonymous_identity_with_ip_fallback(self) -> None:
        client = build_client(blocked=False)
        gate = SecployGate(client=client)

        decision = gate.inspect(
            request={
                "method": "GET",
                "url": "https://api.example.com/public",
                "headers": {"X-Forwarded-For": "203.0.113.10"},
            }
        )

        auth = decision["auth"]
        self.assertEqual(auth["identity_key"], "anonymous")
        self.assertEqual(auth["ip_address"], "203.0.113.10")
        self.assertEqual(auth["remote_addr"], "203.0.113.10")

    def test_identity_control_only_blocks_matching_identity(self) -> None:
        gate = SecployGate(client=build_client(blocked=True, with_controls=True))

        allowed = gate.inspect(
            request={"method": "GET", "url": "https://api.example.com/orders"},
            auth={"identity_key": "user_999"},
        )
        self.assertFalse(allowed["blocked"])
        self.assertEqual(allowed["reason"], "control_not_applicable")

        with self.assertRaises(SecurityGateBlocked):
            gate(
                request={"method": "GET", "url": "https://api.example.com/orders"},
                auth={"identity_key": "user_123"},
            )

    def test_blocked_event_sets_403_status(self) -> None:
        client = build_client(blocked=True)
        gate = SecployGate(client=client, raise_on_block=False)

        gate(request={"method": "DELETE", "url": "https://api.example.com/users/1"})

        _, payload = client.send_event.call_args.args
        self.assertEqual(payload["context"]["http_status"], 403)

    def test_blocked_login_endpoint_classified_as_bruteforce(self) -> None:
        client = build_client(blocked=True)
        gate = SecployGate(client=client, raise_on_block=False)

        gate(request={"method": "POST", "url": "https://api.example.com/auth/login"})

        _, payload = client.send_event.call_args.args
        self.assertEqual(payload["secploy_signal"], "bruteforce")
        self.assertIn("credential", payload["message"])

    def test_blocked_payment_endpoint_classified_as_fraud(self) -> None:
        client = build_client(blocked=True)
        gate = SecployGate(client=client, raise_on_block=False)

        gate(request={"method": "POST", "url": "https://api.example.com/billing/charge"})

        _, payload = client.send_event.call_args.args
        self.assertEqual(payload["secploy_signal"], "fraud")
        self.assertIn("fraud", payload["message"])

    def test_blocked_admin_endpoint_classified_as_policy_block_with_privileged_hint(self) -> None:
        client = build_client(blocked=True)
        gate = SecployGate(client=client, raise_on_block=False)

        gate(request={"method": "GET", "url": "https://api.example.com/admin/users"})

        _, payload = client.send_event.call_args.args
        self.assertIn("privileged", payload["message"])

    def test_gate_request_blocks_before_transport(self) -> None:
        client = build_client(blocked=True)
        gate = SecployGate(client=client)

        with patch("secploy.handlers.requests.request") as request_mock:
            with self.assertRaises(SecurityGateBlocked):
                gate.request("DELETE", "https://api.example.com/orders/1")

        request_mock.assert_not_called()
        client.send_event.assert_called_once()
        event_name, payload = client.send_event.call_args.args
        self.assertEqual(event_name, "warning")
        self.assertTrue(payload["context"]["secploy_gate"]["blocked"])
        self.assertEqual(payload["context"]["http_status"], 403)

    def test_gate_allows_flow_when_event_tracking_fails(self) -> None:
        gate = SecployGate(client=build_client(blocked=False, send_event_side_effect=RuntimeError("boom")))
        request = {"method": "GET", "url": "https://api.example.com/health"}

        allowed = gate(request=request)

        self.assertIs(allowed, request)

    def test_session_adapter_executes_transport_when_allowed(self) -> None:
        gate = SecployGate(client=build_client(blocked=False))
        secured_session = gate.session(
            auth={"auth_provider": "bearer"},
            metadata={"service": "tests"},
        )

        session_request = Mock(return_value="ok")
        secured_session.session.request = session_request

        response = secured_session.post(
            "https://api.example.com/orders",
            secploy_auth={"identity_key": "user_123"},
            json={"id": 99},
        )

        self.assertEqual(response, "ok")
        session_request.assert_called_once_with(
            "POST",
            "https://api.example.com/orders",
            json={"id": 99},
        )

    def test_blocked_exception_contains_control_context(self) -> None:
        gate = SecployGate(client=build_client(blocked=True, with_controls=True))

        with self.assertRaises(SecurityGateBlocked) as ctx:
            gate.request(
                "DELETE",
                "https://api.example.com/orders/1",
                auth={"identity_key": "user_123"},
            )

        exc = ctx.exception
        self.assertEqual(exc.action_type, "block_identity")
        self.assertEqual(exc.target, "user_123")
        self.assertIn("control=block_identity:user_123", str(exc))

    def test_protect_injects_protector_and_applies_registered_identity(self) -> None:
        gate = SecployGate(client=build_client(blocked=True, with_controls=True))
        checkpoint = []

        @gate.protect(endpoint="/me", method="GET")
        def me(protector):
            checkpoint.append("entered")
            protector.register_identity(
                id="user_123",
                name="Test User",
                email="test@example.com",
            )
            checkpoint.append("after")
            return "ok"

        with self.assertRaises(SecurityGateBlocked):
            me()

        self.assertEqual(checkpoint, ["entered"])

    def test_protect_with_protector_defaults_to_anonymous_when_not_registered(self) -> None:
        gate = SecployGate(client=build_client(blocked=True, with_controls=True))

        @gate.protect(endpoint="/public", method="GET")
        def public_endpoint(protector):
            return "ok"

        self.assertEqual(public_endpoint(), "ok")

    def test_protect_injects_protector_when_kwarg_is_none(self) -> None:
        gate = SecployGate(client=build_client(blocked=True, with_controls=True))
        checkpoint = []

        @gate.protect(endpoint="/me", method="GET")
        def me(protector=None):
            checkpoint.append("entered")
            protector.register_identity(id="user_123")
            checkpoint.append("after")
            return "ok"

        with self.assertRaises(SecurityGateBlocked):
            me(protector=None)

        self.assertEqual(checkpoint, ["entered"])

    def test_protect_injects_protector_when_kwarg_is_signature_default(self) -> None:
        gate = SecployGate(client=build_client(blocked=True, with_controls=True))
        checkpoint = []
        sentinel = object()

        @gate.protect(endpoint="/me", method="GET")
        def me(protector=sentinel):
            checkpoint.append("entered")
            protector.register_identity(id="user_123")
            checkpoint.append("after")
            return "ok"

        with self.assertRaises(SecurityGateBlocked):
            me(protector=sentinel)

        self.assertEqual(checkpoint, ["entered"])

    def test_django_middleware_uses_custom_blocked_handler(self) -> None:
        gate = SecployGate(client=build_client(blocked=True))
        get_response = Mock(return_value="allowed")
        request = SimpleNamespace(method="POST", path="/api/orders", headers={}, COOKIES={})

        middleware = gate.django_middleware(
            get_response,
            blocked_handler=lambda req, exc: ("blocked", exc.decision["reason"]),
        )

        result = middleware(request)

        self.assertEqual(result, ("blocked", "blocked_by_rule"))
        get_response.assert_not_called()

    def test_fastapi_middleware_uses_async_blocked_handler(self) -> None:
        gate = SecployGate(client=build_client(blocked=True))
        request = SimpleNamespace(
            method="POST",
            url=SimpleNamespace(path="/api/orders"),
            headers={},
            cookies={},
        )
        call_next = Mock(return_value="allowed")

        async def blocked_handler(req, exc):
            return {"detail": exc.decision["reason"]}

        middleware = gate.fastapi_middleware(blocked_handler=blocked_handler)
        result = asyncio.run(middleware(request, call_next))

        self.assertEqual(result, {"detail": "blocked_by_rule"})
        call_next.assert_not_called()


class SecployGateCompatibilityTests(unittest.TestCase):
    def test_compat_gate_named_parameters_return_gate_request(self) -> None:
        gate = CompatSecployGate(client=build_client(blocked=False))

        allowed = gate(
            method="PATCH",
            endpoint="/api/settings",
            user_id="u_1",
            session_id="sess_1",
        )

        self.assertIsInstance(allowed, GateRequest)
        self.assertEqual(allowed.method, "PATCH")
        self.assertEqual(allowed.path, "/api/settings")

    def test_compat_gate_non_strict_returns_gate_decision(self) -> None:
        gate = CompatSecployGate(client=build_client(blocked=True), strict_mode=False)

        decision = gate(method="DELETE", endpoint="/api/settings")

        self.assertIsInstance(decision, GateDecision)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "blocked_by_rule")

    def test_compat_gate_strict_raises_legacy_exception(self) -> None:
        gate = CompatSecployGate(client=build_client(blocked=True), strict_mode=True)

        with self.assertRaises(SecurityGateException):
            gate(method="DELETE", endpoint="/api/settings")


if __name__ == "__main__":
    unittest.main()