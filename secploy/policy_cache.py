"""
Local security policy cache for the Secploy gate.

The gate used to ask the API whether each individual request was allowed, which
put a network round trip on the caller's request path — plus, on the server, a
tenant lookup, a schema switch, rule matching and an identity write, per
request. This module holds the whole policy in process instead, so a gate
decision is a dictionary lookup and a pre-compiled regex.

Correctness rests on one rule: **the decision must be byte-identical to what the
API would have returned.** So ``evaluate()`` reproduces the server's raw response
payload rather than a decision object, and the client builds the final decision
from that payload with the same code it uses for a remote response. There is one
decision-builder and two payload sources, which is what makes shadow mode a
meaningful comparison instead of two implementations drifting apart.

Snapshots are immutable. Refreshing swaps a single attribute, which is atomic
under the GIL, so the read path takes no lock at all and a reader always sees a
whole snapshot — never a half-rebuilt one.
"""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Pattern, Tuple

import requests

from .lib import secploy_logger

# Matches SDKBlockedEndpointCheckView: a control is enforceable in these states.
ACTIVE_CONTROL_STATUSES = frozenset({"pending", "applied", "requires_adapter"})

DEFAULT_FETCH_TIMEOUT = 10

# How long a snapshot may go unrefreshed before we start warning. Enforcement
# continues regardless — a stale policy is far better than no policy, and the
# whole point of caching is to keep working when the API cannot be reached.
DEFAULT_MAX_STALENESS = 900


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _compile(pattern: str) -> Optional[Pattern]:
    """
    Pre-compile a rule pattern, or return None when it is not valid regex.

    The server falls back to exact string comparison on ``re.error``; a None here
    means the caller does the same, so an invalid pattern behaves identically in
    both places.
    """
    try:
        return re.compile(pattern)
    except re.error:
        return None


class PolicySnapshot:
    """
    One immutable, query-ready view of a project's gate policy.

    Rules are bucketed by method and pre-compiled once here rather than being
    re-parsed on every request, and controls are indexed by ``(target_type,
    target)`` so matching is a handful of dictionary lookups instead of a scan.
    """

    __slots__ = (
        "version",
        "fetched_at",
        "generated_at",
        "ttl_seconds",
        "rules_by_method",
        "controls_by_target",
        "rule_count",
        "control_count",
    )

    def __init__(self, payload: Dict[str, Any]):
        self.version: str = str(payload.get("version") or "")
        self.generated_at = payload.get("generated_at")
        self.ttl_seconds = int(payload.get("ttl_seconds") or 300)
        self.fetched_at = time.time()

        rules: Dict[str, List[Tuple[Optional[Pattern], str, Dict[str, Any]]]] = {}
        for rule in payload.get("blocked_endpoints") or []:
            if not isinstance(rule, dict):
                continue
            method = str(rule.get("method") or "").strip().upper()
            pattern = str(rule.get("path_pattern") or "")
            rules.setdefault(method, []).append((_compile(pattern), pattern, rule))
        self.rules_by_method = rules
        self.rule_count = sum(len(v) for v in rules.values())

        # (target_type, target) -> [(order, control, compiled_scope_pattern)]
        controls: Dict[Tuple[str, str], List[Tuple[int, Dict[str, Any], Any]]] = {}
        count = 0
        for order, control in enumerate(payload.get("controls") or []):
            if not isinstance(control, dict):
                continue
            if str(control.get("status") or "") not in ACTIVE_CONTROL_STATUSES:
                continue
            target_type = str(control.get("target_type") or "").strip()
            target = str(control.get("target") or "").strip()
            if not target_type or not target:
                continue

            scope_pattern = None
            metadata = control.get("metadata")
            if isinstance(metadata, dict):
                scope = metadata.get("endpoint_scope")
                if isinstance(scope, dict):
                    raw = str(scope.get("path_pattern") or "").strip()
                    if raw:
                        scope_pattern = (_compile(raw), raw)

            controls.setdefault((target_type, target), []).append(
                (order, control, scope_pattern)
            )
            count += 1
        self.controls_by_target = controls
        self.control_count = count

    @property
    def age_seconds(self) -> float:
        return time.time() - self.fetched_at

    def __repr__(self) -> str:
        return (
            f"<PolicySnapshot version={self.version} rules={self.rule_count} "
            f"controls={self.control_count} age={self.age_seconds:.0f}s>"
        )


def _control_matches_endpoint_scope(control, scope_pattern, method: str, endpoint: str) -> bool:
    """
    Port of SDKBlockedEndpointCheckView._control_matches_endpoint_scope.

    A control with no ``endpoint_scope`` stays project-wide; one with a scope only
    applies to matching methods and paths.
    """
    metadata = control.get("metadata")
    scope = metadata.get("endpoint_scope") if isinstance(metadata, dict) else None
    if not isinstance(scope, dict):
        return True

    scoped_method = str(scope.get("method") or "").strip().upper()
    if scoped_method and scoped_method != method:
        return False

    if scope_pattern is None:
        # No path_pattern in the scope: method-only scoping, already satisfied.
        return True

    compiled, raw = scope_pattern
    if compiled is None:
        return raw == endpoint
    return compiled.search(endpoint) is not None


class SecurityPolicyCache:
    """
    Fetches, holds and refreshes the project's gate policy.

    Args:
        api_url:          Base API URL, e.g. ``https://api.secploy.com``.
        headers_callback: Returns current SDK auth headers.
        max_staleness:    Seconds before an unrefreshed snapshot starts warning.
    """

    def __init__(
        self,
        api_url: str,
        headers_callback,
        max_staleness: int = DEFAULT_MAX_STALENESS,
    ):
        self._api_url = api_url.rstrip("/")
        self._get_headers = headers_callback
        self._max_staleness = max_staleness

        # Rebound wholesale on refresh; never mutated in place. Readers do not lock.
        self._snapshot: Optional[PolicySnapshot] = None

        self._fetch_lock = threading.Lock()
        self._realtime = None
        self._stale_warned = False

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    @property
    def snapshot(self) -> Optional[PolicySnapshot]:
        return self._snapshot

    @property
    def is_loaded(self) -> bool:
        return self._snapshot is not None

    @property
    def version(self) -> Optional[str]:
        snapshot = self._snapshot
        return snapshot.version if snapshot else None

    # ------------------------------------------------------------------
    # Fetch
    # ------------------------------------------------------------------

    def fetch(self, timeout: int = DEFAULT_FETCH_TIMEOUT) -> Optional[PolicySnapshot]:
        """
        Pull the current snapshot, or keep the existing one on a 304.

        Returns the live snapshot, or None if nothing could be loaded. Never
        raises: a policy refresh failure must not surface in the host
        application, it just means the previous snapshot stays in force.
        """
        with self._fetch_lock:
            current = self._snapshot
            try:
                headers = dict(self._get_headers() or {})
            except Exception as exc:
                secploy_logger.warning(f"Security policy fetch: headers failed: {exc}")
                return current
            if current and current.version:
                headers["If-None-Match"] = f'"{current.version}"'

            try:
                response = requests.get(
                    f"{self._api_url}/projects/security/policy/",
                    headers=headers,
                    timeout=timeout,
                )
            except Exception as exc:
                # Deliberately broad. fetch() runs on the WebSocket handler, the
                # polling thread and the start-up thread; anything that escapes
                # here kills refreshing for the life of the process, so the gate
                # would silently freeze on whatever snapshot it last had.
                secploy_logger.warning(f"Security policy fetch failed: {exc}")
                return current

            if response.status_code == 304:
                if current:
                    current.fetched_at = time.time()
                    self._stale_warned = False
                return current

            if response.status_code == 401:
                secploy_logger.warning(
                    "Security policy fetch: invalid API key or environment key."
                )
                return current

            if not response.ok:
                secploy_logger.warning(
                    f"Security policy fetch failed ({response.status_code})."
                )
                return current

            try:
                payload = response.json()
            except Exception as exc:
                secploy_logger.warning(f"Security policy response was not JSON: {exc}")
                return current

            if not isinstance(payload, dict):
                secploy_logger.warning("Security policy response had an unexpected shape.")
                return current

            try:
                snapshot = PolicySnapshot(payload)
            except Exception as exc:
                secploy_logger.warning(f"Security policy snapshot build failed: {exc}")
                return current
            self._snapshot = snapshot  # atomic rebind; readers see old or new
            self._stale_warned = False
            secploy_logger.info(
                f"Security policy loaded: version={snapshot.version} "
                f"rules={snapshot.rule_count} controls={snapshot.control_count}"
            )
            return snapshot

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        method: str,
        endpoint: str,
        auth: Optional[Dict[str, Any]] = None,
        project_key: str = "",
        env_key: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Reproduce the API's raw decision payload from the local snapshot.

        Returns None when no snapshot has loaded yet, so the caller can fall back
        to a remote lookup instead of guessing.
        """
        snapshot = self._snapshot
        if snapshot is None:
            return None

        self._warn_if_stale(snapshot)

        auth = auth or {}
        rule = self._match_rule(snapshot, method, endpoint)
        controls = self._match_controls(
            snapshot, method, endpoint, auth, project_key, env_key
        )

        payload: Dict[str, Any] = {
            "blocked": rule is not None or bool(controls),
            "method": method,
            "endpoint": endpoint,
        }
        if rule is not None:
            payload["rule"] = rule
            payload["reason"] = "blocked_by_endpoint_rule"
        if controls:
            payload["controls"] = controls
            if "reason" not in payload:
                payload["reason"] = "blocked_by_control_action"

        return payload

    @staticmethod
    def _match_rule(snapshot: PolicySnapshot, method: str, endpoint: str):
        """First matching rule wins, in the snapshot's newest-first order."""
        for compiled, raw, rule in snapshot.rules_by_method.get(method, ()):
            if compiled is None:
                if raw == endpoint:
                    return rule
                continue
            if compiled.search(endpoint):
                return rule
        return None

    def _match_controls(
        self,
        snapshot: PolicySnapshot,
        method: str,
        endpoint: str,
        auth: Dict[str, Any],
        project_key: str,
        env_key: str,
    ) -> List[Dict[str, Any]]:
        """
        Port of _resolve_active_controls: match on session, identity, IP or API
        key, then apply endpoint scoping.
        """
        identity_key = str(auth.get("identity_key") or "").strip()
        user_id = str(auth.get("user_id") or "").strip()
        session_id = str(auth.get("session_id") or "").strip()
        ip_address = str(auth.get("ip_address") or "").strip()
        remote_addr = str(auth.get("remote_addr") or "").strip()

        lookups: List[Tuple[str, str]] = []
        if session_id:
            lookups.append(("session", session_id))
        for value in dict.fromkeys(v for v in (identity_key, user_id) if v):
            lookups.append(("identity", value))
        for value in dict.fromkeys(v for v in (ip_address, remote_addr) if v):
            lookups.append(("ip", value))
        for value in dict.fromkeys(v for v in (project_key, env_key) if v):
            lookups.append(("api_key", value))

        if not lookups:
            return []

        now = datetime.now(timezone.utc)
        matched: Dict[str, Tuple[int, Dict[str, Any]]] = {}

        for key in lookups:
            for order, control, scope_pattern in snapshot.controls_by_target.get(key, ()):
                control_id = str(control.get("id") or f"{key}:{order}")
                if control_id in matched:
                    continue

                # The snapshot can outlive a control's expiry by up to its TTL,
                # so expiry is re-checked here. Enforcing a lapsed control means
                # blocking a request that should now succeed.
                expires_at = _parse_dt(control.get("expires_at"))
                if expires_at is not None and expires_at <= now:
                    continue

                if not _control_matches_endpoint_scope(
                    control, scope_pattern, method, endpoint
                ):
                    continue

                matched[control_id] = (order, control)

        # Restore the server's ordering, which the per-target index does not keep.
        return [control for _, control in sorted(matched.values(), key=lambda item: item[0])]

    def _warn_if_stale(self, snapshot: PolicySnapshot) -> None:
        if self._stale_warned or snapshot.age_seconds <= self._max_staleness:
            return
        self._stale_warned = True
        secploy_logger.warning(
            f"Secploy security policy has not refreshed in "
            f"{snapshot.age_seconds:.0f}s (version={snapshot.version}). "
            "Still enforcing the last known policy."
        )

    # ------------------------------------------------------------------
    # Real-time delivery
    # ------------------------------------------------------------------

    def start_realtime(self, ws_url: str, headers_callback) -> None:
        """Subscribe to policy-change pushes, with the usual polling fallback."""
        if self._realtime is not None:
            secploy_logger.warning("Security policy real-time is already running.")
            return

        from .realtime import RealtimeChannel

        self._realtime = RealtimeChannel(
            ws_url=ws_url,
            headers_callback=headers_callback,
            on_update=self.fetch,
            channel_name="security policy",
            thread_prefix="secploy-security",
            update_message_types=("security.update", "security.subscribed"),
        )
        self._realtime.start()

    def stop_realtime(self) -> None:
        if self._realtime is not None:
            self._realtime.stop()
            self._realtime = None
            secploy_logger.info("Security policy real-time stopped.")

    @property
    def is_realtime(self) -> bool:
        return self._realtime is not None and self._realtime.is_connected
