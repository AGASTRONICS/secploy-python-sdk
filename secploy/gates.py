"""Backward-compatible gate API built on top of the current SecployGate."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, Optional, Union
from urllib.parse import urlsplit

from .handlers import SecployGate as BaseSecployGate
from .handlers import SecurityGateBlocked
from .schemas import SecurityGateDecision


class SecurityGateException(SecurityGateBlocked):
    """Backward-compatible alias for blocked gate requests."""

    def __init__(self, decision: SecurityGateDecision):
        super().__init__(decision)
        self.reason = str(decision.get("reason") or "blocked_by_secploy")
        controls = decision.get("controls") or []
        first_control = controls[0] if isinstance(controls, list) and controls else {}
        self.action_type = first_control.get("action_type")
        self.target = first_control.get("target")


class GateRequest:
    """Flexible request wrapper for callers using the legacy gates module."""

    def __init__(
        self,
        method: str,
        endpoint: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        identity_key: Optional[str] = None,
        auth_provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        request_body: Optional[Dict[str, Any]] = None,
    ):
        self.method = method.strip().upper()
        self.endpoint = endpoint.strip()
        self.user_id = user_id
        self.session_id = session_id
        self.identity_key = identity_key
        self.auth_provider = auth_provider
        self.metadata = metadata or {}
        self.request_body = request_body or {}
        self.timestamp = datetime.now(UTC).isoformat()

        parsed = urlsplit(self.endpoint)
        self.path = parsed.path or self.endpoint
        if self.path and not self.path.startswith("/"):
            self.path = f"/{self.path}"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GateRequest":
        return cls(
            method=data.get("method", "GET"),
            endpoint=data.get("endpoint") or data.get("url") or data.get("path") or "",
            user_id=data.get("user_id"),
            session_id=data.get("session_id"),
            identity_key=data.get("identity_key"),
            auth_provider=data.get("auth_provider"),
            metadata=data.get("metadata"),
            request_body=data.get("body") or data.get("json"),
        )

    @classmethod
    def from_request_obj(cls, request: Any) -> "GateRequest":
        url = getattr(request, "url", None)
        path = getattr(url, "path", None) if url is not None else None
        endpoint = str(path or url or getattr(request, "path", None) or "")
        return cls(
            method=str(getattr(request, "method", "GET")),
            endpoint=endpoint,
            metadata=getattr(request, "metadata", None),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "endpoint": self.endpoint,
            "path": self.path,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "identity_key": self.identity_key,
            "auth_provider": self.auth_provider,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


class GateDecision:
    """Legacy object wrapper around the current typed gate decision."""

    def __init__(self, allowed: bool, reason: str, checks_performed: Dict[str, Any]):
        self.allowed = allowed
        self.reason = reason
        self.checks_performed = checks_performed
        self.timestamp = datetime.now(UTC).isoformat()

    @classmethod
    def from_security_decision(cls, decision: SecurityGateDecision) -> "GateDecision":
        checks_performed = {
            "rule": decision.get("rule") or {},
            "controls": decision.get("controls") or [],
            "metadata": decision.get("metadata") or {},
            "auth": decision.get("auth") or {},
        }
        return cls(
            allowed=bool(decision.get("allowed", False)),
            reason=str(decision.get("reason") or "blocked_by_secploy"),
            checks_performed=checks_performed,
        )

    def __repr__(self) -> str:
        return f"GateDecision(allowed={self.allowed}, reason={self.reason!r})"


class SecployGate(BaseSecployGate):
    """Compatibility wrapper matching the original secploy.gates API."""

    def __init__(
        self,
        client: Any,
        auto_submit_events: bool = True,
        strict_mode: bool = True,
        **kwargs: Any,
    ):
        super().__init__(
            client=client,
            track_decisions=auto_submit_events,
            raise_on_block=strict_mode,
            **kwargs,
        )
        self.auto_submit_events = auto_submit_events
        self.strict_mode = strict_mode

    def __call__(
        self,
        request: Union[Dict[str, Any], Any, None] = None,
        method: Optional[str] = None,
        endpoint: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        identity_key: Optional[str] = None,
        auth_provider: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Union[GateRequest, GateDecision, Any]:
        request_obj, auth = self._build_request_and_auth(
            request=request,
            method=method,
            endpoint=endpoint,
            user_id=user_id,
            session_id=session_id,
            identity_key=identity_key,
            auth_provider=auth_provider,
            metadata=metadata,
        )

        try:
            allowed = super().__call__(request=request_obj, auth=auth, metadata=metadata)
        except SecurityGateBlocked as exc:
            if self.strict_mode:
                raise SecurityGateException(exc.decision) from exc
            return GateDecision.from_security_decision(exc.decision)

        if isinstance(allowed, dict) and allowed.get("blocked"):
            return GateDecision.from_security_decision(allowed)

        if isinstance(request_obj, GateRequest):
            return request_obj
        return allowed

    def batch_check(
        self,
        requests: list[Union[Dict[str, Any], Any]],
        fail_fast: bool = True,
    ) -> list[Union[GateRequest, GateDecision, Any]]:
        results = []
        for item in requests:
            try:
                results.append(self(request=item))
            except SecurityGateException:
                if fail_fast:
                    raise
                decision = self.inspect(request=item)
                results.append(GateDecision.from_security_decision(decision))
        return results

    def _build_request_and_auth(
        self,
        request: Union[Dict[str, Any], Any, None],
        method: Optional[str],
        endpoint: Optional[str],
        user_id: Optional[str],
        session_id: Optional[str],
        identity_key: Optional[str],
        auth_provider: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> tuple[Any, Dict[str, Any]]:
        auth: Dict[str, Any] = {}
        if user_id:
            auth["user_id"] = user_id
        if session_id:
            auth["session_id"] = session_id
        if identity_key:
            auth["identity_key"] = identity_key
        if auth_provider:
            auth["auth_provider"] = auth_provider

        if isinstance(request, dict):
            request_obj = GateRequest.from_dict(request)
            if method:
                request_obj.method = method.strip().upper()
            if endpoint:
                request_obj.endpoint = endpoint
                request_obj.path = GateRequest(method=request_obj.method, endpoint=endpoint).path
            if user_id:
                request_obj.user_id = user_id
            if session_id:
                request_obj.session_id = session_id
            if identity_key:
                request_obj.identity_key = identity_key
            if auth_provider:
                request_obj.auth_provider = auth_provider
            if metadata:
                request_obj.metadata.update(metadata)
            auth.setdefault("identity_key", request_obj.identity_key)
            auth.setdefault("session_id", request_obj.session_id)
            auth.setdefault("auth_provider", request_obj.auth_provider)
            auth.setdefault("user_id", request_obj.user_id)
            return request_obj, auth

        if request is not None:
            return request, auth

        if not method or not endpoint:
            raise ValueError("method and endpoint are required")

        request_obj = GateRequest(
            method=method,
            endpoint=endpoint,
            user_id=user_id,
            session_id=session_id,
            identity_key=identity_key,
            auth_provider=auth_provider,
            metadata=metadata,
        )
        return request_obj, auth


__all__ = [
    "SecployGate",
    "SecurityGateException",
    "GateRequest",
    "GateDecision",
]
