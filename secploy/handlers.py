from __future__ import annotations

import inspect
import time
from functools import wraps
from importlib import import_module
from typing import Callable
from typing import TYPE_CHECKING, Any, Dict, Mapping, MutableMapping, Optional
from urllib.parse import urlsplit

import requests

from .lib import secploy_logger
from .schemas import SecurityGateAuthContext, SecurityGateDecision
from .scrubbing import hash_session_id

if TYPE_CHECKING:
	from .client import SecployClient


def _json_safe(value: Any, max_depth: int = 5) -> Any:
	"""Best-effort conversion to JSON-serializable values for telemetry payloads."""
	if max_depth <= 0:
		return repr(value)

	if value is None or isinstance(value, (str, int, float, bool)):
		return value

	if isinstance(value, bytes):
		try:
			return value.decode("utf-8", errors="replace")
		except Exception:
			return repr(value)

	if isinstance(value, Mapping):
		return {
			str(k): _json_safe(v, max_depth=max_depth - 1)
			for k, v in value.items()
		}

	if isinstance(value, (list, tuple, set)):
		return [_json_safe(v, max_depth=max_depth - 1) for v in value]

	return repr(value)


class SecurityGateBlocked(Exception):
	"""Raised when Secploy explicitly blocks a request."""

	def __init__(self, decision: SecurityGateDecision):
		self.decision = decision
		self.reason = str(decision.get("reason") or "blocked_by_secploy")
		self.rule = decision.get("rule") if isinstance(decision.get("rule"), dict) else {}
		self.controls = decision.get("controls") if isinstance(decision.get("controls"), list) else []
		first_control = self.controls[0] if self.controls else {}
		self.action_type = first_control.get("action_type")
		self.target = first_control.get("target")

		method = decision.get("method") or "UNKNOWN"
		endpoint = decision.get("endpoint") or ""
		rule_reason = self.rule.get("reason") if isinstance(self.rule, dict) else None
		parts = [f"Secploy blocked {method} {endpoint}", f"reason={self.reason}"]
		if rule_reason:
			parts.append(f"rule={rule_reason}")
		if self.action_type or self.target:
			parts.append(f"control={self.action_type or 'unknown'}:{self.target or 'unknown'}")
		super().__init__(" | ".join(parts))


class MFARequiredException(SecurityGateBlocked):
	"""Raised when Secploy requires MFA verification before the request is allowed.

	The caller should redirect the user to an MFA challenge.  ``http_status_code``
	is 401 so that frameworks can map it to a ``401 Unauthorized`` response.
	"""

	http_status_code: int = 401


class SessionRevokedException(SecurityGateBlocked):
	"""Raised when Secploy has revoked the caller's session (``revoke_session``)."""

	http_status_code: int = 401


class SessionRestrictedException(SecurityGateBlocked):
	"""Raised when Secploy has restricted (but not fully revoked) the session (``restrict_session``)."""

	http_status_code: int = 403


class IPBlockedException(SecurityGateBlocked):
	"""Raised when Secploy blocks the request based on the source IP address (``block_ip``)."""

	http_status_code: int = 403


class RateLimitedException(SecurityGateBlocked):
	"""Raised when Secploy applies a rate-limit control (``rate_limit``).

	``retry_after`` is populated from the control's ``retry_after`` field when
	present (seconds until the limit resets).
	"""

	http_status_code: int = 429

	def __init__(self, decision: SecurityGateDecision) -> None:
		super().__init__(decision)
		first_control = self.controls[0] if self.controls else {}
		self.retry_after: Optional[int] = first_control.get("retry_after")


class APIKeyBlockedException(SecurityGateBlocked):
	"""Raised when Secploy blocks the request because the API key is revoked (``block_api_key``)."""

	http_status_code: int = 401


class _ProtectIdentityRegistrar:
	"""Helper injected into protected handlers to register request identity details.

	Use ``register_identity(...)`` as early as possible in the handler so identity-
	scoped controls can be enforced before business logic runs.
	"""

	def __init__(
		self,
		gate: "SecployGate",
		request_payload: Dict[str, Any],
		base_auth: Optional[Dict[str, Any]],
		handlers: Dict[str, Optional[Callable[..., Any]]],
		request_obj: Optional[Any],
	):
		self._gate = gate
		self._request_payload = request_payload
		self._base_auth = dict(base_auth or {})
		self._handlers = handlers
		self._request_obj = request_obj
		self._resolved = False
		self._decision: Optional[SecurityGateDecision] = None

	def register_identity(
		self,
		id: Any,
		name: Optional[str] = None,
		username: Optional[str] = None,
		avater: Optional[str] = None,
		avatar: Optional[str] = None,
		email: Optional[str] = None,
		metadata: Optional[Dict[str, Any]] = None,
		is_authenticated: Optional[bool] = None,
		auth_provider: Optional[str] = None,
		session_id: Optional[str] = None,
		ip_address: Optional[str] = None,
		remote_addr: Optional[str] = None,
	) -> SecurityGateDecision:
		"""Merge identity context into this protected call and evaluate the gate."""
		identity_key = str(id).strip() if id is not None else ""
		if not identity_key:
			identity_key = str(self._base_auth.get("identity_key") or "").strip() or "anonymous"

		auth_context = dict(self._base_auth)
		auth_context["identity_key"] = identity_key

		if name:
			auth_context["name"] = str(name)
		if username:
			auth_context["username"] = str(username)
		if avatar:
			auth_context["avatar"] = str(avatar)
		elif avater:
			auth_context["avatar"] = str(avater)
		if email:
			auth_context["email"] = str(email)
		if metadata is not None:
			auth_context["metadata"] = dict(metadata)
		if is_authenticated is not None:
			auth_context["is_authenticated"] = bool(is_authenticated)
		if auth_provider:
			auth_context["auth_provider"] = str(auth_provider)
		if session_id:
			auth_context["session_id"] = str(session_id)
		if ip_address:
			auth_context["ip_address"] = str(ip_address)
		if remote_addr:
			auth_context["remote_addr"] = str(remote_addr)

		decision = self._gate.inspect(request=self._request_payload, auth=auth_context)
		self._resolved = True
		self._decision = decision
		if decision.get("blocked"):
			request_args = (self._request_obj,) if self._request_obj is not None else ()
			self._gate._dispatch_control_exception(decision, request_args, self._handlers)
		return decision

	def ensure_checked(self) -> None:
		"""Guarantee at least one gate evaluation for protected handlers."""
		if self._resolved:
			return
		decision = self._gate.inspect(request=self._request_payload, auth=self._base_auth)
		self._resolved = True
		self._decision = decision
		if decision.get("blocked"):
			request_args = (self._request_obj,) if self._request_obj is not None else ()
			self._gate._dispatch_control_exception(decision, request_args, self._handlers)


class SecploySessionAdapter:
	"""Adapter that applies Secploy gate checks to all requests sent through a session."""

	def __init__(
		self,
		gate: "SecployGate",
		session: Optional[requests.Session] = None,
		auth: Optional[Dict[str, Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
	):
		self._gate = gate
		self._session = session or requests.Session()
		self._default_auth = dict(auth or {})
		self._default_metadata = dict(metadata or {})

	@property
	def session(self) -> requests.Session:
		return self._session

	def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
		request_auth = dict(self._default_auth)
		request_auth.update(dict(kwargs.pop("secploy_auth", {}) or {}))

		request_metadata = dict(self._default_metadata)
		request_metadata.update(dict(kwargs.pop("secploy_metadata", {}) or {}))

		return self._gate.request(
			method,
			url,
			session=self._session,
			auth=request_auth or None,
			metadata=request_metadata or None,
			**kwargs,
		)

	def get(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("GET", url, **kwargs)

	def post(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("POST", url, **kwargs)

	def put(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("PUT", url, **kwargs)

	def patch(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("PATCH", url, **kwargs)

	def delete(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("DELETE", url, **kwargs)

	def head(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("HEAD", url, **kwargs)

	def options(self, url: str, **kwargs: Any) -> requests.Response:
		return self.request("OPTIONS", url, **kwargs)

	def __getattr__(self, name: str) -> Any:
		return getattr(self._session, name)


class SecployGate:
	"""
	Callable request gate for framework and client request objects.

	Allowed requests are returned unchanged so the gate fits naturally into
	wrappers and middleware. Blocked requests raise SecurityGateBlocked by
	default, or return the decision if raise_on_block=False.
	"""

	_AUTH_PATHS = ("/auth", "/login", "/signin", "/token", "/password",
	               "/credential", "/session", "/oauth", "/sso", "/logout")
	_PAYMENT_PATHS = ("/pay", "/checkout", "/billing", "/charge",
	                  "/transaction", "/wallet", "/card", "/invoice", "/refund")
	_ADMIN_PATHS = ("/admin", "/internal", "/actuator", "/debug",
	                "/console", "/config", "/.env", "/manage", "/.git")

	def __init__(
		self,
		client: Optional["SecployClient"] = None,
		timeout: int = 5,
		fail_open: bool = True,
		raise_on_block: bool = True,
		track_decisions: bool = True,
		**client_kwargs: Any,
	):
		if client is None:
			from .client import SecployClient

			client = SecployClient(**client_kwargs)

		self.client = client
		self.timeout = timeout
		self.fail_open = fail_open
		self.raise_on_block = raise_on_block
		self.track_decisions = track_decisions
		self._protected_bindings: Dict[str, Dict[str, str]] = {}

	def __call__(
		self,
		request: Any,
		auth: Optional[Dict[str, Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
		timeout: Optional[int] = None,
	) -> Any:
		decision = self.inspect(
			request=request,
			auth=auth,
			metadata=metadata,
			timeout=timeout,
		)
		if decision.get("blocked"):
			if self.raise_on_block:
				raise SecurityGateBlocked(decision)
			return decision
		return request

	def request(
		self,
		method: str,
		url: str,
		*,
		session: Optional[Any] = None,
		auth: Optional[Dict[str, Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
		**kwargs: Any,
	) -> Any:
		"""
		Run an outbound HTTP request through the gate, then execute it if allowed.
		"""
		request_payload = {
			"method": method,
			"url": url,
			"headers": self._coerce_mapping(kwargs.get("headers")),
			"cookies": self._coerce_mapping(kwargs.get("cookies")),
		}
		self(request=request_payload, auth=auth, metadata=metadata)

		transport = session.request if session is not None else requests.request
		started_at = time.perf_counter()
		try:
			response = transport(method, url, **kwargs)
		except Exception as exc:
			self._track_outbound_dependency_call(
				method=method,
				url=url,
				status_code=None,
				duration_ms=(time.perf_counter() - started_at) * 1000,
				metadata=metadata,
				error=exc,
			)
			raise

		self._track_outbound_dependency_call(
			method=method,
			url=url,
			status_code=getattr(response, "status_code", None),
			duration_ms=(time.perf_counter() - started_at) * 1000,
			metadata=metadata,
		)
		return response

	def session(
		self,
		session: Optional[requests.Session] = None,
		auth: Optional[Dict[str, Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
	) -> SecploySessionAdapter:
		"""Create a requests-compatible session adapter guarded by this gate."""
		return SecploySessionAdapter(
			gate=self,
			session=session,
			auth=auth,
			metadata=metadata,
		)

	def flask_before_request(
		self,
		blocked_handler: Optional[Callable[..., Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
	) -> Callable[[], Any]:
		"""
		Create a Flask before_request hook that blocks denied requests.
		"""
		def middleware() -> Any:
			flask = import_module("flask")
			jsonify = flask.jsonify
			request = flask.request

			try:
				self(request=request, metadata=metadata)
			except SecurityGateBlocked as exc:
				handler_result = self._invoke_blocked_handler(blocked_handler, request, exc)
				if handler_result is not None:
					return handler_result
				return jsonify(self._blocked_response_body(exc)), 403
			return None

		return middleware

	def django_middleware(
		self,
		get_response: Callable[[Any], Any],
		blocked_handler: Optional[Callable[..., Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
	) -> Callable[[Any], Any]:
		"""
		Create a Django-compatible middleware callable around an existing handler.
		"""
		def middleware(request: Any) -> Any:
			try:
				self(request=request, metadata=metadata)
			except SecurityGateBlocked as exc:
				handler_result = self._invoke_blocked_handler(blocked_handler, request, exc)
				if handler_result is not None:
					return handler_result
				JsonResponse = import_module("django.http").JsonResponse

				return JsonResponse(self._blocked_response_body(exc), status=403)
			return get_response(request)

		return middleware

	def fastapi_middleware(
		self,
		blocked_handler: Optional[Callable[..., Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
	) -> Callable[[Any, Callable[[Any], Any]], Any]:
		"""
		Create a FastAPI / Starlette HTTP middleware callable.
		"""
		async def middleware(request: Any, call_next: Callable[[Any], Any]) -> Any:
			try:
				self(request=request, metadata=metadata)
			except SecurityGateBlocked as exc:
				handler_result = self._invoke_blocked_handler(blocked_handler, request, exc)
				if inspect.isawaitable(handler_result):
					return await handler_result
				if handler_result is not None:
					return handler_result
				JSONResponse = import_module("starlette.responses").JSONResponse

				return JSONResponse(self._blocked_response_body(exc), status_code=403)

			response = call_next(request)
			if inspect.isawaitable(response):
				return await response
			return response

		return middleware

	def inspect(
		self,
		request: Any,
		auth: Optional[Dict[str, Any]] = None,
		metadata: Optional[Dict[str, Any]] = None,
		timeout: Optional[int] = None,
	) -> SecurityGateDecision:
		normalized_request = self._normalize_request(request)
		method = normalized_request["method"]
		endpoint = normalized_request["endpoint"]
		raw_url = normalized_request.get("url") or endpoint
		auth_context = self._resolve_auth_context(
			request=request,
			headers=normalized_request.get("headers") or {},
			cookies=normalized_request.get("cookies") or {},
			explicit_auth=auth,
		)

		try:
			decision = self.client.get_endpoint_decision(
				method=method,
				endpoint=endpoint,
				auth=auth_context,
				timeout=timeout or self.timeout,
			)
			if not self.fail_open and self._is_lookup_fallback(decision):
				raise RuntimeError(
					f"Secploy decision lookup failed for {method} {endpoint}: "
					f"{decision.get('reason', 'lookup_unavailable')}"
				)
		except Exception as exc:
			if not self.fail_open:
				raise
			secploy_logger.warning(f"Secploy gate failed open for {method} {endpoint}: {exc}")
			decision = {
				"allowed": True,
				"blocked": False,
				"method": method,
				"endpoint": endpoint,
				"url": raw_url,
				"reason": "lookup_unavailable",
				"rule": {},
				"controls": [],
				"raw": {},
			}

		decision["url"] = raw_url
		decision = self._filter_controls_by_auth_scope(decision, auth_context)
		decision["auth"] = auth_context
		decision["metadata"] = dict(metadata or {})

		if self.track_decisions:
			self._track_decision(decision)

		return decision
	
	# Function monitoring registry
	_registered_functions: Dict[str, Callable] = {}

	def register_function(self, fn: Callable) -> Callable:
		"""Register and wrap a function for monitoring and control, and emit an event on execution."""
		from functools import wraps
		fn_name = fn.__qualname__
		self._registered_functions[fn_name] = fn

		@wraps(fn)
		def wrapper(*args, **kwargs):
			# Gate check before function execution
			self(
				request={
					'method': 'FUNCTION',
					'endpoint': fn_name,
					'metadata': {'type': 'function', 'args': args, 'kwargs': kwargs},
				}
			)
			# Build function execution event payload
			import time
			import sys
			from inspect import signature
			from datetime import datetime, timezone
			start_time = time.time()
			start_time_iso = datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat()
			exc_info = None
			result = None
			try:
				result = fn(*args, **kwargs)
				return result
			except Exception as exc:
				exc_info = {
					"type": type(exc).__name__,
					"message": str(exc),
				}
				raise
			finally:
				duration = time.time() - start_time
				duration_s = round(duration, 6)
				# Try to get argument names and values
				try:
					sig = signature(fn)
					bound = sig.bind(*args, **kwargs)
					bound.apply_defaults()
					arg_map = dict(bound.arguments)
				except Exception:
					arg_map = {}

				safe_args = _json_safe(args)
				safe_kwargs = _json_safe(kwargs)
				safe_arg_map = _json_safe(arg_map)
				safe_exception = _json_safe(exc_info)
				result_type = type(result).__name__ if result is not None else None
				result_preview = _json_safe(result)

				telemetry_context = {
					"type": "function_execution",
					"function": fn_name,
					"module": fn.__module__,
					"qualname": fn.__qualname__,
					"args": safe_args,
					"kwargs": safe_kwargs,
					"arg_map": safe_arg_map,
					"result_type": result_type,
					"result_preview": result_preview,
					"duration_seconds": duration_s,
					"exception": safe_exception,
					"started_at": start_time_iso,
				}
				payload = {
					"type": "function_execution",
					"name": fn_name,
					"function": fn_name,
					"module": fn.__module__,
					"qualname": fn.__qualname__,
					"args": safe_args,
					"kwargs": safe_kwargs,
					"arg_map": safe_arg_map,
					"result_type": result_type,
					"result_preview": result_preview,
					"exception": safe_exception,
					"duration": f"{duration_s:.6f}",
					"timestamp": start_time_iso,
					"context": telemetry_context,
					"message": f"Function {fn_name} executed in {duration:.4f}s" + (f" with exception: {exc_info['type']}" if exc_info else ""),
				}
				try:
					self.client.send_event(
						event_type="function_execution",
						payload=payload
					)
				except Exception as exc:
					secploy_logger.warning(f"Failed to emit function execution event for {fn_name}: {exc}")
		return wrapper

	def monitor(self, fn: Callable) -> Callable:
		"""Decorator to monitor a function."""
		return self.register_function(fn)

	def sync_function_registry(self):
		"""Send the list of registered functions to the backend for control/visibility."""
		function_names = list(self._registered_functions.keys())
		try:
			self.client.send_event(
				event_type="function_registry",
				payload={"functions": function_names}
			)
		except Exception as exc:
			secploy_logger.warning(f"Failed to sync function registry: {exc}")

	# ------------------------------------------------------------------ #
	#  Endpoint / function protection decorator                           #
	# ------------------------------------------------------------------ #

	_CONTROL_TO_EXCEPTION: Dict[str, type] = {
		"force_mfa":        MFARequiredException,
		"revoke_session":   SessionRevokedException,
		"restrict_session": SessionRestrictedException,
		"block_ip":         IPBlockedException,
		"rate_limit":       RateLimitedException,
		"block_api_key":    APIKeyBlockedException,
	}

	def protect(
		self,
		endpoint: Optional[str] = None,
		method: Optional[str] = None,
		auth: Optional[Dict[str, Any]] = None,
		auth_extractor: Optional[Callable[..., Optional[Dict[str, Any]]]] = None,
		on_block: Optional[Callable[..., Any]] = None,
		on_mfa_required: Optional[Callable[..., Any]] = None,
		on_session_revoked: Optional[Callable[..., Any]] = None,
		on_ip_blocked: Optional[Callable[..., Any]] = None,
		on_rate_limited: Optional[Callable[..., Any]] = None,
	) -> Callable:
		"""Decorator that evaluates the Secploy security decision for the decorated
		endpoint or callable and raises the most-specific exception for the active
		control returned by the backend rule engine.

		Supported ``action_type`` → exception mapping:

		* ``force_mfa``        → :class:`MFARequiredException`   (HTTP 401)
		* ``revoke_session``   → :class:`SessionRevokedException` (HTTP 401)
		* ``restrict_session`` → :class:`SessionRestrictedException` (HTTP 403)
		* ``block_ip``         → :class:`IPBlockedException`      (HTTP 403)
		* ``rate_limit``       → :class:`RateLimitedException`    (HTTP 429)
		* ``block_api_key``    → :class:`APIKeyBlockedException`  (HTTP 401)
		* *(any other block)*  → :class:`SecurityGateBlocked`     (HTTP 403)

		Control-specific handlers (``on_mfa_required``, ``on_session_revoked``,
		``on_ip_blocked``, ``on_rate_limited``, ``on_block``) are called with
		``(request_obj, exception)`` when provided.  If the handler returns a
		non-``None`` value that value becomes the function's return value
		(useful for returning framework response objects instead of raising).

		The decorator transparently supports both regular and ``async`` callables.

		Args:
			endpoint:           Override the endpoint path for the gate lookup.
			method:             Override the HTTP method (defaults to the
			                    ``method`` attribute of the first request-like
			                    argument, or ``"GET"``).
			auth:               Static auth context merged into the gate check.
			auth_extractor:     Callable invoked with the same ``*args/**kwargs``
			                    as the decorated function; must return an auth
			                    dict or ``None``.
			on_block:           Handler for generic blocks and ``block_api_key``.
			on_mfa_required:    Handler for ``force_mfa`` controls.
			on_session_revoked: Handler for ``revoke_session`` /
			                    ``restrict_session`` controls.
			on_ip_blocked:      Handler for ``block_ip`` controls.
			on_rate_limited:    Handler for ``rate_limit`` controls.

		Example::

			gate = client.security_gate()

			# Basic: auto-extracts method + endpoint from the request object
			@gate.protect()
			async def transfer_funds(request: Request):
				...

			# Fine-grained: explicit config + per-control handlers
			@gate.protect(
				endpoint="/api/admin/reset",
				method="POST",
				on_mfa_required=lambda req, exc: JSONResponse(
					{"mfa_required": True, "reason": exc.reason}, status_code=401
				),
				on_ip_blocked=lambda req, exc: JSONResponse(
					{"detail": "Access denied"}, status_code=403
				),
			)
			async def admin_reset(request: Request):
				...
		"""
		def decorator(fn: Callable) -> Callable:
			# Register the decorated callable once immediately. If endpoint/method
			# are not explicitly provided, runtime resolution will register the
			# concrete binding on first call.
			self._register_protected_binding(fn, method=method, endpoint=endpoint)

			_handlers: Dict[str, Optional[Callable[..., Any]]] = {
				"force_mfa":        on_mfa_required,
				"revoke_session":   on_session_revoked,
				"restrict_session": on_session_revoked,
				"block_ip":         on_ip_blocked,
				"rate_limit":       on_rate_limited,
				"block_api_key":    on_block,
				"__default__":      on_block,
			}

			@wraps(fn)
			def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
				req_dict, resolved_auth, request_obj = self._resolve_protect_context(
					fn, args, kwargs, endpoint, method, auth, auth_extractor
				)
				self._register_protected_binding(
					fn,
					method=req_dict.get("method"),
					endpoint=req_dict.get("endpoint"),
				)

				if self._function_accepts_protector(fn, kwargs):
					protector = _ProtectIdentityRegistrar(
						gate=self,
						request_payload=req_dict,
						base_auth=resolved_auth,
						handlers=_handlers,
						request_obj=request_obj,
					)
					protected_kwargs = dict(kwargs)
					protected_kwargs["protector"] = protector
					result = fn(*args, **protected_kwargs)
					protector.ensure_checked()
					return result

				decision = self.inspect(request=req_dict, auth=resolved_auth)
				if decision.get("blocked"):
					request_args = (request_obj,) if request_obj is not None else args
					result = self._dispatch_control_exception(decision, request_args, _handlers)
					if result is not None:
						return result
				return fn(*args, **kwargs)

			@wraps(fn)
			async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
				req_dict, resolved_auth, request_obj = self._resolve_protect_context(
					fn, args, kwargs, endpoint, method, auth, auth_extractor
				)
				self._register_protected_binding(
					fn,
					method=req_dict.get("method"),
					endpoint=req_dict.get("endpoint"),
				)

				if self._function_accepts_protector(fn, kwargs):
					protector = _ProtectIdentityRegistrar(
						gate=self,
						request_payload=req_dict,
						base_auth=resolved_auth,
						handlers=_handlers,
						request_obj=request_obj,
					)
					protected_kwargs = dict(kwargs)
					protected_kwargs["protector"] = protector
					ret = fn(*args, **protected_kwargs)
					if inspect.isawaitable(ret):
						ret = await ret
					protector.ensure_checked()
					return ret

				decision = self.inspect(request=req_dict, auth=resolved_auth)
				if decision.get("blocked"):
					request_args = (request_obj,) if request_obj is not None else args
					result = self._dispatch_control_exception(decision, request_args, _handlers)
					if result is not None:
						if inspect.isawaitable(result):
							return await result
						return result
				ret = fn(*args, **kwargs)
				if inspect.isawaitable(ret):
					return await ret
				return ret

			if inspect.iscoroutinefunction(fn):
				return async_wrapper
			return sync_wrapper

		return decorator

	def _register_protected_binding(
		self,
		fn: Callable,
		method: Optional[str],
		endpoint: Optional[str],
	) -> None:
		"""Register a protected function/endpoint mapping once and sync it."""
		fn_name = fn.__qualname__
		self._registered_functions.setdefault(fn_name, fn)

		resolved_method = str(method or "GET").strip().upper() or "GET"
		resolved_endpoint = str(endpoint or "").strip()
		if not resolved_endpoint:
			resolved_endpoint = "/" + fn_name.replace(".", "/").replace(" ", "_")
		if not resolved_endpoint.startswith("/"):
			resolved_endpoint = f"/{resolved_endpoint}"

		binding_key = f"{fn_name}:{resolved_method}:{resolved_endpoint}"
		if binding_key in self._protected_bindings:
			return

		self._protected_bindings[binding_key] = {
			"function": fn_name,
			"module": fn.__module__,
			"method": resolved_method,
			"endpoint": resolved_endpoint,
		}
		self._sync_protected_registry()

	def _sync_protected_registry(self) -> None:
		"""Best-effort sync of protect() registry to backend for visibility."""
		try:
			self.client.send_event(
				event_type="protected_function_registry",
				payload={
					"functions": list(self._registered_functions.keys()),
					"bindings": list(self._protected_bindings.values()),
				},
			)
		except Exception as exc:
			secploy_logger.warning(f"Failed to sync protected function registry: {exc}")

	def _resolve_protect_context(
		self,
		fn: Callable,
		args: tuple,
		kwargs: Dict[str, Any],
		endpoint: Optional[str],
		method: Optional[str],
		explicit_auth: Optional[Dict[str, Any]],
		auth_extractor: Optional[Callable[..., Optional[Dict[str, Any]]]],
	) -> tuple[Dict[str, Any], Optional[Dict[str, Any]], Optional[Any]]:
		"""Build the ``(request_dict, auth_dict)`` pair consumed by ``inspect()``.

		Endpoint, method, headers, and cookies are auto-derived from the first
		request-like argument when not provided explicitly.
		"""
		request_obj = self._find_request_arg(fn, args, kwargs)

		resolved_endpoint = endpoint
		if not resolved_endpoint and request_obj is not None:
			resolved_endpoint = self._extract_request_url(request_obj) or None
		if not resolved_endpoint:
			resolved_endpoint = "/" + fn.__qualname__.replace(".", "/").replace(" ", "_")

		resolved_method = method
		if not resolved_method and request_obj is not None:
			resolved_method = str(getattr(request_obj, "method", None) or "").upper() or None
		resolved_method = resolved_method or "GET"

		req_dict: Dict[str, Any] = {
			"method": resolved_method,
			"endpoint": resolved_endpoint,
		}
		if request_obj is not None:
			req_dict["headers"] = self._coerce_headers(request_obj)
			req_dict["cookies"] = self._coerce_cookies(request_obj)

		# --- auth resolution ---
		resolved_auth: Optional[Dict[str, Any]] = None
		if auth_extractor is not None:
			try:
				resolved_auth = auth_extractor(*args, **kwargs)
			except Exception:
				pass
		if resolved_auth is None and explicit_auth:
			resolved_auth = dict(explicit_auth)
		if resolved_auth is None:
			auto_auth: Dict[str, Any] = {}
			for key in ("user_id", "session_id", "identity_key", "auth_provider",
			            "ip_address", "remote_addr"):
				val = kwargs.get(key)
				if val is not None:
					auto_auth[key] = str(val)
			if auto_auth:
				resolved_auth = auto_auth

		return req_dict, resolved_auth, request_obj

	def _function_accepts_protector(self, fn: Callable, kwargs: Dict[str, Any]) -> bool:
		"""Return True when ``protect`` should inject a ``protector`` argument."""
		try:
			sig = inspect.signature(fn)
		except (TypeError, ValueError):
			return False
		param = sig.parameters.get("protector")
		if param is None:
			return False
		if param.kind not in (
			inspect.Parameter.POSITIONAL_OR_KEYWORD,
			inspect.Parameter.KEYWORD_ONLY,
		):
			return False

		if "protector" not in kwargs:
			return True

		# Some frameworks pass defaulted kwargs explicitly. Allow injection when
		# the provided value is effectively "not set" by user code.
		provided = kwargs.get("protector")
		if provided is None:
			return True

		default = param.default
		if default is not inspect.Parameter.empty and provided is default:
			return True

		return False

	def _filter_controls_by_auth_scope(
		self,
		decision: SecurityGateDecision,
		auth_context: SecurityGateAuthContext,
	) -> SecurityGateDecision:
		"""Drop scoped controls that do not match the current request identity."""
		controls = decision.get("controls")
		if not isinstance(controls, list) or not controls:
			return decision

		matched_controls = [
			control for control in controls
			if isinstance(control, dict) and self._is_control_applicable(control, auth_context)
		]

		if not bool(decision.get("blocked")):
			return decision

		if matched_controls:
			if len(matched_controls) == len(controls):
				return decision
			filtered = dict(decision)
			filtered["controls"] = matched_controls
			return filtered

		# Only scoped controls were returned and none matched this caller.
		filtered = dict(decision)
		filtered["blocked"] = False
		filtered["allowed"] = True
		filtered["reason"] = "control_not_applicable"
		filtered["controls"] = []
		return filtered

	def _is_control_applicable(
		self,
		control: Mapping[str, Any],
		auth_context: SecurityGateAuthContext,
	) -> bool:
		target = str(control.get("target") or "").strip()
		if not target:
			return True

		action_type = str(control.get("action_type") or "").strip().lower()
		target_type = str(control.get("target_type") or "").strip().lower()
		normalized_target = target.lower()

		if action_type in {"block_identity", "allow_identity"} or target_type in {"identity", "user", "account"}:
			return normalized_target in {
				str(auth_context.get("identity_key") or "").strip().lower(),
				str(auth_context.get("user_id") or "").strip().lower(),
			}

		if action_type in {"block_ip", "allow_ip"} or target_type == "ip":
			return normalized_target in {
				str(auth_context.get("ip_address") or "").strip().lower(),
				str(auth_context.get("remote_addr") or "").strip().lower(),
			}

		if action_type in {"revoke_session", "restrict_session"} or target_type == "session":
			return normalized_target == str(auth_context.get("session_id") or "").strip().lower()

		if action_type == "block_api_key" or target_type == "api_key":
			return normalized_target == str(auth_context.get("api_key") or "").strip().lower()

		# For unknown control scopes, keep current behavior and allow backend decision.
		return True

	def _dispatch_control_exception(
		self,
		decision: SecurityGateDecision,
		args: tuple,
		handlers: Dict[str, Optional[Callable[..., Any]]],
	) -> Any:
		"""Raise the most-specific control exception or invoke a registered handler.

		Returns a non-``None`` value if a handler handled the block without
		raising; otherwise raises the exception so the call site propagates it.
		"""
		controls = decision.get("controls") or []
		action_types = [
			str(c.get("action_type") or "").lower()
			for c in controls if isinstance(c, dict)
		]

		priority = [
			"force_mfa",
			"revoke_session",
			"restrict_session",
			"block_ip",
			"rate_limit",
			"block_api_key",
		]
		matched = next((a for a in priority if a in action_types), "__default__")

		exc_class = self._CONTROL_TO_EXCEPTION.get(matched, SecurityGateBlocked)
		exc = exc_class(decision)  # type: ignore[call-arg]

		handler = handlers.get(matched) or handlers.get("__default__")
		if handler is not None:
			request_obj = next((a for a in args if self._looks_like_request(a)), None)
			result = self._invoke_blocked_handler(handler, request_obj, exc)
			if result is not None:
				return result

		raise exc

	def _find_request_arg(
		self,
		fn: Callable,
		args: tuple,
		kwargs: Dict[str, Any],
	) -> Optional[Any]:
		"""Return the first request-like object found in the function's arguments."""
		for key in ("request", "req"):
			val = kwargs.get(key)
			if val is not None and self._looks_like_request(val):
				return val

		try:
			sig = inspect.signature(fn)
			params = list(sig.parameters.values())
			for i, param in enumerate(params):
				if i >= len(args):
					break
				if param.name in ("request", "req") or self._looks_like_request(args[i]):
					return args[i]
		except (ValueError, TypeError):
			for arg in args:
				if self._looks_like_request(arg):
					return arg

		return None

	def _looks_like_request(self, obj: Any) -> bool:
		"""Heuristic: does *obj* resemble an HTTP request object?"""
		if obj is None or isinstance(obj, (str, int, float, bool, bytes, dict, list)):
			return False
		return (hasattr(obj, "method") and hasattr(obj, "url")) or (
			hasattr(obj, "method") and hasattr(obj, "path")
		)

	def _track_decision(self, decision: SecurityGateDecision) -> None:
		signal_context = self._extract_security_signals(decision)
		blocked = bool(decision.get("blocked", False))
		event_type = "warning" if blocked else "info"
		method = decision.get("method", "UNKNOWN")
		endpoint = decision.get("endpoint", "")
		auth = decision.get("auth") or {}
		message = self._build_gate_message(decision, signal_context)

		# Flatten identity/IP fields to top-level so the ingest security engine
		# can read them without traversing nested sub-dicts.
		context: Dict[str, Any] = {
			# Fields the ingest security engine reads by name
			"http_status": 403 if blocked else 200,
			"user_id": auth.get("user_id") or auth.get("identity_key") or "",
			"session_id": auth.get("session_id") or "",
			"auth_provider": auth.get("auth_provider") or "",
			"remote_addr": auth.get("remote_addr") or "",
			# Extra fields the engine scans in ctxMap for keyword matching
			"reason": decision.get("reason") or "",
			"secploy_signal": signal_context["primary_signal"],
			# Full gate detail for downstream processing
			"secploy_gate": {
				"blocked": blocked,
				"reason": decision.get("reason"),
				"rule": decision.get("rule") or {},
				"controls": decision.get("controls") or [],
				"signals": signal_context["signals"],
				"primary_signal": signal_context["primary_signal"],
			},
		}
		if auth:
			context["auth"] = auth
		if decision.get("metadata"):
			context["metadata"] = decision["metadata"]

		try:
			self.client.send_event(
				event_type,
				{
					"message": message,
					"method": method,
					"endpoint": endpoint,
					"secploy_signal": signal_context["primary_signal"],
					"secploy_signals": signal_context["signals"],
					"context": context,
				},
			)
		except Exception as exc:
			secploy_logger.warning(f"Secploy gate event tracking failed: {exc}")

	def _track_outbound_dependency_call(
		self,
		*,
		method: str,
		url: str,
		status_code: Optional[int],
		duration_ms: float,
		metadata: Optional[Dict[str, Any]] = None,
		error: Optional[Exception] = None,
	) -> None:
		parsed = urlsplit((url or "").strip())
		if not parsed.hostname:
			return

		context: Dict[str, Any] = {}
		if metadata:
			context["metadata"] = dict(metadata)

		try:
			self.client.track_external_service_request(
				method=method,
				url=url,
				status_code=status_code,
				duration_ms=duration_ms,
				context=context,
				error=error,
			)
		except Exception as exc:
			secploy_logger.warning(f"Failed to track outbound dependency call for {method} {url}: {exc}")

	def _build_gate_message(
		self,
		decision: SecurityGateDecision,
		signal_context: Dict[str, Any],
	) -> str:
		"""Build a message string that seeds the ingest security engine's keyword scanner."""
		blocked = bool(decision.get("blocked", False))
		method = decision.get("method", "UNKNOWN")
		endpoint = decision.get("endpoint", "")
		eplow = endpoint.lower()
		primary = signal_context["primary_signal"]
		action = "blocked" if blocked else "allowed"
		base = f"Secploy gate {action} {method} {endpoint}"

		hints: list[str] = []
		if primary == "bruteforce":
			hints.append("unauthorized credential attempt brute-force")
		elif primary == "fraud":
			hints.append("fraud payment_abuse transaction_abuse")
		elif primary == "anomaly":
			hints.append("anomalous suspicious unusual")
		elif blocked:
			# Derive a hint from the endpoint path so the ingest engine can
			# apply the right counter (auth-fail, endpoint-abuse, etc.).
			if any(p in eplow for p in self._AUTH_PATHS):
				hints.append("unauthorized forbidden credential")
			elif any(p in eplow for p in self._PAYMENT_PATHS):
				hints.append("fraud payment_abuse")
			elif any(p in eplow for p in self._ADMIN_PATHS):
				hints.append("forbidden privileged access blocked")
			else:
				hints.append("forbidden access blocked")

		reason = decision.get("reason") or ""
		if reason and reason not in ("allowed", "lookup_unavailable"):
			hints.append(reason.replace("_", " "))

		return base + (f" [{', '.join(hints)}]" if hints else "")

	def _extract_security_signals(self, decision: SecurityGateDecision) -> Dict[str, Any]:
		tokens = self._collect_security_signal_tokens(decision)
		text = " ".join(tokens)
		signals: list[str] = []
		blocked = bool(decision.get("blocked", False))
		eplow = (decision.get("endpoint") or "").lower()

		if any(keyword in text for keyword in (
			"bruteforce",
			"brute_force",
			"brute-force",
			"credential_stuff",
			"login_attempt",
			"failed_login",
			"password_spray",
		)):
			signals.append("bruteforce")

		# Endpoint path implies brute-force even when rule names don't say so
		if blocked and "bruteforce" not in signals:
			if any(p in eplow for p in self._AUTH_PATHS):
				signals.append("bruteforce")

		if any(keyword in text for keyword in (
			"fraud",
			"chargeback",
			"carding",
			"payment_abuse",
			"transaction_abuse",
		)):
			signals.append("fraud")

		# Endpoint path implies fraud when rule names don't say so
		if blocked and "fraud" not in signals:
			if any(p in eplow for p in self._PAYMENT_PATHS):
				signals.append("fraud")

		if any(keyword in text for keyword in (
			"anomaly",
			"anomalous",
			"suspicious",
			"unusual",
			"risk",
			"outlier",
		)):
			signals.append("anomaly")

		if any(keyword in text for keyword in (
			"rate_limit",
			"rate-limit",
			"throttle",
			"too_many_requests",
		)):
			signals.append("rate_limit_abuse")

		if any(keyword in text for keyword in (
			"recon",
			"probe",
			"scan",
			"discovery",
			"enumeration",
		)):
			signals.append("reconnaissance")

		if any(keyword in text for keyword in (
			"sql_injection",
			"sqli",
			"xss",
			"path_traversal",
			"rce",
			"command_injection",
			"privilege_escalation",
		)):
			signals.append("injection_attack")

		if not signals and blocked:
			signals.append("policy_block")

		if not signals:
			signals.append("allow")

		return {
			"signals": signals,
			"primary_signal": signals[0],
		}

	def _collect_security_signal_tokens(self, decision: SecurityGateDecision) -> list[str]:
		tokens: list[str] = []

		def append_token(value: Any) -> None:
			if value is None:
				return
			value_str = str(value).strip().lower()
			if value_str:
				tokens.append(value_str)

		append_token(decision.get("reason"))
		rule = decision.get("rule") if isinstance(decision.get("rule"), dict) else {}
		append_token(rule.get("reason"))
		append_token(rule.get("name"))
		append_token(rule.get("category"))
		append_token(rule.get("description"))

		controls = decision.get("controls") if isinstance(decision.get("controls"), list) else []
		for control in controls:
			if not isinstance(control, dict):
				continue
			append_token(control.get("action_type"))
			append_token(control.get("target_type"))
			append_token(control.get("target"))
			append_token(control.get("reason"))
			append_token(control.get("category"))

		# Also include the endpoint path so token-based classification can
		# use it without needing to look at the full decision object.
		append_token(decision.get("endpoint"))
		append_token(decision.get("url"))

		return tokens

	def _invoke_blocked_handler(
		self,
		blocked_handler: Optional[Callable[..., Any]],
		request: Any,
		exc: SecurityGateBlocked,
	) -> Any:
		if blocked_handler is None:
			return None
		try:
			return blocked_handler(request, exc)
		except TypeError:
			return blocked_handler(exc)

	def _blocked_response_body(self, exc: SecurityGateBlocked) -> Dict[str, Any]:
		control_summary = None
		if exc.action_type or exc.target:
			control_summary = {
				"action_type": exc.action_type,
				"target": exc.target,
			}

		payload: Dict[str, Any] = {
			"detail": "Blocked by Secploy",
			"message": str(exc),
			"reason": exc.reason,
			"rule": exc.rule,
			"controls": exc.controls,
		}
		if control_summary:
			payload["control_summary"] = control_summary
		return payload

	def _normalize_request(self, request: Any) -> Dict[str, Any]:
		if request is None:
			raise ValueError("request is required")

		if isinstance(request, Mapping):
			method = self._first_value(request, "method")
			raw_url = self._first_value(request, "url", "endpoint", "path")
			headers = self._coerce_mapping(request.get("headers"))
			cookies = self._coerce_mapping(request.get("cookies"))
		else:
			method = getattr(request, "method", None)
			raw_url = self._extract_request_url(request)
			headers = self._coerce_headers(request)
			cookies = self._coerce_cookies(request)

		normalized_method = str(method or "").strip().upper()
		normalized_endpoint = self._normalize_endpoint(raw_url)
		if not normalized_method or not normalized_endpoint:
			raise ValueError("request must provide method and url/path information")

		return {
			"method": normalized_method,
			"endpoint": normalized_endpoint,
			"url": raw_url,
			"headers": headers,
			"cookies": cookies,
		}

	def _resolve_auth_context(
		self,
		request: Any,
		headers: Mapping[str, Any],
		cookies: Mapping[str, Any],
		explicit_auth: Optional[Dict[str, Any]],
	) -> SecurityGateAuthContext:
		context: SecurityGateAuthContext = {}

		if explicit_auth:
			for key, value in explicit_auth.items():
				if value is not None:
					context[key] = value

		user = getattr(request, "user", None)
		if user is not None:
			if context.get("identity_key") is None:
				user_id = getattr(user, "id", None) or getattr(user, "pk", None)
				username = getattr(user, "username", None) or getattr(user, "email", None)
				identity_key = user_id or username
				if identity_key is not None:
					context["identity_key"] = str(identity_key)
			if context.get("user_id") is None:
				user_id = getattr(user, "id", None) or getattr(user, "pk", None)
				if user_id is not None:
					context["user_id"] = str(user_id)
			if context.get("username") is None:
				username = getattr(user, "username", None) or getattr(user, "email", None)
				if username is not None:
					context["username"] = str(username)
			if context.get("name") is None:
				full_name = getattr(user, "full_name", None)
				if not full_name and hasattr(user, "get_full_name"):
					try:
						full_name = user.get_full_name()
					except Exception:
						full_name = None
				if full_name:
					context["name"] = str(full_name)
			if context.get("email") is None:
				email = getattr(user, "email", None)
				if email is not None:
					context["email"] = str(email)

		session = getattr(request, "session", None)
		session_id = getattr(session, "session_key", None) or getattr(session, "sid", None)
		if session_id and context.get("session_id") is None:
			context["session_id"] = str(session_id)

		remote_addr = self._extract_remote_addr(request)
		if remote_addr and context.get("remote_addr") is None:
			context["remote_addr"] = remote_addr
		if remote_addr and context.get("ip_address") is None:
			context["ip_address"] = remote_addr

		header_map = {str(key).lower(): value for key, value in dict(headers).items()}
		header_identity = self._first_non_empty(
			header_map.get("x-identity-key"),
			header_map.get("x-user-id"),
			header_map.get("x-auth-user"),
		)
		if header_identity and context.get("identity_key") is None:
			context["identity_key"] = str(header_identity)
		if header_map.get("x-user-id") and context.get("user_id") is None:
			context["user_id"] = str(header_map["x-user-id"])
		if header_map.get("x-user-name") and context.get("name") is None:
			context["name"] = str(header_map["x-user-name"])
		if header_map.get("x-user-username") and context.get("username") is None:
			context["username"] = str(header_map["x-user-username"])
		if header_map.get("x-user-email") and context.get("email") is None:
			context["email"] = str(header_map["x-user-email"])

		header_session = self._first_non_empty(
			header_map.get("x-session-id"),
			header_map.get("x-request-session"),
		)
		if header_session and context.get("session_id") is None:
			context["session_id"] = str(header_session)

		header_ip = self._first_non_empty(
			header_map.get("x-forwarded-for"),
			header_map.get("x-real-ip"),
			header_map.get("cf-connecting-ip"),
		)
		if header_ip:
			normalized_ip = str(header_ip).split(",", 1)[0].strip()
			if normalized_ip and context.get("remote_addr") is None:
				context["remote_addr"] = normalized_ip
			if normalized_ip and context.get("ip_address") is None:
				context["ip_address"] = normalized_ip

		auth_header = header_map.get("authorization")
		if auth_header:
			scheme = str(auth_header).split(" ", 1)[0].strip().lower()
			if scheme and context.get("authorization_scheme") is None:
				context["authorization_scheme"] = scheme
			if context.get("auth_provider") is None and scheme:
				context["auth_provider"] = scheme

		if context.get("auth_provider") is None:
			provider = self._first_non_empty(
				header_map.get("x-auth-provider"),
				header_map.get("x-provider"),
			)
			if provider:
				context["auth_provider"] = str(provider)

		cookie_map = {str(key).lower(): value for key, value in dict(cookies).items()}
		cookie_session = self._first_non_empty(
			cookie_map.get("sessionid"),
			cookie_map.get("session"),
			cookie_map.get("sid"),
		)
		if cookie_session and context.get("session_id") is None:
			context["session_id"] = str(cookie_session)

		if context.get("ip_address") is None and context.get("remote_addr") is not None:
			context["ip_address"] = str(context.get("remote_addr"))
		if context.get("remote_addr") is None and context.get("ip_address") is not None:
			context["remote_addr"] = str(context.get("ip_address"))
		if context.get("identity_key") is None:
			context["identity_key"] = "anonymous"
		if context.get("ip_address") is None:
			context["ip_address"] = "unknown"
		if context.get("remote_addr") is None:
			context["remote_addr"] = str(context.get("ip_address") or "unknown")

		# The session identifier arrives from a cookie, a header or a framework
		# session object, and in every one of those cases it is a live
		# credential: whoever reads it out of an event store can replay it.
		#
		# Hashing here, at the one point every path converges on, keeps
		# everything the product actually needs. The value is stable, so a
		# session is still recognisable across events and across processes; it
		# is unique, so sessions stay distinct; and the gate hashes the incoming
		# request the same way, so a control targeting a session still matches.
		# What is lost is only the ability to reuse it, which nothing here
		# wanted.
		if context.get("session_id") is not None:
			context["session_id"] = hash_session_id(context["session_id"])

		return {key: value for key, value in context.items() if value not in (None, "")}

	def _extract_request_url(self, request: Any) -> str:
		url = getattr(request, "url", None)
		if url is not None:
			path = getattr(url, "path", None)
			if path:
				return str(path)
			return str(url)

		return str(
			self._first_non_empty(
				getattr(request, "path", None),
				getattr(request, "full_path", None),
				getattr(request, "endpoint", None),
			)
			or ""
		)

	def _extract_remote_addr(self, request: Any) -> Optional[str]:
		client = getattr(request, "client", None)
		if client is not None:
			host = getattr(client, "host", None)
			if host:
				return str(host)

		remote_addr = getattr(request, "remote_addr", None)
		if remote_addr:
			return str(remote_addr)

		meta = getattr(request, "META", None)
		if isinstance(meta, Mapping):
			forwarded = meta.get("HTTP_X_FORWARDED_FOR")
			if forwarded:
				return str(forwarded).split(",", 1)[0].strip()
			if meta.get("REMOTE_ADDR"):
				return str(meta["REMOTE_ADDR"])

		return None

	def _coerce_headers(self, request: Any) -> Dict[str, Any]:
		headers = getattr(request, "headers", None)
		if headers is not None:
			return self._coerce_mapping(headers)

		meta = getattr(request, "META", None)
		if isinstance(meta, Mapping):
			normalized_meta: Dict[str, Any] = {}
			for key, value in meta.items():
				key_str = str(key)
				if key_str.startswith("HTTP_"):
					header_name = key_str[5:].replace("_", "-").title()
					normalized_meta[header_name] = value
			return normalized_meta

		return {}

	def _coerce_cookies(self, request: Any) -> Dict[str, Any]:
		cookies = getattr(request, "cookies", None)
		if cookies is None:
			cookies = getattr(request, "COOKIES", None)
		return self._coerce_mapping(cookies)

	def _coerce_mapping(self, value: Any) -> Dict[str, Any]:
		if value is None:
			return {}
		if isinstance(value, Mapping):
			return dict(value)
		if isinstance(value, MutableMapping):
			return dict(value)
		try:
			return dict(value)
		except Exception:
			return {}

	def _normalize_endpoint(self, raw_url: Any) -> str:
		candidate = str(raw_url or "").strip()
		parsed = urlsplit(candidate)
		endpoint = parsed.path or candidate
		if endpoint and not endpoint.startswith("/"):
			endpoint = f"/{endpoint}"
		return endpoint

	def _first_value(self, mapping: Mapping[str, Any], *keys: str) -> Any:
		for key in keys:
			if key in mapping and mapping[key] is not None:
				return mapping[key]
		return None

	def _first_non_empty(self, *values: Any) -> Optional[Any]:
		for value in values:
			if value not in (None, ""):
				return value
		return None

	def _is_lookup_fallback(self, decision: Mapping[str, Any]) -> bool:
		reason = str(decision.get("reason") or "")
		if decision.get("blocked"):
			return False
		return reason.startswith(("lookup_", "missing_", "http_", "invalid_"))
