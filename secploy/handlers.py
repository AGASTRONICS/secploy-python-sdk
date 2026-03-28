from __future__ import annotations

import inspect
from importlib import import_module
from typing import Callable
from typing import TYPE_CHECKING, Any, Dict, Mapping, MutableMapping, Optional
from urllib.parse import urlsplit

import requests

from .lib import secploy_logger
from .schemas import SecurityGateAuthContext, SecurityGateDecision

if TYPE_CHECKING:
	from .client import SecployClient


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
		return transport(method, url, **kwargs)

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
				# Try to get argument names and values
				try:
					sig = signature(fn)
					bound = sig.bind(*args, **kwargs)
					bound.apply_defaults()
					arg_map = dict(bound.arguments)
				except Exception:
					arg_map = {}
				payload = {
					"function": fn_name,
					"module": fn.__module__,
					"qualname": fn.__qualname__,
					"args": args,
					"kwargs": kwargs,
					"arg_map": arg_map,
					"result_type": type(result).__name__ if result is not None else None,
					"exception": exc_info,
					"duration": f"{duration:.6f}",
					"timestamp": start_time_iso,
					"context": {
						"type": "function_execution",
						"function": fn_name,
						"module": fn.__module__,
						"args": args,
						"kwargs": kwargs,
						"arg_map": arg_map,
						"duration": f"{duration:.6f}",
						"exception": exc_info,
					},
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

		session = getattr(request, "session", None)
		session_id = getattr(session, "session_key", None) or getattr(session, "sid", None)
		if session_id and context.get("session_id") is None:
			context["session_id"] = str(session_id)

		remote_addr = self._extract_remote_addr(request)
		if remote_addr and context.get("remote_addr") is None:
			context["remote_addr"] = remote_addr

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

		header_session = self._first_non_empty(
			header_map.get("x-session-id"),
			header_map.get("x-request-session"),
		)
		if header_session and context.get("session_id") is None:
			context["session_id"] = str(header_session)

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
