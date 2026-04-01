import threading
import logging
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, List, Union
import queue
import requests
from urllib.parse import urlsplit

from secploy.lib.config import config_to_namespace

from .lib import setup_logger, load_config, DEFAULT_CONFIG, secploy_logger
from .schemas import (
    LogLevel,
    SecployConfig,
    SecurityControlActionRequest,
    SecurityGateDecision,
)
from .log_capture import SecployLogCapturer
from .events import EventHandler
from .processor import EventProcessor
from .config_manager import ConfigManager
from .system_metrics import SystemMetricsCollector

if TYPE_CHECKING:
    from .handlers import SecployGate, SecploySessionAdapter


class _EnvAccessor:
    """Ergonomic config accessor: client.env.MY_KEY or client.env.my_key."""

    def __init__(self, config_manager: ConfigManager):
        self._config_manager = config_manager

    def _lookup(self, key: str, default: Any = None) -> Any:
        # Support exact key plus common case variants.
        for candidate in (key, key.upper(), key.lower()):
            value = self._config_manager.get(candidate, None)
            if value is not None:
                return value
        return default

    def __getattr__(self, name: str) -> Any:
        value = self._lookup(name, None)
        if value is None:
            raise AttributeError(
                f"Config '{name}' was not found. "
                "Use client.env.get('KEY', default) for optional values."
            )
        return value

    def __getitem__(self, key: str) -> Any:
        value = self._lookup(key, None)
        if value is None:
            raise KeyError(key)
        return value

    def get(self, key: str, default: Any = None) -> Any:
        return self._lookup(key, default)

    def all(self) -> Dict[str, str]:
        return self._config_manager.all()

class SecployClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        environment_key: Optional[str] = None,
        organization_id: Optional[str] = None,
        config_file: Optional[str] = None,
        config: Optional[SecployConfig] = DEFAULT_CONFIG,
        log_levels: Optional[List[Union[str, int]]] = None
    ):
        """
        Initialize the Secploy client.

        Args:
            api_key: Optional API key to override configuration
            environment_key: Optional Environment key to override configuration
            organization_id: Optional Organization ID to override configuration
            config_file: Optional path to configuration file
            config: Configuration object, defaults to DEFAULT_CONFIG
        
        Raises:
            ValueError: If required configuration is missing
            TypeError: If configuration values have invalid types
        """
        # Load config from file if provided else it will load from default locations or find .secploy
        config_dict = load_config(config_file)
        config = config_to_namespace(config_dict)

        if config is None:
            secploy_logger.error("No valid configuration found")
            return
            
        # Override api_key if provided directly
        if api_key:
            config.api_key = api_key
        if environment_key:
            config.environment_key = environment_key
        if organization_id:
            config.organization_id = organization_id

        # Special handling for log_level if it's a string
        log_level = getattr(config, 'log_level', None)
        if isinstance(log_level, str):
            try:
                setattr(config, 'log_level', LogLevel(log_level.upper()))
            except ValueError:
                raise ValueError(
                    f"Invalid log level: {log_level}. Must be one of: "
                    f"{', '.join(level.value for level in LogLevel)}"
                )

        # Validate required fields
        if not getattr(config, 'api_key', None):
            raise ValueError("API key is required")
        if not getattr(config, 'environment_key', None):
            raise ValueError("Environment key is required")
        if not getattr(config, 'organization_id', None):
            raise ValueError("Organization ID is required")
        if not getattr(config, 'ingest_url', None):
            raise ValueError("Ingest URL is required")

        # Set instance attributes from config
        self.api_key = getattr(config, 'api_key')
        self.environment_key = getattr(config, 'environment_key', None)
        self.organization_id = getattr(config, 'organization_id', None)
        self.environment = getattr(config, 'environment', 'development')
        self.sampling_rate = getattr(config, 'sampling_rate', 1.0)
        self.ingest_url = getattr(config, 'ingest_url').rstrip("/")
        self.api_url = getattr(config, 'api_url', 'https://api.secploy.com').rstrip("/")
        self.heartbeat_interval = getattr(config, 'heartbeat_interval', 60)
        self.max_retry = getattr(config, 'max_retry', 5)
        self.debug = getattr(config, 'debug', False)
        self.log_level = getattr(config, 'log_level', 'INFO')
        self.realtime = getattr(config, 'realtime', True)  # set False to disable WS
        self.instrument_outbound_requests = bool(
            getattr(config, 'instrument_outbound_requests', True)
        )
        self.instrument_httpx_async = bool(getattr(config, 'instrument_httpx_async', True))

        # Batch processing configuration
        self.batch_size = getattr(config, 'batch_size', 100)  # Max events per batch
        self.flush_interval = getattr(config, 'flush_interval', 60)  # Max seconds between flushes

        # Initialize internal state
        self._event_queue = queue.Queue()
        self._event_handler = EventHandler(self._event_queue)
        
        # Initialize event processor
        self._event_processor = EventProcessor(
            queue=self._event_queue,
            ingest_url=self.ingest_url,
            headers_callback=self._headers,
            batch_size=self.batch_size,
            flush_interval=self.flush_interval,
            max_retry=self.max_retry
        )
        
        # Setup logging
        if self.debug:
            setup_logger(log_level=self.log_level)
        
        # Initialize log capturer
        self._log_capturer = SecployLogCapturer(self, levels=log_levels)

        # Config manager (env vars, secrets, feature flags)
        self.configs = ConfigManager(
            api_url=self.api_url,
            headers_callback=self._headers,
        )

        # Ergonomic config access, e.g. client.env.google_api_key
        self.env = _EnvAccessor(self.configs)

        # System resource metrics (CPU / memory / GPU)
        metrics_interval = getattr(config, 'metrics_interval', 10)
        self.metrics = SystemMetricsCollector(
            send_event=self.send_event,
            interval=metrics_interval,
        )

        # Optional runtime monkey patching for httpx clients.
        self._httpx_instrumented = False
        self._httpx_original_client_request = None
        self._httpx_original_async_client_request = None

        # Optional runtime monkey patching for requests clients.
        self._requests_instrumented = False
        self._requests_original_session_request = None

        self.start()
    
    def capture_logs(self, loggers: Union[str, List[str], None] = None):
        """
        Start capturing logs from specified loggers.
        
        Args:
            loggers: Logger name(s) to capture. Can be:
                    - None to capture the root logger
                    - A string for a single logger
                    - A list of logger names
        """
        self._log_capturer.start_capture(loggers)
        secploy_logger.info(f"Started capturing logs from {loggers or 'root'}")
        
    def stop_capturing_logs(self, loggers: Union[str, List[str], None] = None):
        """
        Stop capturing logs from specified loggers.
        
        Args:
            loggers: Logger name(s) to stop capturing
        """
        self._log_capturer.stop_capture(loggers)
        secploy_logger.info(f"Stopped capturing logs from {loggers or 'root'}")
    
    def _headers(self):
        return {
            "X-API-Key": f"{self.api_key}",
            "X-Environment-Key": f"{self.environment_key}",
            "X-Organization-ID": f"{self.organization_id}",
            "Content-Type": "application/json",
        }

    def send_event(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """
        Queue an event for sending. Events are batched and sent periodically.
        
        Args:
            event_type: Type of the event
            payload: Event payload data
        
        Returns:
            bool: True if event was queued successfully
        """
        return self._event_handler.send_event(event_type, payload)

    def track_http_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        message: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Track an HTTP request event with automatic type inference based on status code.
        For example, 404 becomes "warning" and 500 becomes "critical".
        """
        payload: Dict[str, Any] = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "message": message or f"{method} {endpoint} completed with {status_code}",
            "context": context or {},
        }
        return self.send_event("http_request", payload)

    def _classify_status_event_type(
        self,
        status_code: Optional[int] = None,
        *,
        errored: bool = False,
    ) -> str:
        if errored:
            return "warning"
        if status_code is None:
            return "info"
        if status_code >= 500:
            return "critical"
        if status_code >= 400:
            return "warning"
        return "info"

    def track_external_service_request(
        self,
        method: str,
        url: str,
        status_code: Optional[int] = None,
        message: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
        error: Optional[Exception] = None,
    ) -> bool:
        """
        Track an outbound dependency call made by the running service.
        """
        parsed = urlsplit((url or "").strip())
        hostname = parsed.hostname or ""
        if not hostname:
            return False
        if self._is_internal_secploy_url(url):
            return False

        host = parsed.netloc or hostname
        path = parsed.path or "/"
        merged_context: Dict[str, Any] = dict(context or {})
        merged_context.update(
            {
                "telemetry_kind": "external_service_request",
                "direction": "outbound",
                "external_service_host": host,
                "external_service_hostname": hostname,
                "external_service_scheme": parsed.scheme or "https",
                "external_service_path": path,
                "external_service_url": url,
            }
        )
        if parsed.port is not None:
            merged_context["external_service_port"] = parsed.port
        if parsed.query:
            merged_context["external_service_query"] = parsed.query
        if duration_ms is not None:
            merged_context["duration_ms"] = round(duration_ms, 2)
        if status_code is not None:
            merged_context["external_service_status_code"] = status_code
        if error is not None:
            merged_context["error_type"] = type(error).__name__
            merged_context["error_message"] = str(error)

        payload: Dict[str, Any] = {
            "name": hostname,
            "method": method,
            "message": message
            or (
                f"Outbound {method} {host}{path} failed"
                if error is not None
                else f"Outbound {method} {host}{path} completed"
            ),
            "context": merged_context,
        }
        if status_code is not None:
            payload["status_code"] = status_code

        event_type = self._classify_status_event_type(status_code, errored=error is not None)
        return self.send_event(event_type, payload)

    def _is_internal_secploy_url(self, url: str) -> bool:
        """
        Skip telemetry for Secploy control-plane traffic to avoid recursion/noise.
        """
        parsed = urlsplit((url or "").strip())
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False

        secploy_hosts = set()
        for candidate in (self.ingest_url, self.api_url):
            candidate_host = (urlsplit((candidate or "").strip()).hostname or "").lower()
            if candidate_host:
                secploy_hosts.add(candidate_host)

        if hostname in secploy_hosts:
            return True
        if hostname.endswith(".secploy.com") or hostname == "secploy.com":
            return True
        return False

    def enable_requests_instrumentation(self) -> bool:
        """
        Monkey patch requests.Session.request to auto-capture outbound host telemetry
        without requiring SecployGate wrappers.
        """
        if self._requests_instrumented:
            return True

        self._requests_original_session_request = requests.Session.request
        original_session_request = self._requests_original_session_request
        client_ref = self

        def _tracked_session_request(session, method, url, *args, **kwargs):
            should_track = bool(kwargs.pop("secploy_track_outbound", True))
            if not should_track:
                return original_session_request(session, method, url, *args, **kwargs)

            started_at = time.perf_counter()
            try:
                response = original_session_request(session, method, url, *args, **kwargs)
            except Exception as exc:
                client_ref.track_external_service_request(
                    method=str(method),
                    url=str(url),
                    status_code=None,
                    duration_ms=(time.perf_counter() - started_at) * 1000,
                    context={"transport": "requests"},
                    error=exc,
                )
                raise

            client_ref.track_external_service_request(
                method=str(method),
                url=str(url),
                status_code=getattr(response, "status_code", None),
                duration_ms=(time.perf_counter() - started_at) * 1000,
                context={"transport": "requests"},
            )
            return response

        requests.Session.request = _tracked_session_request
        self._requests_instrumented = True
        secploy_logger.info("Requests instrumentation enabled")
        return True

    def disable_requests_instrumentation(self) -> None:
        """Restore original requests Session.request if it was patched."""
        if not self._requests_instrumented:
            return
        if self._requests_original_session_request is not None:
            requests.Session.request = self._requests_original_session_request

        self._requests_instrumented = False
        self._requests_original_session_request = None
        secploy_logger.info("Requests instrumentation disabled")

    def enable_httpx_instrumentation(self, include_async: bool = True) -> bool:
        """
        Monkey patch httpx Client/AsyncClient request methods so outbound host
        telemetry is captured even when callers do not use security_session.

        Returns:
            bool: True if instrumentation is active, False when httpx is not installed.
        """
        if self._httpx_instrumented:
            return True

        try:
            import httpx  # noqa: PLC0415
        except Exception:
            secploy_logger.warning(
                "httpx is not installed; HTTPX instrumentation skipped. "
                "Install it with: pip install httpx"
            )
            return False

        self._httpx_original_client_request = httpx.Client.request
        client_request = self._httpx_original_client_request
        client_ref = self

        def _tracked_client_request(httpx_client, method, url, *args, **kwargs):
            should_track = bool(kwargs.pop("secploy_track_outbound", True))
            if not should_track:
                return client_request(httpx_client, method, url, *args, **kwargs)

            started_at = time.perf_counter()
            try:
                response = client_request(httpx_client, method, url, *args, **kwargs)
            except Exception as exc:
                client_ref.track_external_service_request(
                    method=str(method),
                    url=str(url),
                    status_code=None,
                    duration_ms=(time.perf_counter() - started_at) * 1000,
                    context={"transport": "httpx", "client_kind": "sync"},
                    error=exc,
                )
                raise

            client_ref.track_external_service_request(
                method=str(method),
                url=str(url),
                status_code=getattr(response, "status_code", None),
                duration_ms=(time.perf_counter() - started_at) * 1000,
                context={"transport": "httpx", "client_kind": "sync"},
            )
            return response

        httpx.Client.request = _tracked_client_request

        if include_async and hasattr(httpx, "AsyncClient"):
            self._httpx_original_async_client_request = httpx.AsyncClient.request
            async_client_request = self._httpx_original_async_client_request

            async def _tracked_async_client_request(httpx_client, method, url, *args, **kwargs):
                should_track = bool(kwargs.pop("secploy_track_outbound", True))
                if not should_track:
                    return await async_client_request(httpx_client, method, url, *args, **kwargs)

                started_at = time.perf_counter()
                try:
                    response = await async_client_request(httpx_client, method, url, *args, **kwargs)
                except Exception as exc:
                    client_ref.track_external_service_request(
                        method=str(method),
                        url=str(url),
                        status_code=None,
                        duration_ms=(time.perf_counter() - started_at) * 1000,
                        context={"transport": "httpx", "client_kind": "async"},
                        error=exc,
                    )
                    raise

                client_ref.track_external_service_request(
                    method=str(method),
                    url=str(url),
                    status_code=getattr(response, "status_code", None),
                    duration_ms=(time.perf_counter() - started_at) * 1000,
                    context={"transport": "httpx", "client_kind": "async"},
                )
                return response

            httpx.AsyncClient.request = _tracked_async_client_request

        self._httpx_instrumented = True
        secploy_logger.info("HTTPX instrumentation enabled")
        return True

    def disable_httpx_instrumentation(self) -> None:
        """Restore original httpx request methods if they were patched."""
        if not self._httpx_instrumented:
            return

        try:
            import httpx  # noqa: PLC0415
        except Exception:
            self._httpx_instrumented = False
            self._httpx_original_client_request = None
            self._httpx_original_async_client_request = None
            return

        if self._httpx_original_client_request is not None:
            httpx.Client.request = self._httpx_original_client_request
        if self._httpx_original_async_client_request is not None and hasattr(httpx, "AsyncClient"):
            httpx.AsyncClient.request = self._httpx_original_async_client_request

        self._httpx_instrumented = False
        self._httpx_original_client_request = None
        self._httpx_original_async_client_request = None
        secploy_logger.info("HTTPX instrumentation disabled")

    def track_error(
        self,
        error: Exception,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        status_code: int = 500,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Track an application error event with default critical/error semantics.
        """
        merged_context = dict(context or {})
        merged_context.setdefault("error_type", type(error).__name__)

        payload: Dict[str, Any] = {
            "message": str(error),
            "status_code": status_code,
            "context": merged_context,
        }
        if endpoint:
            payload["endpoint"] = endpoint
        if method:
            payload["method"] = method

        return self.send_event("error", payload)

    def track_metric(
        self,
        name: str,
        value: Union[int, float],
        unit: Optional[str] = None,
        tags: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
    ) -> bool:
        """
        Track a metric event with a normalized payload shape.
        """
        merged_context = dict(context or {})
        if tags is not None:
            merged_context["tags"] = tags
        if unit:
            merged_context["unit"] = unit

        payload: Dict[str, Any] = {
            "name": name,
            "value": value,
            "message": message or f"Metric {name}={value}",
            "context": merged_context,
        }
        return self.send_event("metric", payload)

    def _normalize_endpoint_reference(self, endpoint: str) -> str:
        raw_endpoint = (endpoint or "").strip()
        parsed_endpoint = urlsplit(raw_endpoint)
        normalized_endpoint = parsed_endpoint.path or raw_endpoint
        if normalized_endpoint and not normalized_endpoint.startswith("/"):
            normalized_endpoint = f"/{normalized_endpoint}"
        return normalized_endpoint

    def get_endpoint_decision(
        self,
        method: str,
        endpoint: str,
        timeout: int = 5,
    ) -> SecurityGateDecision:
        """
        Return the current Secploy decision for an endpoint.

        On lookup failures, this method fails open and returns an allowed decision.
        """
        normalized_method = (method or "").strip().upper()
        normalized_endpoint = self._normalize_endpoint_reference(endpoint)
        fallback_decision: SecurityGateDecision = {
            "allowed": True,
            "blocked": False,
            "method": normalized_method,
            "endpoint": normalized_endpoint,
            "url": endpoint,
            "reason": "lookup_unavailable",
            "rule": {},
            "controls": [],
            "raw": {},
        }

        try:
            if not normalized_method or not normalized_endpoint:
                secploy_logger.warning(
                    "Endpoint decision lookup skipped: method and endpoint are required."
                )
                fallback_decision["reason"] = "missing_method_or_endpoint"
                return fallback_decision

            url = f"{self.api_url}/projects/endpoints/blocked/check/"
            response = requests.get(
                url,
                headers=self._headers(),
                params={"method": normalized_method, "endpoint": normalized_endpoint},
                timeout=timeout,
            )

            if response.status_code < 200 or response.status_code >= 300:
                secploy_logger.warning(
                    f"Failed to fetch endpoint decision: {response.status_code}"
                )
                fallback_decision["reason"] = f"http_{response.status_code}"
                return fallback_decision

            try:
                payload = response.json()
                if not isinstance(payload, dict):
                    secploy_logger.warning("Unexpected response format for endpoint decision")
                    fallback_decision["reason"] = "invalid_response_payload"
                    return fallback_decision
            except Exception as e:
                secploy_logger.warning(f"Failed to parse endpoint decision response: {e}")
                fallback_decision["reason"] = "invalid_json"
                return fallback_decision

            blocked = bool(payload.get("blocked", False))
            rule = payload.get("rule") or {}
            controls = payload.get("controls") or payload.get("actions") or []
            reason = payload.get("reason") or rule.get("reason") or (
                "blocked_by_rule" if blocked else "allowed"
            )
            decision: SecurityGateDecision = {
                "allowed": not blocked,
                "blocked": blocked,
                "method": normalized_method,
                "endpoint": normalized_endpoint,
                "url": endpoint,
                "reason": str(reason),
                "rule": rule if isinstance(rule, dict) else {},
                "controls": controls if isinstance(controls, list) else [],
                "raw": payload,
            }
            if blocked:
                secploy_logger.debug(
                    f"Endpoint {normalized_method} {normalized_endpoint} is blocked by rule: "
                    f"{decision['reason']}"
                )
            return decision

        except requests.RequestException as e:
            secploy_logger.warning(f"Network error while fetching endpoint decision: {e}")
            return fallback_decision
        except Exception as e:
            secploy_logger.warning(f"Unexpected error in endpoint decision lookup: {e}")
            return fallback_decision

    def endpoint_blocked(
        self,
        method: str,
        endpoint: str,
    ) -> bool:
        """
        Check if an endpoint is blocked in a project before performing the action.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
            endpoint: The endpoint path/URL to check (e.g., "/api/users", "POST /api/data")
        
        Returns:
            bool: True if the endpoint is blocked, False if not blocked or if unable to determine.
                  Returns False on any API errors to allow requests to proceed safely.
        
        Example:
            if client.endpoint_blocked('DELETE', '/api/sensitive-endpoint'):
                print("Cannot perform action - endpoint is blocked")
            else:
                # Safe to proceed
                perform_action()
        """
        decision = self.get_endpoint_decision(method=method, endpoint=endpoint, timeout=5)
        return bool(decision.get("blocked", False))

    def security_gate(
        self,
        timeout: int = 5,
        fail_open: bool = True,
        raise_on_block: bool = True,
        track_decisions: bool = True,
    ) -> "SecployGate":
        """
        Create a callable gate that evaluates requests against Secploy endpoint decisions.
        """
        from .handlers import SecployGate

        return SecployGate(
            client=self,
            timeout=timeout,
            fail_open=fail_open,
            raise_on_block=raise_on_block,
            track_decisions=track_decisions,
        )

    def security_session(
        self,
        timeout: int = 5,
        fail_open: bool = True,
        raise_on_block: bool = True,
        track_decisions: bool = True,
        session: Optional[requests.Session] = None,
        auth: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "SecploySessionAdapter":
        """
        Create a requests-compatible session adapter protected by Secploy gate checks.
        """
        gate = self.security_gate(
            timeout=timeout,
            fail_open=fail_open,
            raise_on_block=raise_on_block,
            track_decisions=track_decisions,
        )
        return gate.session(session=session, auth=auth, metadata=metadata)

    def submit_security_control_actions(
        self,
        actions: List[SecurityControlActionRequest],
        timeout: int = 5,
    ) -> Dict[str, Any]:
        """
        Submit one or more security control actions to the API ingest endpoint.

        This endpoint is API-key authenticated and project-scoped by key.
        The backend may immediately execute actions and returns their statuses.

        Args:
            actions: List of control actions to submit.
            timeout: Request timeout in seconds.

        Returns:
            Parsed JSON response from the API.

        Raises:
            ValueError: If actions list is empty.
            requests.HTTPError: If API responds with an error status.
        """
        if not actions:
            raise ValueError("actions must contain at least one item")

        payload = {"actions": actions}
        url = f"{self.api_url}/projects/security/control-actions/"
        response = requests.post(
            url,
            headers=self._headers(),
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()

    def submit_security_control_action(
        self,
        action_type: str,
        target_type: str,
        target: str,
        reason: Optional[str] = None,
        identity_key: Optional[str] = None,
        session_id: Optional[str] = None,
        auth_provider: Optional[str] = None,
        risk_score: Optional[float] = None,
        expires_at: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        """
        Convenience wrapper for submitting a single security control action.
        """
        action: SecurityControlActionRequest = {
            "action_type": action_type,
            "target_type": target_type,
            "target": target,
        }
        if reason:
            action["reason"] = reason
        if identity_key:
            action["identity_key"] = identity_key
        if session_id:
            action["session_id"] = session_id
        if auth_provider:
            action["auth_provider"] = auth_provider
        if risk_score is not None:
            action["risk_score"] = risk_score
        if expires_at:
            action["expires_at"] = expires_at
        if metadata:
            action["metadata"] = metadata

        return self.submit_security_control_actions([action], timeout=timeout)

    def start(self):
        """Start the client's event processing and real-time config delivery."""
        secploy_logger.info("Starting Secploy client...")
        self._event_processor.start()
        self.metrics.start()

        if self.instrument_outbound_requests:
            self.enable_requests_instrumentation()
            self.enable_httpx_instrumentation(include_async=self.instrument_httpx_async)

        if self.realtime:
            ws_url = (
                self.api_url
                .replace("https://", "wss://")
                .replace("http://", "ws://")
            ) + "/ws/sdk/configs/"
            self.configs.start_realtime(ws_url, self._headers)

    def stop(self):
        """Stop the client and wait for processing to finish."""
        secploy_logger.info("Stopping Secploy client...")

        # Stop system metrics collection
        self.metrics.stop()

        # Stop real-time config delivery (WebSocket + polling fallback)
        self.configs.stop_realtime()

        # Stop config auto-refresh if running
        if self.configs.is_refreshing:
            self.configs.stop_refresh()

        # Stop all log capturing
        if hasattr(self, '_log_capturer'):
            self._log_capturer.stop_all()

        # Restore patched HTTPX transport hooks if they were enabled.
        self.disable_httpx_instrumentation()
        self.disable_requests_instrumentation()
        
        # Stop event processing
        self._event_processor.stop()
