import threading
import logging
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, List, Union, Tuple
import queue
import requests
from urllib.parse import urlsplit

from secploy.lib.config import config_to_namespace

from .lib import setup_logger, load_config, DEFAULT_CONFIG, secploy_logger
from .schemas import (
    DependencyScanRequest,
    DependencyHealthItem,
    DependencyHealthReport,
    DependencyHealthSummary,
    DependencyIssue,
    LogLevel,
    SecployConfig,
    SecurityControlActionRequest,
    SecurityGateDecision,
)
from .log_capture import SecployLogCapturer
from .errors import culprit_from, parse_exception
from .events import DEFAULT_MAX_QUEUE_SIZE, EventHandler
from .scrubbing import Scrubber
from .processor import EventProcessor
from .config_manager import ConfigManager
from .policy_cache import SecurityPolicyCache
from .identity_reporter import IdentityReporter
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
        # The version of the application being observed. Attached to every
        # error; without it an issue cannot say which build it first appeared
        # in, and "this regressed in 2.4.1" is unanswerable.
        self.release = getattr(config, 'release', None)
        self.ingest_url = getattr(config, 'ingest_url').rstrip("/")
        self.api_url = getattr(config, 'api_url', 'https://api.secploy.com').rstrip("/")
        self.max_retry = getattr(config, 'max_retry', 5)
        self.debug = getattr(config, 'debug', False)
        self.log_level = getattr(config, 'log_level', 'INFO')
        self.realtime = getattr(config, 'realtime', True)  # set False to disable WS
        self.instrument_outbound_requests = bool(
            getattr(config, 'instrument_outbound_requests', True)
        )
        self.instrument_httpx_async = bool(getattr(config, 'instrument_httpx_async', True))
        self.remote_scan_requests = bool(getattr(config, 'remote_scan_requests', True))
        self.scan_request_poll_interval = max(
            5,
            int(getattr(config, 'scan_request_poll_interval', 30) or 30),
        )
        self.auto_dependency_health_report = bool(
            getattr(config, 'auto_dependency_health_report', True)
        )

        # Batch processing configuration
        self.batch_size = getattr(config, 'batch_size', 100)  # Max events per batch
        self.flush_interval = getattr(config, 'flush_interval', 60)  # Max seconds between flushes

        # Initialize internal state
        # Bounded: see DEFAULT_MAX_QUEUE_SIZE. An unbounded queue here meant an
        # unreachable ingest grew the host application's memory until it died.
        self._event_queue = queue.Queue(
            maxsize=getattr(config, "max_queue_size", DEFAULT_MAX_QUEUE_SIZE)
        )
        # Credentials never leave the process. See scrubbing.py for what
        # counts as one and why identifiers deliberately do not.
        self._scrubber = Scrubber(
            deny_keys=getattr(config, "scrub_fields", None),
            enabled=bool(getattr(config, "scrub_enabled", True)),
        )
        self._event_handler = EventHandler(
            self._event_queue,
            scrubber=self._scrubber,
            before_send=getattr(config, "before_send", None),
            # Applied at last. It has been in the configuration - documented,
            # defaulted, validated - and never read, so a project that turned
            # its volume down was still sending all of it.
            sampling_rate=self.sampling_rate,
        )
        
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

        # Security policy cache backing the gate.
        #
        # "remote" keeps the historical per-request API lookup and stays the
        # default, so upgrading the SDK never changes enforcement on its own.
        # "shadow" proves the local cache agrees with the API on real traffic.
        # "cached" takes the network call off the request path entirely.
        gate_mode = str(getattr(config, 'gate_mode', 'remote') or 'remote').lower()
        if gate_mode not in ('remote', 'cached', 'shadow'):
            raise ValueError(
                f"Invalid gate_mode: {gate_mode!r}. "
                "Must be one of: remote, cached, shadow."
            )
        self.gate_mode = gate_mode
        self.security_policy = SecurityPolicyCache(
            api_url=self.api_url,
            headers_callback=self._headers,
            max_staleness=int(getattr(config, 'max_policy_staleness', 900) or 900),
        )

        # Identity telemetry. With the gate cached there is no per-request call
        # to carry identity to the API, so it is batched and deduplicated here.
        self.identities = IdentityReporter(
            api_url=self.api_url,
            headers_callback=self._headers,
            report_interval=int(getattr(config, 'identity_report_interval', 300) or 300),
            flush_interval=int(getattr(config, 'identity_flush_interval', 30) or 30),
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

        # Background polling for platform-triggered dependency scans.
        self._scan_request_thread: Optional[threading.Thread] = None
        self._scan_request_stop = threading.Event()

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

    def _report_error(
        self,
        parsed: Dict[str, Any],
        level: str = "error",
        mechanism: str = "manual",
        handled: bool = True,
        extra: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Send a parsed exception as an event.

        One builder for every path - a crash, a logged error, an explicit
        capture - so that the same failure reported three ways produces one
        issue rather than three.
        """
        try:
            context: Dict[str, Any] = {
                "exception_type": parsed.get("type"),
                "exception_value": parsed.get("value"),
                # Both shapes go out: structured frames for grouping and
                # display, the formatted strings so an ingest that predates
                # them still understands the event.
                "stacktrace": parsed.get("stacktrace") or [],
                "frames": parsed.get("frames") or [],
                # No culprit here on purpose. Each side owns what it actually
                # knows: the SDK knows which frames are the application's own,
                # because it is running inside it; the ingest owns how a module
                # path is normalised, because that rule has to be identical for
                # every event whatever sent it. Sending our own culprit as well
                # produced a field that quietly disagreed with the issue's.
                "environment": self.environment,
                "mechanism": mechanism,
                "handled": handled,
            }
            if self.release:
                context["release"] = self.release
            if extra:
                context.update(extra)

            return self.send_event(level, {
                "type": level,
                "message": f"{parsed.get('type')}: {parsed.get('value')}",
                "context": context,
            })
        except Exception as exc:
            # Reporting a failure must never become one.
            secploy_logger.error(f"Failed to build an error report: {exc}")
            return False

    def capture_exception(
        self,
        error: Any = None,
        level: str = "error",
        **context: Any,
    ) -> bool:
        """
        Report an exception that was caught and handled.

        Called with no argument inside an ``except`` block it picks up the
        exception being handled, which is the shape this is nearly always used
        in::

            try:
                charge(order)
            except PaymentError:
                client.capture_exception()
                raise
        """
        return self._report_error(
            parse_exception(error),
            level=level,
            mechanism="manual",
            handled=True,
            extra=context or None,
        )

    def capture_message(
        self,
        message: str,
        level: str = "info",
        **context: Any,
    ) -> bool:
        """
        Report a message with no exception behind it.

        The stack is captured from the caller so the event still says where it
        came from.
        """
        import traceback as _traceback

        try:
            frames = []
            stack = _traceback.extract_stack()[:-1]
            from .errors import _app_root, _is_vendor, _module_for

            root = _app_root()
            for summary in stack[-20:]:
                filename = summary.filename or ""
                frames.append({
                    "filename": filename,
                    "module": _module_for(filename, root),
                    "function": summary.name or "",
                    "lineno": summary.lineno,
                    "context_line": (summary.line or "").strip() or None,
                    "in_app": bool(filename) and not _is_vendor(filename),
                })
        except Exception:
            frames = []

        return self._report_error(
            {
                "type": "Message",
                "value": message,
                "frames": frames,
                "stacktrace": [message],
                "culprit": culprit_from(frames),
            },
            level=level,
            mechanism="manual",
            handled=True,
            extra=context or None,
        )

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

    def track_security_signal(
        self,
        event_type: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        risk_score: Optional[float] = None,
    ) -> bool:
        """
        Emit a named security/domain signal to the ingest pipeline.

        ``event_type`` must use a recognised namespace prefix:
        ``auth.``, ``fraud.``, ``payment.``, ``account.``, ``compliance.``,
        ``access.``, ``data.``, ``api.``, ``secret.``, ``security.``,
        ``incident.``, or ``dependency_scan.``
        """
        ctx: Dict[str, Any] = dict(context or {})
        if risk_score is not None:
            ctx["risk_score"] = risk_score
        payload: Dict[str, Any] = {"message": message, "context": ctx}
        if metadata:
            payload["metadata"] = metadata
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

    def _remote_endpoint_decision(
        self,
        method: str,
        endpoint: str,
        auth: Optional[Dict[str, Any]] = None,
        timeout: int = 5,
    ) -> SecurityGateDecision:
        """
        Ask the API for a decision. One network round trip per call.

        On lookup failures this fails open and returns an allowed decision.
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
            params = {
                "method": normalized_method,
                "endpoint": normalized_endpoint,
            }
            if auth:
                for key in (
                    "identity_key",
                    "user_id",
                    "session_id",
                    "auth_provider",
                    "ip_address",
                    "remote_addr",
                    "name",
                    "username",
                    "avatar",
                    "avater",
                    "email",
                    "is_authenticated",
                ):
                    value = auth.get(key)
                    if value not in (None, ""):
                        params[key] = value
            response = requests.get(
                url,
                headers=self._headers(),
                params=params,
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

            return self._decision_from_payload(
                payload, normalized_method, normalized_endpoint, endpoint
            )

        except requests.RequestException as e:
            secploy_logger.warning(f"Network error while fetching endpoint decision: {e}")
            return fallback_decision
        except Exception as e:
            secploy_logger.warning(f"Unexpected error in endpoint decision lookup: {e}")
            return fallback_decision

    def _decision_from_payload(
        self,
        payload: Dict[str, Any],
        normalized_method: str,
        normalized_endpoint: str,
        raw_endpoint: str,
    ) -> SecurityGateDecision:
        """
        Build a gate decision from a raw decision payload.

        Both the remote lookup and the local policy cache feed this one builder,
        so a cached decision is identical to the one the API would have returned.
        Any divergence would show up as a shadow-mode mismatch rather than
        silently changing what gets blocked.
        """
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
            "url": raw_endpoint,
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

    def _cached_endpoint_decision(
        self,
        method: str,
        endpoint: str,
        auth: Optional[Dict[str, Any]] = None,
    ) -> Optional[SecurityGateDecision]:
        """
        Decide from the in-process policy snapshot. No I/O.

        Returns None when no snapshot has loaded yet, so the caller can fall back
        to the network rather than guess at a policy it has not seen.
        """
        normalized_method = (method or "").strip().upper()
        normalized_endpoint = self._normalize_endpoint_reference(endpoint)
        if not normalized_method or not normalized_endpoint:
            return None

        try:
            payload = self.security_policy.evaluate(
                method=normalized_method,
                endpoint=normalized_endpoint,
                auth=auth,
                project_key=self.api_key,
                env_key=self.environment_key or "",
            )
        except Exception as exc:
            secploy_logger.warning(f"Local policy evaluation failed: {exc}")
            return None

        if payload is None:
            return None

        # The remote path reports identity as a side effect of its query string;
        # on this path nothing else would, so record it here. Deduplicated and
        # batched, so a repeat visitor costs a dict lookup and nothing more.
        try:
            self.identities.record(auth)
        except Exception as exc:
            secploy_logger.warning(f"Identity record failed: {exc}")

        return self._decision_from_payload(
            payload, normalized_method, normalized_endpoint, endpoint
        )

    @staticmethod
    def _decision_signature(decision: SecurityGateDecision) -> Tuple:
        """The parts of a decision that have to agree for the cache to be correct."""
        rule = decision.get("rule") or {}
        controls = decision.get("controls") or []
        return (
            bool(decision.get("blocked")),
            str(decision.get("reason") or ""),
            str(rule.get("id") or ""),
            tuple(sorted(str(c.get("id") or "") for c in controls if isinstance(c, dict))),
        )

    def _report_shadow_mismatch(
        self,
        local: SecurityGateDecision,
        remote: SecurityGateDecision,
        method: str,
        endpoint: str,
    ) -> None:
        local_sig = self._decision_signature(local)
        remote_sig = self._decision_signature(remote)
        secploy_logger.warning(
            f"Secploy gate shadow mismatch on {method} {endpoint}: "
            f"local={local_sig} remote={remote_sig}"
        )
        try:
            self.send_event(
                "secploy.gate.shadow_mismatch",
                {
                    "method": method,
                    "endpoint": endpoint,
                    "policy_version": self.security_policy.version,
                    "local": {
                        "blocked": local_sig[0],
                        "reason": local_sig[1],
                        "rule_id": local_sig[2],
                        "control_ids": list(local_sig[3]),
                    },
                    "remote": {
                        "blocked": remote_sig[0],
                        "reason": remote_sig[1],
                        "rule_id": remote_sig[2],
                        "control_ids": list(remote_sig[3]),
                    },
                },
            )
        except Exception as exc:
            secploy_logger.warning(f"Failed to report shadow mismatch: {exc}")

    def get_endpoint_decision(
        self,
        method: str,
        endpoint: str,
        auth: Optional[Dict[str, Any]] = None,
        timeout: int = 5,
    ) -> SecurityGateDecision:
        """
        Return the current Secploy decision for an endpoint.

        Behaviour depends on ``gate_mode``:

        ``remote``
            Ask the API on every call. The original behaviour, and still the
            default so upgrading the SDK changes nothing on its own.
        ``cached``
            Decide from the local policy snapshot, with no network call. Falls
            back to a remote lookup only while the first snapshot is still
            loading.
        ``shadow``
            Decide locally *and* remotely, report any disagreement, and return
            the remote decision. Run this in production to prove the cache
            agrees with the API before switching to ``cached``.

        On lookup failures this fails open and returns an allowed decision.
        """
        mode = self.gate_mode

        if mode == "cached":
            decision = self._cached_endpoint_decision(method, endpoint, auth)
            if decision is not None:
                return decision
            # No snapshot yet — usually the first request after start-up.
            secploy_logger.debug(
                "Security policy not loaded yet; falling back to a remote lookup."
            )
            return self._remote_endpoint_decision(method, endpoint, auth, timeout)

        if mode == "shadow":
            local = self._cached_endpoint_decision(method, endpoint, auth)
            remote = self._remote_endpoint_decision(method, endpoint, auth, timeout)
            if local is not None and remote.get("reason") != "lookup_unavailable":
                if self._decision_signature(local) != self._decision_signature(remote):
                    self._report_shadow_mismatch(local, remote, method, endpoint)
            # The API stays authoritative in shadow mode.
            return remote

        return self._remote_endpoint_decision(method, endpoint, auth, timeout)

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

    @staticmethod
    def register_identity(
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
    ) -> Dict[str, Any]:
        """Build a normalized identity context dict for gate auth parameters.

        This is a pythonic helper for apps that prefer explicit identity
        registration without depending on decorator-injected ``protector``.
        The returned dictionary can be passed to:
        - ``SecployGate.inspect(..., auth=...)``
        - ``SecployGate.request(..., auth=...)``
        - ``client.security_session(..., auth=...)`` / ``secploy_auth``.
        """
        identity_key = str(id).strip() if id is not None else ""
        if not identity_key:
            identity_key = "anonymous"

        auth_context: Dict[str, Any] = {
            "identity_key": identity_key,
        }

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

        return auth_context

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

    def fetch_dependency_scan_requests(self, timeout: int = 5) -> List[DependencyScanRequest]:
        """
        Poll for dependency scan requests issued from the Secploy platform.
        """
        url = f"{self.api_url}/projects/scans/requests/"
        response = requests.get(url, headers=self._headers(), timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        requests_list = payload.get("requests") if isinstance(payload, dict) else []
        return requests_list if isinstance(requests_list, list) else []

    def acknowledge_dependency_scan_request(
        self,
        request_id: str,
        succeeded: bool,
        detail: Optional[str] = None,
        error: Optional[str] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        """
        Acknowledge a dependency scan request after the SDK handles it.
        """
        payload: Dict[str, Any] = {"succeeded": succeeded}
        if detail:
            payload["detail"] = detail
        if error:
            payload["error"] = error

        url = f"{self.api_url}/projects/scans/requests/{request_id}/ack/"
        response = requests.post(url, headers=self._headers(), json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def _list_installed_dependencies(self) -> List[Tuple[str, str]]:
        """
        Return installed distributions as (name, version) pairs sorted by name.
        """
        try:
            from importlib import metadata as importlib_metadata  # noqa: PLC0415
        except Exception as exc:
            secploy_logger.warning(f"Unable to inspect installed dependencies: {exc}")
            return []

        discovered: Dict[str, str] = {}
        for dist in importlib_metadata.distributions():
            raw_name = dist.metadata.get("Name")
            version = dist.version
            if not raw_name or not version:
                continue
            normalized_name = str(raw_name).strip()
            if not normalized_name:
                continue
            discovered[normalized_name] = str(version).strip()

        return sorted(discovered.items(), key=lambda item: item[0].lower())

    def _is_outdated_version(self, current_version: str, latest_version: str) -> bool:
        """
        Compare versions with packaging when available, fallback to string compare.
        """
        if not latest_version:
            return False
        try:
            from packaging.version import Version  # noqa: PLC0415

            return Version(str(current_version)) < Version(str(latest_version))
        except Exception:
            return str(current_version) != str(latest_version)

    def _fetch_pypi_latest_version(
        self,
        package_name: str,
        timeout: int,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Fetch latest package version from PyPI.
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            response = requests.get(url, timeout=timeout)
        except requests.RequestException as exc:
            return None, f"network_error: {exc}"

        if response.status_code == 404:
            return None, "not_found_on_pypi"
        if response.status_code < 200 or response.status_code >= 300:
            return None, f"http_{response.status_code}"

        try:
            payload = response.json()
        except Exception:
            return None, "invalid_pypi_json"

        info = payload.get("info")
        if not isinstance(info, dict):
            return None, "invalid_pypi_payload"
        latest_version = info.get("version")
        if not isinstance(latest_version, str) or not latest_version.strip():
            return None, "missing_latest_version"
        return latest_version.strip(), None

    def _normalize_osv_issue(self, issue: Dict[str, Any]) -> DependencyIssue:
        return {
            "id": str(issue.get("id") or ""),
            "summary": str(issue.get("summary") or ""),
            "details": str(issue.get("details") or ""),
            "published": str(issue.get("published") or ""),
            "modified": str(issue.get("modified") or ""),
            "aliases": [str(alias) for alias in issue.get("aliases") or []],
            "severity": [
                severity
                for severity in (issue.get("severity") or [])
                if isinstance(severity, dict)
            ],
            "references": [
                reference
                for reference in (issue.get("references") or [])
                if isinstance(reference, dict)
            ],
        }

    def _fetch_osv_issues(
        self,
        package_name: str,
        version: str,
        timeout: int,
    ) -> Tuple[List[DependencyIssue], Optional[str]]:
        """
        Fetch OSV issues for a package version.
        """
        query = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI",
            },
            "version": version,
        }
        try:
            response = requests.post("https://api.osv.dev/v1/query", json=query, timeout=timeout)
        except requests.RequestException as exc:
            return [], f"network_error: {exc}"

        if response.status_code < 200 or response.status_code >= 300:
            return [], f"http_{response.status_code}"

        try:
            payload = response.json()
        except Exception:
            return [], "invalid_osv_json"

        raw_issues = payload.get("vulns") or []
        if not isinstance(raw_issues, list):
            return [], "invalid_osv_payload"

        normalized = [
            self._normalize_osv_issue(issue)
            for issue in raw_issues
            if isinstance(issue, dict)
        ]
        normalized.sort(
            key=lambda issue: (issue.get("modified") or issue.get("published") or ""),
            reverse=True,
        )
        return normalized, None

    def dependency_health_report(
        self,
        limit: Optional[int] = None,
        include_current_issues: bool = True,
        include_latest_issues: bool = True,
        incidents_limit: int = 3,
        timeout: int = 8,
    ) -> DependencyHealthReport:
        """
        Inspect installed dependencies and return version/issue health insight.

        The report includes:
        - installed version for each dependency
        - latest available version on PyPI
        - whether the dependency is outdated
        - issue counts (via OSV) for current and latest versions
        - recent issue records as incident-like entries
        """
        if limit is not None and limit < 1:
            raise ValueError("limit must be >= 1 when provided")
        if incidents_limit < 0:
            raise ValueError("incidents_limit must be >= 0")

        dependencies = self._list_installed_dependencies()
        if limit is not None:
            dependencies = dependencies[:limit]

        items: List[DependencyHealthItem] = []

        for package_name, current_version in dependencies:
            latest_version, latest_error = self._fetch_pypi_latest_version(
                package_name=package_name,
                timeout=timeout,
            )
            is_outdated = (
                self._is_outdated_version(current_version, latest_version)
                if latest_version
                else False
            )

            current_issues: List[DependencyIssue] = []
            latest_issues: List[DependencyIssue] = []

            if include_current_issues:
                current_issues, _ = self._fetch_osv_issues(
                    package_name=package_name,
                    version=current_version,
                    timeout=timeout,
                )
            if include_latest_issues and latest_version:
                latest_issues, _ = self._fetch_osv_issues(
                    package_name=package_name,
                    version=latest_version,
                    timeout=timeout,
                )

            merged_recent: List[DependencyIssue] = []
            seen_issue_ids = set()
            for issue in current_issues + latest_issues:
                issue_id = issue.get("id") or ""
                if issue_id in seen_issue_ids:
                    continue
                seen_issue_ids.add(issue_id)
                merged_recent.append(issue)

            merged_recent.sort(
                key=lambda issue: (issue.get("modified") or issue.get("published") or ""),
                reverse=True,
            )

            item: DependencyHealthItem = {
                "name": package_name,
                "current_version": current_version,
                "latest_version": latest_version,
                "is_outdated": is_outdated,
                "latest_check_error": latest_error,
                "has_current_issues": len(current_issues) > 0,
                "current_issue_count": len(current_issues),
                "has_latest_issues": len(latest_issues) > 0,
                "latest_issue_count": len(latest_issues),
                "recent_incidents": merged_recent[:incidents_limit],
            }
            items.append(item)

        summary: DependencyHealthSummary = {
            "total_dependencies": len(items),
            "outdated_dependencies": sum(1 for item in items if item.get("is_outdated")),
            "dependencies_with_current_issues": sum(
                1 for item in items if item.get("has_current_issues")
            ),
            "dependencies_with_latest_issues": sum(
                1 for item in items if item.get("has_latest_issues")
            ),
        }
        return {
            "summary": summary,
            "dependencies": items,
        }

    def emit_dependency_health_report(
        self,
        limit: int = 20,
        incidents_limit: int = 5,
        timeout: int = 8,
    ) -> bool:
        """
        Build dependency health insights and send them through ingest as an event.

        This keeps frontend visibility aligned with the same ingest/event pipeline.
        """
        try:
            report = self.dependency_health_report(
                limit=limit,
                incidents_limit=incidents_limit,
                include_current_issues=True,
                include_latest_issues=True,
                timeout=timeout,
            )
            payload: Dict[str, Any] = {
                "name": "dependency_health_report",
                "message": "Dependency health report generated",
                "context": {
                    "type": "dependency_health_report",
                    "source": "secploy-python-sdk",
                    "summary": report.get("summary", {}),
                    "dependencies": report.get("dependencies", []),
                },
            }
            return self.send_event("dependency_health_report", payload)
        except Exception as exc:
            secploy_logger.warning(f"Failed to emit dependency health report: {exc}")
            return False

    def _emit_dependency_health_report_async(self) -> None:
        """Emit dependency report in background so startup stays responsive."""

        def _worker() -> None:
            # Small delay gives app startup and event processor time to settle.
            time.sleep(1.0)
            self.emit_dependency_health_report()

        threading.Thread(
            target=_worker,
            daemon=True,
            name="secploy-dependency-health-report",
        ).start()

    def _start_dependency_scan_request_polling(self) -> None:
        if self._scan_request_thread is not None and self._scan_request_thread.is_alive():
            return

        self._scan_request_stop.clear()

        def _worker() -> None:
            while not self._scan_request_stop.wait(timeout=self.scan_request_poll_interval):
                try:
                    requests_to_process = self.fetch_dependency_scan_requests(timeout=5)
                except Exception as exc:
                    secploy_logger.warning(f"Dependency scan request poll failed: {exc}")
                    continue

                for request in requests_to_process:
                    request_id = request.get("request_id")
                    if not request_id:
                        continue

                    try:
                        emitted = self.emit_dependency_health_report()
                        if not emitted:
                            raise RuntimeError("SDK failed to emit dependency health report")

                        self.acknowledge_dependency_scan_request(
                            request_id=request_id,
                            succeeded=True,
                            detail="Dependency health report emitted by SDK.",
                            timeout=5,
                        )
                    except Exception as exc:
                        secploy_logger.warning(f"Dependency scan request handling failed: {exc}")
                        try:
                            self.acknowledge_dependency_scan_request(
                                request_id=request_id,
                                succeeded=False,
                                error=str(exc),
                                timeout=5,
                            )
                        except Exception as ack_exc:
                            secploy_logger.warning(f"Dependency scan request acknowledgement failed: {ack_exc}")

        self._scan_request_thread = threading.Thread(
            target=_worker,
            daemon=True,
            name="secploy-scan-request-poll",
        )
        self._scan_request_thread.start()

    def _stop_dependency_scan_request_polling(self) -> None:
        self._scan_request_stop.set()
        if self._scan_request_thread is not None:
            self._scan_request_thread.join(timeout=3)
            self._scan_request_thread = None

    def start(self):
        """Start the client's event processing and real-time config delivery."""
        secploy_logger.info("Starting Secploy client...")
        self._event_processor.start()
        self.metrics.start()

        if self.instrument_outbound_requests:
            self.enable_requests_instrumentation()
            self.enable_httpx_instrumentation(include_async=self.instrument_httpx_async)

        if self.auto_dependency_health_report:
            self._emit_dependency_health_report_async()

        if self.remote_scan_requests:
            self._start_dependency_scan_request_polling()

        if self.gate_mode != 'remote':
            self._start_security_policy()
            self.identities.start()

        if self.realtime:
            ws_url = (
                self.api_url
                .replace("https://", "wss://")
                .replace("http://", "ws://")
            ) + "/ws/sdk/configs/"
            self.configs.start_realtime(ws_url, self._headers)

    def _start_security_policy(self) -> None:
        """
        Load the policy snapshot and subscribe to changes.

        The first fetch runs on a background thread so importing and starting the
        SDK never blocks the host application on a network call. Until it lands,
        the gate falls back to a remote lookup, so requests are decided correctly
        from the very first one rather than being waved through.
        """
        def _bootstrap():
            try:
                self.security_policy.fetch()
            except Exception as exc:
                secploy_logger.warning(f"Initial security policy fetch failed: {exc}")

            if not self.realtime:
                return
            ws_url = (
                self.api_url
                .replace("https://", "wss://")
                .replace("http://", "ws://")
            ) + "/ws/sdk/security/"
            try:
                self.security_policy.start_realtime(ws_url, self._headers)
            except Exception as exc:
                secploy_logger.warning(f"Security policy real-time failed to start: {exc}")

        threading.Thread(
            target=_bootstrap,
            daemon=True,
            name="secploy-security-bootstrap",
        ).start()

    def stop(self):
        """Stop the client and wait for processing to finish."""
        secploy_logger.info("Stopping Secploy client...")

        # Stop system metrics collection
        self.metrics.stop()

        # Stop real-time config delivery (WebSocket + polling fallback)
        self.configs.stop_realtime()

        # Stop security policy delivery
        self.security_policy.stop_realtime()

        # Flush any identity records still pending
        self.identities.stop()

        # Stop dependency scan request polling.
        self._stop_dependency_scan_request_polling()

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
