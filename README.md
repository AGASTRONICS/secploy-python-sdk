# Secploy Python SDK

[![PyPI version](https://img.shields.io/pypi/v/secploy.svg)](https://pypi.org/project/secploy/)
[![Python versions](https://img.shields.io/pypi/pyversions/secploy.svg)](https://pypi.org/project/secploy/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Secploy Python SDK provides event ingestion, structured log capture, runtime configuration sync, request gating, and security control actions for Python services.

## Table Of Contents

- [Secploy Python SDK](#secploy-python-sdk)
  - [Table Of Contents](#table-of-contents)
  - [Highlights](#highlights)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Function Monitoring \& Telemetry](#function-monitoring--telemetry)
    - [Usage](#usage)
    - [What Happens](#what-happens)
    - [Telemetry Fields](#telemetry-fields)
  - [Security Gate](#security-gate)
  - [Runnable Example](#runnable-example)
  - [CLI](#cli)
  - [Framework Examples](#framework-examples)
    - [FastAPI](#fastapi)
    - [Flask](#flask)
    - [Django](#django)
  - [Configuration](#configuration)
    - [Supported Keys](#supported-keys)
    - [Environment Variables](#environment-variables)
  - [Runtime Config Access](#runtime-config-access)
    - [Realtime Config Updates](#realtime-config-updates)
    - [Manual Polling (Optional)](#manual-polling-optional)
  - [Structured Log Capture](#structured-log-capture)
  - [Endpoint Blocking](#endpoint-blocking)
    - [Basic Usage](#basic-usage)
    - [Authentication](#authentication)
    - [Safe Defaults](#safe-defaults)
  - [Dependency Health Insights](#dependency-health-insights)
  - [API Surface](#api-surface)
    - [SecployClient](#secployclient)
    - [ConfigManager](#configmanager)
  - [Production Notes](#production-notes)
  - [Troubleshooting](#troubleshooting)
    - [Missing dependency errors](#missing-dependency-errors)
    - [Config sync authentication failure (`401`)](#config-sync-authentication-failure-401)
    - [YAML output fails in CLI sync](#yaml-output-fails-in-cli-sync)
  - [License](#license)

## Highlights

- Send application events to Secploy ingest.
- Capture Python logs and uncaught exceptions with structured context.
- Pull project configs from the Secploy API.
- Receive config updates through WebSocket with automatic 15-second polling fallback.
- Bootstrap project config and local `.env` files from CLI.

## Installation

Install from PyPI:

```bash
pip install secploy
```

Install with explicit realtime extra:

```bash
pip install "secploy[realtime]"
```

## Quick Start

Create a `.secploy` file in your project root:

```yaml
api_key: YOUR_API_KEY
environment_key: YOUR_ENVIRONMENT_KEY
organization_id: YOUR_ORGANIZATION_ID
environment: production
```

Use the SDK:

```python
from secploy import SecployClient

client = SecployClient()

client.send_event(
    "user.signup",
    {
        "user_id": "u_123",
        "plan": "pro",
        "source": "landing_page",
    },
)

# Dot-access project configs
google_api_key = client.env.google_api_key
var_a = client.env.var_a

# Graceful shutdown
client.stop()
```


## Function Monitoring & Telemetry

Secploy lets you monitor and control specific Python functions, emitting rich telemetry for every invocation. This enables security, audit, and analytics use cases.

### Usage

```python
from secploy import SecployGate

gate = SecployGate()

# Register and monitor a function
@gate.monitor
def protected_function(x, y):
        return x + y

protected_function(1, 2)  # Checked and tracked

# Or register dynamically
monitored = gate.register_function(lambda a, b: a * b)
monitored(3, 4)
```

### What Happens
- Before each function call, SecployGate checks security policy (can block or allow).
- After execution, a `function_execution` event is emitted with full telemetry.

### Telemetry Fields
Each function execution event includes:
- `function`: Qualified function name
- `module`: Module name
- `args`, `kwargs`: Arguments passed
- `arg_map`: Argument names and values
- `result_type`: Type of return value
- `exception`: Exception info (if any)
- `duration`: Execution time (seconds)
- `timestamp`: Start time
- `context`: All above, plus event type and extra context
- `message`: Human-readable summary

Example event payload:
```json
{
    "function": "my_module.protected_function",
    "module": "my_module",
    "args": [1, 2],
    "kwargs": {},
    "arg_map": {"x": 1, "y": 2},
    "result_type": "int",
    "exception": null,
    "duration": 0.0002,
    "timestamp": 1711640000.123,
    "context": {
        "type": "function_execution",
        "function": "my_module.protected_function",
        "module": "my_module",
        "args": [1, 2],
        "kwargs": {},
        "arg_map": {"x": 1, "y": 2},
        "duration": 0.0002,
        "exception": null
    },
    "message": "Function my_module.protected_function executed in 0.0002s"
}
```

You can use this for audit, analytics, or real-time security enforcement.

---

## Security Gate

If you want Secploy to evaluate requests before your application or HTTP client executes them, use `SecployGate`.

```python
from secploy import SecployGate, SecurityGateBlocked

secploy_gate = SecployGate()

request_data = {
    "method": "POST",
    "url": "https://api.example.com/api/billing/charge",
    "headers": {
        "Authorization": "Bearer token",
        "X-User-Id": "user_123",
        "X-Session-Id": "sess_456",
    },
}

try:
    request_data = secploy_gate(request=request_data)
    # Request is allowed.
except SecurityGateBlocked as exc:
    print(exc)
    print(exc.decision)
```

`SecployGate` accepts dictionaries plus common request objects from `requests`, Flask, Django, and FastAPI / Starlette.

You can also build it from an existing client:

```python
from secploy import SecployClient

client = SecployClient()
secploy_gate = client.security_gate()
```

To inspect the decision without raising, call `inspect(...)` or initialize the gate with `raise_on_block=False`.

To automatically protect outbound HTTP calls:

```python
response = secploy_gate.request(
    "POST",
    "https://api.example.com/api/billing/charge",
    headers={"Authorization": "Bearer token"},
    json={"amount": 2000},
)
```

If you prefer a reusable `requests`-style client with Secploy checks on every call:

```python
secured_session = client.security_session(
    auth={"auth_provider": "bearer"},
    metadata={"service": "billing-api"},
)

response = secured_session.post(
    "https://api.example.com/api/billing/charge",
    secploy_auth={"identity_key": "user_123"},
    json={"amount": 2000},
)
```

Outbound calls made through `secploy_gate.request(...)` or `client.security_session(...)`
also emit dependency telemetry automatically, including the destination host,
scheme, path, status code, and duration. Those events can be visualized in the
Secploy project graph as external service dependencies.

By default, `SecployClient` also instruments outbound calls from `requests`
automatically (without requiring `SecployGate`) so your project can discover
external dependencies from normal runtime traffic.

If your application uses `httpx` directly and you disabled auto instrumentation,
you can enable runtime instrumentation manually:

```python
client.enable_httpx_instrumentation()
```

You can also toggle `requests` instrumentation explicitly:

```python
client.enable_requests_instrumentation()
client.disable_requests_instrumentation()
```

To skip dependency telemetry for a specific outbound call, pass
`secploy_track_outbound=False`:

```python
requests.get("https://internal.example.com/health", secploy_track_outbound=False)
httpx.get("https://internal.example.com/health", secploy_track_outbound=False)
```

When blocked, `SecurityGateBlocked` now includes richer context:

- `exc.reason`
- `exc.rule`
- `exc.controls`
- `exc.action_type`
- `exc.target`

And framework helpers return structured block payloads including rule/control details by default.

To install it in frameworks:

```python
# FastAPI
app.middleware("http")(secploy_gate.fastapi_middleware())

# Flask
app.before_request(secploy_gate.flask_before_request())

# Django
class SecployGateMiddleware:
    def __init__(self, get_response):
        self._middleware = secploy_gate.django_middleware(get_response)

    def __call__(self, request):
        return self._middleware(request)
```

## Runnable Example

A complete runnable example is available at `examples/basic_usage.py`.

Security gate examples are available at:

- `examples/endpoint_blocking_example.py`
- `examples/fastapi_gate_example.py`
- `examples/flask_gate_example.py`
- `examples/django_gate_middleware.py`

Run it from the repository root:

```bash
python examples/basic_usage.py
```

Or set explicit config file path:

```bash
python examples/basic_usage.py --config-file .secploy
```

## CLI

The package installs a `secploy` command.

Initialize project config:

```bash
secploy init
```

Force overwrite existing file:

```bash
secploy init --force
```

Sync remote configs to local file:

```bash
secploy sync --configs
```

Default output is `.env` in `KEY="value"` format.

Common options:

```bash
secploy sync --configs --output .env.local
secploy sync --configs --format json --output configs.json
secploy sync --configs --format yaml --output configs.yaml
secploy sync --configs --config-file /path/to/.secploy
```

## Framework Examples

### FastAPI

```python
from fastapi import FastAPI, Request
from secploy import SecployClient

app = FastAPI()
client = SecployClient()


@app.middleware("http")
async def secploy_http_events(request: Request, call_next):
    response = await call_next(request)
    client.send_event(
        "http.request",
        {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
        },
    )
    return response
```

### Flask

```python
from flask import Flask, request
from secploy import SecployClient

app = Flask(__name__)
client = SecployClient()


@app.after_request
def secploy_http_events(response):
    client.send_event(
        "http.request",
        {
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
        },
    )
    return response
```

### Django

```python
from secploy import SecployClient

client = SecployClient()


class SecployEventMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        client.send_event(
            "http.request",
            {
                "method": request.method,
                "path": request.path,
                "status_code": response.status_code,
            },
        )
        return response
```

## Configuration

Configuration precedence (highest first):

1. Direct constructor arguments (`api_key`, `environment_key`, `organization_id`)
2. Environment variables (`SECPLOY_*`)
3. Config file (`.secploy`, `{project}.secploy`, or `*.secploy` discovered upward)
4. SDK defaults

### Supported Keys

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `api_key` | `str` | Required | Secploy API key |
| `environment_key` | `str` | Required | Environment key |
| `organization_id` | `str` | Required | Organization identifier |
| `environment` | `str` | `development` | Environment label |
| `ingest_url` | `str` | `https://ingest.secploy.com` | Ingest base URL |
| `api_url` | `str` | `https://api.secploy.com` | API base URL |
| `heartbeat_interval` | `int` | `60` | Heartbeat interval |
| `max_retry` | `int` | `5` | Event processor retry cap |
| `sampling_rate` | `float` | `1.0` | Event sampling |
| `log_level` | `str` | `INFO` | Logger level |
| `batch_size` | `int` | `100` | Max events per batch |
| `max_queue_size` | `int` | `10000` | Queue size limit |
| `flush_interval` | `int` | `5` | Batch flush interval (seconds) |
| `retry_attempts` | `int` | `3` | Retry attempts |
| `ignore_errors` | `bool` | `true` | Continue on non-critical issues |
| `debug` | `bool` | `false` | Enables SDK debug logging |
| `source_root` | `str` | `None` | Optional source root metadata |
| `realtime` | `bool` | `true` | Enable/disable realtime config stream |
| `instrument_outbound_requests` | `bool` | `true` | Auto-capture outbound `requests`/`httpx` telemetry |
| `instrument_httpx_async` | `bool` | `true` | Include `httpx.AsyncClient` instrumentation |

### Environment Variables

Use the `SECPLOY_` prefix with uppercased keys:

```bash
export SECPLOY_API_KEY=YOUR_API_KEY
export SECPLOY_ENVIRONMENT_KEY=YOUR_ENVIRONMENT_KEY
export SECPLOY_ORGANIZATION_ID=YOUR_ORGANIZATION_ID
export SECPLOY_ENVIRONMENT=production
export SECPLOY_DEBUG=false
```

## Runtime Config Access

`SecployClient` exposes a config manager at `client.configs`.

```python
client = SecployClient()

# Ergonomic dot-access (case-insensitive fallback)
google_api_key = client.env.google_api_key
var_a = client.env.var_a

# Lazy-fetch single value
api_token = client.configs.get("THIRD_PARTY_TOKEN")

# Get full snapshot
all_configs = client.configs.all()
```

For optional values, use:

```python
optional_value = client.env.get("missing_key", default="")
```

### Realtime Config Updates

By default, the client starts realtime config delivery from:

- `wss://<api-host>/ws/sdk/configs/` (derived from `api_url`)

Behavior:

- On websocket `config.update`, SDK refreshes config cache immediately.
- If websocket disconnects, SDK falls back to polling every 15 seconds.
- When websocket reconnects, polling fallback stops automatically.

Disable realtime in config:

```yaml
realtime: false
```

### Manual Polling (Optional)

```python
def on_change(key, old_value, new_value):
    print(f"Config changed: {key}: {old_value} -> {new_value}")


client.configs.start_refresh(interval=60, on_change=on_change)
# ...
client.configs.stop_refresh()
```

## Structured Log Capture

Capture root logger:

```python
client = SecployClient()
client.capture_logs()
```

Capture specific logger(s):

```python
client.capture_logs("my.service")
client.capture_logs(["uvicorn", "my.service"])
```

Stop capture:

```python
client.stop_capturing_logs("my.service")

# Stop all resources on shutdown
client.stop()
```

## Endpoint Blocking

Check if an endpoint is blocked before performing an action. This is useful for preventing actions on sensitive endpoints that have been administratively blocked.

### Basic Usage

```python
from secploy import SecployClient

client = SecployClient()

# Check if an endpoint is blocked
if client.endpoint_blocked(method='DELETE', endpoint='/api/users/123'):
    print("Cannot delete user - endpoint is blocked")
else:
    print("Safe to delete user")
```

### Authentication

No extra project identifier is required. The backend resolves the project from your SDK headers:

```yaml
api_key: YOUR_API_KEY
environment_key: YOUR_ENVIRONMENT_KEY
organization_id: YOUR_ORGANIZATION_ID
```

Then use the method without parameters:

```python
if client.endpoint_blocked(method='POST', endpoint='/api/billing/charge'):
    print("Billing endpoint is blocked")
```

### Safe Defaults

- Returns `False` if unable to determine block status (network error, missing config, etc.)
- Backend applies the blocked-endpoint rule matching for you
- All errors are logged but don't raise exceptions
- Uses your organization ID automatically from client configuration

## Dependency Health Insights

Secploy now does this automatically.

When `SecployClient()` starts, the SDK builds a dependency health report,
then sends it through ingest as a `dependency_health_report` event so it can
be shown in frontend dashboards without extra SDK code.

The SDK also polls for dependency scan requests created from the Secploy
platform. When an operator clicks scan in the dashboard, an integrated backend
can pick up that request automatically and emit a fresh report without adding
custom endpoint code.

This keeps usage simple: initialize once and Secploy handles the rest.

```python
from secploy import SecployClient

client = SecployClient()
# No manual dependency report call required.
```

If needed, you can disable automatic dependency reporting:

```yaml
auto_dependency_health_report: false
```

If needed, you can also disable remote scan request polling or adjust its
interval:

```yaml
remote_scan_requests: true
scan_request_poll_interval: 30
```

Frontend and backend teams can use the canonical event schema here:

- [Dependency Health Report Event Contract](docs/dependency-health-report-event.md)

## API Surface

### SecployClient

- `send_event(event_type: str, payload: dict) -> bool`
- `track_http_request(method: str, endpoint: str, status_code: int, message: str | None = None, context: dict | None = None) -> bool`
- `track_external_service_request(method: str, url: str, status_code: int | None = None, message: str | None = None, context: dict | None = None, duration_ms: float | None = None, error: Exception | None = None) -> bool`
- `track_error(error: Exception, endpoint: str | None = None, method: str | None = None, status_code: int = 500, context: dict | None = None) -> bool`
- `track_metric(name: str, value: int | float, unit: str | None = None, tags: dict | None = None, context: dict | None = None, message: str | None = None) -> bool`
- `endpoint_blocked(method: str, endpoint: str) -> bool`
  - Check if an endpoint is blocked before performing an action
    - Queries the Secploy API for a server-side blocked-endpoint decision
  - Returns `True` if blocked, `False` if not blocked or on error (safe default)
    - Uses the client's configured `api_key`, `environment_key`, and `organization_id` headers
- `submit_security_control_actions(actions: list[dict], timeout: int = 5) -> dict`
  - Submit one or more post-auth security control actions via API-key authenticated ingest endpoint
  - Returns created/executed action statuses from backend
- `submit_security_control_action(action_type: str, target_type: str, target: str, ..., timeout: int = 5) -> dict`
  - Convenience wrapper for sending a single control action
- `dependency_health_report(limit: int | None = None, include_current_issues: bool = True, include_latest_issues: bool = True, incidents_limit: int = 3, timeout: int = 8) -> dict`
    Returns dependency version drift plus issue and recent incident-like records from OSV.
- `emit_dependency_health_report(limit: int = 20, incidents_limit: int = 5, timeout: int = 8) -> bool`
    Sends dependency health report through ingest as a `dependency_health_report` event.
- `enable_requests_instrumentation() -> bool`
- `disable_requests_instrumentation() -> None`
- `enable_httpx_instrumentation(include_async: bool = True) -> bool`
- `disable_httpx_instrumentation() -> None`
- `capture_logs(loggers: str | list[str] | None = None) -> None`
- `stop_capturing_logs(loggers: str | list[str] | None = None) -> None`
- `start() -> None`
- `stop() -> None`
- `env` (dot-access config proxy)
- `configs` (`ConfigManager`)

### ConfigManager

- `fetch() -> dict[str, str]`
- `get(key: str, default: str | None = None) -> str | None`
- `all() -> dict[str, str]`
- `start_refresh(interval: int = 60, on_change: callable | None = None) -> None`
- `stop_refresh() -> None`
- `start_realtime(ws_url: str, headers_callback: callable) -> None`
- `stop_realtime() -> None`

## Production Notes

- Reuse one `SecployClient` instance per service process.
- Ensure `client.stop()` is called during graceful shutdown.
- Keep `api_url` and `ingest_url` aligned with your Secploy environment.
- For containerized apps, mount `.secploy` via secret management or use environment variables.

## Troubleshooting

### Missing dependency errors

```bash
pip install -U secploy
```

### Config sync authentication failure (`401`)

Verify these values in `.secploy`:

- `api_key`
- `environment_key`
- `organization_id`

### YAML output fails in CLI sync

```bash
pip install pyyaml
```

## License

MIT
