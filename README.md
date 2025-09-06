<p align="center">
  <img src="https://secploy.vercel.app/logo.png" alt="Secploy Logo" width="180">
</p>

<h1 align="center">Secploy Python SDK</h1>

<p align="center">
  <em>Event tracking, heartbeat monitoring, and real-time status updates for your apps — powered by Secploy.</em>
</p>

---

## 📌 Overview

**Secploy** is a modern **security monitoring and observability platform** that helps you track **events, uptime, and live statuses** in real time.

## ⚙️ Configuration

The Secploy SDK can be configured in multiple ways, providing flexibility for different environments and use cases.

### Configuration Methods (in order of precedence)

1. **Direct initialization parameters**

   ```python
    client = SecployClient()

    config = SecployConfig(
        api_key="your-key",
        environment="production",
        log_level=LogLevel.INFO,
        batch_size=100
    )

    client = SecployClient(config=config)
    ```

2. **Configuration file** (.secploy or project-name.secploy)

```yaml
api_key: your-api-key
environment: production
debug: true
````

3. **Environment variables**
   ```bash
   export SECPLOY_API_KEY=your-api-key
   export SECPLOY_ENVIRONMENT=production
   export SECPLOY_DEBUG=true
   ```

### Configuration Options

| Option               | Type             | Default                     | Description                                           |
| -------------------- | ---------------- | --------------------------- | ----------------------------------------------------- |
| `api_key`            | `str`            | Required                    | Your Secploy project API key                          |
| `environment`        | `str`            | `"development"`             | Environment name (e.g., production, staging)          |
| `ingest_url`         | `str`            | `"https://api.secploy.com"` | Secploy API endpoint                                  |
| `heartbeat_interval` | `int`            | `30`                        | Seconds between heartbeat signals                     |
| `max_retry`          | `int`            | `3`                         | Maximum retry attempts for failed requests            |
| `debug`              | `bool`           | `false`                     | Enable debug logging                                  |
| `sampling_rate`      | `float`          | `1.0`                       | Event sampling rate (0.0 to 1.0)                      |
| `log_level`          | `LogLevel`/`str` | `"INFO"`                    | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `batch_size`         | `int`            | `100`                       | Maximum events per batch                              |
| `max_queue_size`     | `int`            | `10000`                     | Maximum events in queue before dropping               |
| `flush_interval`     | `int`            | `60`                        | Maximum seconds between event batch flushes           |
| `retry_attempts`     | `int`            | `3`                         | Number of retry attempts for failed events            |
| `ignore_errors`      | `bool`           | `false`                     | Continue on non-critical errors                       |
| `source_root`        | `str`            | `None`                      | Root directory for source file paths                  |

### Configuration File Example

Create a `.secploy` file in your project root:

```yaml
# Required settings
api_key: your-api-key
environment: production

# Event batching
batch_size: 100
flush_interval: 30
max_queue_size: 5000

# Performance
sampling_rate: 0.1 # Sample 10% of events
max_retry: 3
retry_attempts: 2

# Debugging
debug: false
log_level: INFO
ignore_errors: false

# Advanced
source_root: /app
heartbeat_interval: 60
ingest_url: https://api.secploy.com
```

### Environment Variables

All configuration options can be set via environment variables with the `SECPLOY_` prefix:

```bash
# Required settings
SECPLOY_API_KEY=your-api-key
SECPLOY_ENVIRONMENT=production

# Event batching
SECPLOY_BATCH_SIZE=100
SECPLOY_FLUSH_INTERVAL=30
SECPLOY_MAX_QUEUE_SIZE=5000

# Performance
SECPLOY_SAMPLING_RATE=0.1
SECPLOY_MAX_RETRY=3
SECPLOY_RETRY_ATTEMPTS=2

# Debugging
SECPLOY_DEBUG=false
SECPLOY_LOG_LEVEL=INFO
SECPLOY_IGNORE_ERRORS=false

# Advanced
SECPLOY_SOURCE_ROOT=/app
SECPLOY_HEARTBEAT_INTERVAL=60
SECPLOY_INGEST_URL=https://api.secploy.com
```

With the **Secploy Python SDK**, you can:

- ✅ Send **events** from your Python applications or microservices.
- 💓 Monitor uptime & availability using **heartbeats**.
- 📊 Attach **environment** and **project metadata** automatically.
- 📡 Receive **live project statuses** in your Secploy dashboard (`Running`, `Idle`, `Shutdown`).

---

## 🚀 Installation

Install directly from **PyPI**:

```bash
pip install secploy
```

Or from source:

```bash
git clone https://github.com/your-org/secploy-python-sdk.git
cd secploy-python-sdk
pip install .
```

---

## ⚡ Quick Start

### 1️⃣ Initialize the Client

```python
from secploy import SecployClient

client = SecployClient(
    api_key="your_project_api_key",
    environment="production"
)
```

---

### 2️⃣ Send Events

```python
client.track_event(
    name="user_signup",
    properties={
        "user_id": 101,
        "plan": "pro",
        "referral": "campaign_2025"
    }
)
```

---

### 3️⃣ Report an Incident

```python
incident = client.create_incident(
    title="High Error Rate",
    description="API error rate exceeded 5% in the EU region.",
    severity="critical"
)
print("Incident ID:", incident.id)
```

---

### 4️⃣ Monitor Heartbeats

_(Ideal for background jobs, services, or scheduled tasks)_

```python
import time

while True:
    client.heartbeat()
    time.sleep(60)  # every minute
```

---

### 5️⃣ Listen for Live Status Updates

_(Requires WebSocket + Django Channels backend)_

```python
for status in client.listen_status():
    print(f"[STATUS UPDATE] Project is now {status}")
```

Possible statuses:

- `running`
- `idle`
- `shutdown`

---

## 📌 Environments

When you create a project in Secploy, multiple environments are automatically created:

| Environment   | Purpose                |
| ------------- | ---------------------- |
| `production`  | Live, customer-facing  |
| `staging`     | Pre-production testing |
| `development` | Local development      |

Each environment has its own **API key** — use the matching key for the environment you’re sending data from.

---

## 📡 SDK Methods

| Method                                          | Description                    |
| ----------------------------------------------- | ------------------------------ |
| `track_event(name, properties)`                 | Send a structured event        |
| `create_incident(title, description, severity)` | Create a new incident          |
| `heartbeat()`                                   | Send a heartbeat signal        |
| `listen_status()`                               | Stream live project status     |
| `set_environment(env_code)`                     | Switch environment dynamically |

---

## 🛡 Requirements

- Python **3.8+**
- `requests`
- `websocket-client`

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch:

   ```bash
   git checkout -b feature/my-feature
   ```

3. Commit your changes:

   ```bash
   git commit -m "Add my feature"
   ```

4. Push to the branch and open a Pull Request

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.
