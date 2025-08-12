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
````

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

*(Ideal for background jobs, services, or scheduled tasks)*

```python
import time

while True:
    client.heartbeat()
    time.sleep(60)  # every minute
```

---

### 5️⃣ Listen for Live Status Updates

*(Requires WebSocket + Django Channels backend)*

```python
for status in client.listen_status():
    print(f"[STATUS UPDATE] Project is now {status}")
```

Possible statuses:

* `running`
* `idle`
* `shutdown`

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

* Python **3.8+**
* `requests`
* `websocket-client`

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

