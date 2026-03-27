"""Flask example: install Secploy gate before_request hook and outbound secured session."""

from flask import Flask, jsonify
from secploy import SecployClient, SecurityGateBlocked

app = Flask(__name__)
client = SecployClient()
secploy_gate = client.security_gate()
secured_session = client.security_session(
    auth={"auth_provider": "session"},
    metadata={"service": "flask-gate-example"},
)


@app.before_request
def secploy_security_gate():
    return secploy_gate.flask_before_request()()


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.post("/proxy")
def proxy_route():
    try:
        response = secured_session.post(
            "https://api.example.com/internal/action",
            secploy_auth={"identity_key": "svc-flask"},
            json={"action": "ping"},
            timeout=5,
        )
        return jsonify({"status_code": response.status_code})
    except SecurityGateBlocked as exc:
        return jsonify({"blocked": True, "reason": exc.reason, "message": str(exc)}), 403
