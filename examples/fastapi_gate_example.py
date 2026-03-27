"""FastAPI example: install Secploy gate middleware and outbound secured session."""

from fastapi import FastAPI, Request
from secploy import SecployClient, SecurityGateBlocked

app = FastAPI()
client = SecployClient()
secploy_gate = client.security_gate()
secured_session = client.security_session(
    auth={"auth_provider": "bearer"},
    metadata={"service": "fastapi-gate-example"},
)


@app.middleware("http")
async def security_gate_middleware(request: Request, call_next):
    return await secploy_gate.fastapi_middleware()(request, call_next)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/proxy")
async def proxy_route():
    """Example of gated outbound request."""
    try:
        response = secured_session.post(
            "https://api.example.com/internal/action",
            secploy_auth={"identity_key": "svc-fastapi"},
            json={"action": "ping"},
            timeout=5,
        )
        return {"status_code": response.status_code}
    except SecurityGateBlocked as exc:
        return {"blocked": True, "reason": exc.reason, "message": str(exc)}
