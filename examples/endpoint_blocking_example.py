"""Examples for endpoint decisions, automatic request gating, and the @gate.protect decorator.

The ``protect`` decorator enforces security controls from the Secploy backend
rule engine on individual endpoints or plain Python functions.  It raises a
specific exception type depending on the ``action_type`` returned in the gate
decision's ``controls`` list:

  force_mfa        -> MFARequiredException   (HTTP 401)
  revoke_session   -> SessionRevokedException (HTTP 401)
  restrict_session -> SessionRestrictedException (HTTP 403)
  block_ip         -> IPBlockedException      (HTTP 403)
  rate_limit       -> RateLimitedException    (HTTP 429)
  block_api_key    -> APIKeyBlockedException  (HTTP 401)
  (generic block)  -> SecurityGateBlocked     (HTTP 403)
"""

from secploy import (
    SecployClient,
    SecployGate,
    SecurityGateBlocked,
    MFARequiredException,
    SessionRevokedException,
    SessionRestrictedException,
    IPBlockedException,
    RateLimitedException,
    APIKeyBlockedException,
)

client = SecployClient()
gate = client.security_gate()


# ---------------------------------------------------------------------------
# 1. Basic protect — auto-extracts method + endpoint from the request object
# ---------------------------------------------------------------------------

@gate.protect()
async def get_profile(request):
    """FastAPI/Starlette endpoint protected with default settings."""
    return {"profile": "data"}


# ---------------------------------------------------------------------------
# 2. Explicit endpoint + method (useful when the path can't be auto-detected)
# ---------------------------------------------------------------------------

@gate.protect(endpoint="/api/transfer", method="POST")
async def transfer_funds(request):
    return {"status": "transferred"}


# ---------------------------------------------------------------------------
# 3. Force-MFA control — redirect to MFA challenge instead of raising
# ---------------------------------------------------------------------------

@gate.protect(
    endpoint="/api/admin/settings",
    method="POST",
    on_mfa_required=lambda req, exc: {
        "mfa_required": True,
        "reason": exc.reason,
        "redirect": "/mfa/verify",
    },
)
async def update_admin_settings(request):
    return {"updated": True}


# ---------------------------------------------------------------------------
# 4. Session blocking — graceful logout response on revocation
# ---------------------------------------------------------------------------

@gate.protect(
    on_session_revoked=lambda req, exc: {
        "detail": "Your session has been revoked. Please log in again.",
        "logout": True,
    },
)
async def dashboard(request):
    return {"data": "dashboard"}


# ---------------------------------------------------------------------------
# 5. IP restriction — return a 403 response body instead of raising
# ---------------------------------------------------------------------------

@gate.protect(
    on_ip_blocked=lambda req, exc: {
        "detail": "Access from your IP address is not permitted.",
        "reason": exc.reason,
    },
)
async def api_endpoint(request):
    return {"result": "ok"}


# ---------------------------------------------------------------------------
# 6. Rate limiting — surface Retry-After information
# ---------------------------------------------------------------------------

@gate.protect(
    on_rate_limited=lambda req, exc: {
        "detail": "Too many requests.",
        "retry_after": getattr(exc, "retry_after", None),
    },
)
async def high_volume_endpoint(request):
    return {"processed": True}


# ---------------------------------------------------------------------------
# 7. Full multi-control handler — handles all control types explicitly
# ---------------------------------------------------------------------------

@gate.protect(
    endpoint="/api/payment/charge",
    method="POST",
    on_mfa_required=lambda req, exc: {"mfa_required": True},
    on_session_revoked=lambda req, exc: {"session_expired": True},
    on_ip_blocked=lambda req, exc: {"ip_blocked": True},
    on_rate_limited=lambda req, exc: {"rate_limited": True, "retry_after": getattr(exc, "retry_after", None)},
    on_block=lambda req, exc: {"blocked": True, "reason": exc.reason},
)
async def charge_payment(request):
    return {"charged": True}


# ---------------------------------------------------------------------------
# 8. Protecting plain (non-HTTP) functions
#    endpoint/method are synthesised from the function's qualified name
# ---------------------------------------------------------------------------

@gate.protect()
def process_batch_job(job_id: str, user_id: str):
    """Regular function — gate uses method='GET', endpoint derived from qualname."""
    return f"processed {job_id}"


# ---------------------------------------------------------------------------
# 9. Using an auth_extractor to pass identity context to the gate
# ---------------------------------------------------------------------------

def extract_auth(request) -> dict:
    """Pull identity info from the request for gate evaluation."""
    user = getattr(request, "state", None)
    return {
        "user_id": str(getattr(user, "user_id", "") or ""),
        "session_id": str(getattr(request, "session_id", "") or ""),
        "remote_addr": str(getattr(request.client, "host", "") or "") if hasattr(request, "client") else "",
    }


@gate.protect(auth_extractor=extract_auth)
async def sensitive_action(request):
    return {"done": True}


# ---------------------------------------------------------------------------
# 10. Catching control-specific exceptions in calling code
# ---------------------------------------------------------------------------

async def call_with_exception_handling(request):
    try:
        return await transfer_funds(request)
    except MFARequiredException as exc:
        print(f"MFA required — reason: {exc.reason}")
    except SessionRevokedException as exc:
        print(f"Session revoked — log user out")
    except SessionRestrictedException as exc:
        print(f"Session restricted — limited access only")
    except IPBlockedException as exc:
        print(f"IP blocked — {exc.target}")
    except RateLimitedException as exc:
        print(f"Rate limited — retry after {exc.retry_after}s")
    except APIKeyBlockedException as exc:
        print(f"API key revoked")
    except SecurityGateBlocked as exc:
        print(f"Blocked: {exc.reason} (action={exc.action_type})")


# ---------------------------------------------------------------------------
# 11. Legacy: manual endpoint_blocked check (still supported)
# ---------------------------------------------------------------------------

if client.endpoint_blocked(method="DELETE", endpoint="/api/users/123"):
    print("Endpoint is blocked")
else:
    print("Endpoint is available")

    print(f"Decision: {exc.decision}")


# Example 5: Gate an outbound requests call automatically
try:
    response = secured_session.post(
        'POST',
        'https://api.example.com/api/critical-action',
        secploy_auth={'identity_key': 'user_123'},
        headers={'Authorization': 'Bearer token'},
        json={'action': 'rotate_key'},
    )
    print(f"Outbound response: {response.status_code}")
except SecurityGateBlocked as exc:
    print(f"Outbound request blocked: {exc}")
    print(f"Reason: {exc.reason}")
    print(f"Rule: {exc.rule}")
    print(f"Controls: {exc.controls}")


# Example 6: Framework installation helpers
# FastAPI:
# app.middleware('http')(secploy_gate.fastapi_middleware())
#
# Flask:
# app.before_request(secploy_gate.flask_before_request())
#
# Django:
# class SecployGateMiddleware:
#     def __init__(self, get_response):
#         self.middleware = secploy_gate.django_middleware(get_response)
#
#     def __call__(self, request):
#         return self.middleware(request)


# Example 7: Header-based project resolution
# The backend resolves the project from these SDK headers:
# - X-API-Key
# - X-Environment-Key
# - X-Organization-ID
#
# So endpoint_blocked does not need any explicit project identifier.

if client.endpoint_blocked(method='POST', endpoint='/api/critical-action'):
    print("Critical action is blocked")
else:
    print("Critical action is allowed")


# Example 8: Organization ID is automatically used
# The client is initialized with organization_id from config,
# so endpoint_blocked uses it internally without needing to pass it:

if client.endpoint_blocked(method='DELETE', endpoint='/api/settings'):
    print("Settings endpoint is blocked for this organization")

