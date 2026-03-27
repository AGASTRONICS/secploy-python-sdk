"""Examples for endpoint decisions and automatic request gating."""

from secploy import SecployClient, SecployGate, SecurityGateBlocked

# Initialize the client (credentials from config file or environment variables)
client = SecployClient()

# Example 1: Check if an endpoint is blocked before making a request
if client.endpoint_blocked(method='DELETE', endpoint='/api/users/123'):
    print("❌ Cannot delete user - endpoint is blocked")
    # Handle the blocked endpoint (log, alert, etc.)
else:
    print("✅ Endpoint is not blocked - safe to proceed")
    # Proceed with the delete request
    # response = requests.delete("https://api.example.com/api/users/123")


# Example 2: Multiple checks before a batch operation
sensitive_endpoints = [
    ('DELETE', '/api/admin/reset'),
    ('POST', '/api/billing/charge'),
    ('PATCH', '/api/accounts/123/permissions'),
]

blocked_endpoints = []
for method, endpoint in sensitive_endpoints:
    if client.endpoint_blocked(method=method, endpoint=endpoint):
        blocked_endpoints.append((method, endpoint))

if blocked_endpoints:
    print(f"⚠️  {len(blocked_endpoints)} endpoints are blocked:")
    for method, endpoint in blocked_endpoints:
        print(f"   - {method} {endpoint}")
    print("Cannot proceed with batch operation")
else:
    print("✅ All endpoints are available - batch operation can proceed")


# Example 3: Using endpoint_blocked in a request wrapper
import requests

def safe_request(method, endpoint, *args, **kwargs):
    """Wrapper that checks if endpoint is blocked before making request."""
    if client.endpoint_blocked(method=method, endpoint=endpoint):
        raise Exception(f"Endpoint {method} {endpoint} is blocked")
    
    url = f"https://api.example.com{endpoint}"
    return requests.request(method, url, *args, **kwargs)


# Use the safe wrapper
try:
    response = safe_request('GET', '/api/data')
    print(f"Response: {response.status_code}")
except Exception as e:
    print(f"Error: {e}")


# Example 4: Automatic request gate
secploy_gate = SecployGate(client=client)
secured_session = client.security_session(
    auth={"auth_provider": "bearer"},
    metadata={"service": "endpoint-blocking-example"},
)

prepared_request = {
    'method': 'POST',
    'url': 'https://api.example.com/api/critical-action',
    'headers': {
        'Authorization': 'Bearer token',
        'X-User-Id': 'user_123',
        'X-Session-Id': 'sess_456',
    },
}

try:
    allowed_request = secploy_gate(request=prepared_request)
    print(f"Gate allowed {allowed_request['method']} {allowed_request['url']}")
except SecurityGateBlocked as exc:
    print(f"Gate blocked request: {exc}")
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

