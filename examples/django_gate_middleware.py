"""Django middleware example: protect inbound requests with SecployGate."""

from django.http import JsonResponse
from secploy import SecployClient, SecurityGateBlocked

client = SecployClient()
secploy_gate = client.security_gate()


class SecployGateMiddleware:
    def __init__(self, get_response):
        self._middleware = secploy_gate.django_middleware(get_response)

    def __call__(self, request):
        return self._middleware(request)


def custom_blocked_handler(request, exc: SecurityGateBlocked):
    """Optional: plug this into django_middleware(..., blocked_handler=custom_blocked_handler)."""
    return JsonResponse(
        {
            "detail": "Blocked by Secploy",
            "reason": exc.reason,
            "message": str(exc),
            "control": {
                "action_type": exc.action_type,
                "target": exc.target,
            },
        },
        status=403,
    )
