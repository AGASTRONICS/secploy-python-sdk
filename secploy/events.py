from typing import Dict, Any, Optional
import time
from dataclasses import dataclass, field
from queue import Queue

from .lib import secploy_logger


@dataclass
class EventBatch:
    events: list = field(default_factory=list)
    size: int = 0
    last_flush: float = field(default_factory=time.time)


class EventHandler:
    def __init__(self, queue: Queue):
        self._event_queue = queue

    _ALLOWED_EVENT_TYPES = {
        "log",
        "metric",
        "event",
        "info",
        "warn",
        "error",
        "debug",
        "warning",
        "critical",
        "http_request",
        "system_metrics",
        "function_execution",
        "function_registry",
        "dependency_health_report",
    }

    def _normalize_event_type(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        normalized = str(value).strip().lower()
        return normalized if normalized in self._ALLOWED_EVENT_TYPES else None

    def _infer_event_type_from_status(self, status_code: Any) -> Optional[str]:
        try:
            code = int(status_code)
        except (TypeError, ValueError):
            return None

        if code >= 500:
            return "critical"
        if code >= 400:
            return "warning"
        if code >= 300:
            return "info"
        return "info"

    def _normalize_payload(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        # Do not mutate caller-owned objects.
        normalized_payload: Dict[str, Any] = dict(payload or {})

        context = normalized_payload.get("context")
        if not isinstance(context, dict):
            context = {}
        else:
            context = dict(context)

        endpoint = normalized_payload.get("endpoint") or normalized_payload.get("path")
        method = normalized_payload.get("method")
        status_code = normalized_payload.get("status_code")

        if endpoint:
            context.setdefault("path", endpoint)
            context.setdefault("http_url", endpoint)
        if method:
            context.setdefault("method", method)
            context.setdefault("http_method", method)
        if status_code is not None:
            context.setdefault("status_code", status_code)
            context.setdefault("http_status", status_code)

        normalized_payload["context"] = context

        explicit_payload_type = self._normalize_event_type(normalized_payload.get("type"))
        explicit_event_type = self._normalize_event_type(event_type)
        inferred_type = self._infer_event_type_from_status(
            context.get("http_status", normalized_payload.get("status_code"))
        )

        final_type = explicit_payload_type or explicit_event_type or inferred_type or "event"
        normalized_payload["type"] = final_type
        context.setdefault("type", final_type)

        if not normalized_payload.get("message"):
            normalized_payload["message"] = str(event_type)

        return normalized_payload

    def send_event(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """
        Queue an event for sending. Events are batched and sent periodically.
        
        Args:
            event_type: Type of the event
            payload: Event payload data
        
        Returns:
            bool: True if event was queued successfully
        """
        try:
            normalized_payload = self._normalize_payload(event_type, payload)
            self._event_queue.put({
                "type": event_type,
                "payload": normalized_payload,
                "timestamp": time.time()
            })
            return True
        except Exception as e:
            secploy_logger.error(f"Failed to queue event: {e}")
            return False
