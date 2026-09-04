from typing import Dict, Any, Optional
import time
import uuid
from dataclasses import dataclass, field
from queue import Empty, Full, Queue

from .lib import secploy_logger
from .sampling import should_send
from .scrubbing import Scrubber

# How many unsent events may be held before the oldest start being discarded.
#
# The queue used to be unbounded. If the ingest was unreachable - an outage, a
# firewall rule, a typo in the URL - it grew for as long as the application kept
# running, inside the application's own memory. An agent that reports on a
# service must not be the reason that service dies, so the buffer is finite and
# overflow is a counted loss rather than a slow leak.
#
# At roughly a kilobyte per event this is single-digit megabytes: enough to ride
# out a long outage, small enough to be invisible next to the host application.
DEFAULT_MAX_QUEUE_SIZE = 10000


@dataclass
class EventBatch:
    events: list = field(default_factory=list)
    size: int = 0
    last_flush: float = field(default_factory=time.time)


class EventHandler:
    """
    The single door every event goes through on its way out.

    Scrubbing and the before_send hook live here rather than at each place that
    builds a payload, because that is the only arrangement that stays correct:
    redacting per call site guarantees the next payload someone adds is the one
    that leaks.
    """

    def __init__(self, queue: Queue, scrubber=None, before_send=None, sampling_rate: float = 1.0):
        self._event_queue = queue
        # Events discarded because the queue was full. Surfaced so a silent
        # loss is at least a countable one.
        self.dropped_events = 0
        self._scrubber = scrubber if scrubber is not None else Scrubber()
        self._before_send = before_send
        self._sampling_rate = sampling_rate
        # Events the application's own hook chose not to send.
        self.filtered_events = 0
        # Events thinned by sampling. Counted separately from the two above:
        # they mean different things, and a rate that turns out to be dropping
        # more than expected should be visible rather than inferred.
        self.sampled_events = 0

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

    # Top-level namespaces for security/domain signals (e.g. fraud.rule.matched)
    _ALLOWED_NAMESPACED_PREFIXES = (
        "auth.",
        "account.",
        "payment.",
        "fraud.",
        "compliance.",
        "access.",
        "data.",
        "api.",
        "secret.",
        "security.",
        "incident.",
        "dependency_scan.",
    )

    def _normalize_event_type(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        normalized = str(value).strip().lower()
        return normalized if normalized in self._ALLOWED_EVENT_TYPES else None
    def _normalize_event_type(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        normalized = str(value).strip().lower()
        if normalized in self._ALLOWED_EVENT_TYPES:
            return normalized
        # Allow well-known namespaced security/domain signal types
        if any(normalized.startswith(prefix) for prefix in self._ALLOWED_NAMESPACED_PREFIXES):
            return normalized
        return None

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

            # Sampling first, so the work below - the hook, the scrub, the
            # serialisation - is not spent on an event that is about to be
            # discarded. Errors and security signals are never sampled; see
            # sampling.py for why that distinction exists.
            if not should_send(event_type, normalized_payload, self._sampling_rate):
                self.sampled_events += 1
                return False

            # The application's hook runs first, on the real values, so it can
            # decide from them - drop this event, annotate it, redact something
            # only this codebase knows is sensitive.
            if self._before_send is not None:
                normalized_payload = self._apply_before_send(normalized_payload)
                if normalized_payload is None:
                    self.filtered_events += 1
                    return False

            # Scrubbing runs last so that nothing the hook returned - including
            # anything it added - can escape unscrubbed.
            normalized_payload = self._scrubber.scrub(normalized_payload)
            if not isinstance(normalized_payload, dict):
                # The scrubber refused the payload outright.
                return False

            # Generated here, at enqueue, and never again. A retry of a batch
            # carries the same ids, which is what lets the ingest recognise a
            # redelivery and not count the occurrence twice - and occurrence
            # counts are the whole point of grouping.
            normalized_payload.setdefault("event_id", str(uuid.uuid4()))
            return self._enqueue({
                "type": event_type,
                "payload": normalized_payload,
                "timestamp": time.time()
            })
        except Exception as e:
            secploy_logger.error(f"Failed to queue event: {e}")
            return False

    def _apply_before_send(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Run the application's hook, defensively.

        A hook that raises must not stop the SDK reporting. The event is kept
        rather than dropped: a broken filter should cost visibility into the
        filter, not into the application.
        """
        try:
            result = self._before_send(dict(payload))
        except Exception as exc:
            secploy_logger.error(f"before_send raised, keeping the event as-is: {exc}")
            return payload

        if result is None:
            return None
        if not isinstance(result, dict):
            secploy_logger.error(
                "before_send must return a dict or None; keeping the event as-is"
            )
            return payload
        return result

    def _enqueue(self, event: Dict[str, Any]) -> bool:
        """
        Add an event, making room by discarding the oldest if the queue is full.

        Never blocks. This is called from the application's own request path,
        and a full buffer must not become backpressure on the service being
        observed - the whole point of queueing here is that the application
        never waits on us.

        The oldest go first because the newest are the ones that matter. If the
        ingest is unreachable, keeping a stale window and refusing everything
        since would leave the SDK blind to what is happening now, which for a
        security agent is the wrong half of the data to keep.
        """
        # Bounded rather than a bare loop: under heavy contention another
        # producer can refill the slot we just made, and spinning here would
        # turn a full queue into a busy wait on the caller's request path.
        for _ in range(8):
            try:
                self._event_queue.put_nowait(event)
                return True
            except Full:
                try:
                    self._event_queue.get_nowait()
                    self.dropped_events += 1
                    if self.dropped_events % 1000 == 1:
                        secploy_logger.warning(
                            f"Event queue is full; discarded {self.dropped_events} "
                            f"oldest events so far"
                        )
                except Empty:
                    # Drained by the processor between the two calls. Try the
                    # insert again rather than losing this event.
                    continue

        self.dropped_events += 1
        return False
