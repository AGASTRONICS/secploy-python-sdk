"""
Batched identity reporting.

The gate used to report the caller's identity as a side effect of asking the API
whether a request was allowed — one report, and one database write, per request.
With the policy cached locally the gate makes no request at all, so identities
would otherwise stop being reported entirely.

They are reported from here instead, and the important part is the deduplication
rather than the batching. A busy endpoint sees the same user hundreds of times a
minute; sending each sighting would only move the write storm from the request
path to a queue. An identity is re-sent only when something about it changes, or
when its last report has aged out — so steady traffic from a known user costs one
report per interval, not one per request.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

import requests

from .lib import secploy_logger

# How long an unchanged identity stays suppressed before being reported again.
DEFAULT_REPORT_INTERVAL = 300

# How often the pending batch is flushed.
DEFAULT_FLUSH_INTERVAL = 30

DEFAULT_MAX_BATCH = 500

# Cap on distinct identities tracked for deduplication. Without it, an app whose
# identity key is something high-cardinality (a per-request id, say) would grow
# this table without bound.
DEFAULT_MAX_TRACKED = 10_000

_FINGERPRINT_FIELDS = (
    "identity_key",
    "user_id",
    "name",
    "username",
    "avatar",
    "email",
    "session_id",
    "auth_provider",
    "ip_address",
    "remote_addr",
    "is_authenticated",
)


class IdentityReporter:
    """
    Collects identity observations and ships them in deduplicated batches.

    Args:
        api_url:          Base API URL.
        headers_callback: Returns current SDK auth headers.
        report_interval:  Seconds an unchanged identity stays suppressed.
        flush_interval:   Seconds between background flushes.
        max_batch:        Most identities sent in one request.
        max_tracked:      Most identities remembered for deduplication.
    """

    def __init__(
        self,
        api_url: str,
        headers_callback,
        report_interval: int = DEFAULT_REPORT_INTERVAL,
        flush_interval: int = DEFAULT_FLUSH_INTERVAL,
        max_batch: int = DEFAULT_MAX_BATCH,
        max_tracked: int = DEFAULT_MAX_TRACKED,
    ):
        self._api_url = api_url.rstrip("/")
        self._get_headers = headers_callback
        self._report_interval = report_interval
        self._flush_interval = flush_interval
        self._max_batch = max_batch
        self._max_tracked = max_tracked

        self._lock = threading.Lock()
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._seen: Dict[str, tuple] = {}  # identity_key -> (fingerprint, reported_at)

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(auth: Dict[str, Any]) -> tuple:
        return tuple(str(auth.get(field) or "") for field in _FINGERPRINT_FIELDS)

    def record(self, auth: Optional[Dict[str, Any]]) -> bool:
        """
        Note that an identity was seen. Returns True if it was queued for
        sending, False if it was suppressed as a duplicate.

        Cheap by design: this runs on the request path, so it does a dict lookup
        and a tuple comparison and nothing else.
        """
        if not auth:
            return False

        identity_key = str(auth.get("identity_key") or auth.get("user_id") or "").strip()
        if not identity_key or identity_key == "anonymous":
            return False

        fingerprint = self._fingerprint(auth)
        now = time.time()

        with self._lock:
            previous = self._seen.get(identity_key)
            if previous is not None:
                last_fingerprint, reported_at = previous
                unchanged = last_fingerprint == fingerprint
                fresh = (now - reported_at) < self._report_interval
                if unchanged and fresh:
                    return False

            self._seen[identity_key] = (fingerprint, now)
            self._trim_seen()

            # Only fields actually present are carried, so a later sparse
            # sighting (a gate call that knows the key but not the email, say)
            # merges into the richer earlier one instead of erasing it. A field
            # explicitly sent as False still counts as present and wins.
            record = {
                field: auth[field]
                for field in _FINGERPRINT_FIELDS
                if auth.get(field) is not None
            }
            record["identity_key"] = identity_key
            record["last_seen_at"] = _utc_now_iso()

            existing = self._pending.get(identity_key)
            if existing:
                merged = dict(existing)
                merged.update(record)
                record = merged
            self._pending[identity_key] = record

            over_capacity = len(self._pending) >= self._max_batch

        if over_capacity:
            self.flush()
        return True

    def _trim_seen(self) -> None:
        """Drop the oldest tracked identities once over capacity. Caller holds the lock."""
        excess = len(self._seen) - self._max_tracked
        if excess <= 0:
            return
        oldest = sorted(self._seen.items(), key=lambda item: item[1][1])[:excess]
        for key, _ in oldest:
            self._seen.pop(key, None)

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def flush(self, timeout: int = 10) -> int:
        """
        Send everything pending. Returns the number of identities sent.

        Never raises: identity reporting is telemetry and must not surface in the
        host application. On failure the batch is put back so the next flush
        retries it.
        """
        with self._lock:
            if not self._pending:
                return 0
            batch = list(self._pending.values())[: self._max_batch]
            for record in batch:
                self._pending.pop(record["identity_key"], None)

        try:
            response = requests.post(
                f"{self._api_url}/projects/security/identities/",
                headers=self._get_headers(),
                json={"identities": batch},
                timeout=timeout,
            )
        except Exception as exc:
            secploy_logger.warning(f"Identity report failed: {exc}")
            self._requeue(batch)
            return 0

        if not (200 <= response.status_code < 300):
            secploy_logger.warning(
                f"Identity report rejected ({response.status_code})."
            )
            # A 4xx will not succeed on retry, so only requeue server-side faults.
            if response.status_code >= 500:
                self._requeue(batch)
            return 0

        secploy_logger.debug(f"Reported {len(batch)} identity record(s).")
        return len(batch)

    def _requeue(self, batch: List[Dict[str, Any]]) -> None:
        with self._lock:
            for record in batch:
                # A newer sighting queued while we were sending wins.
                self._pending.setdefault(record["identity_key"], record)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop():
            while not self._stop.wait(timeout=self._flush_interval):
                try:
                    self.flush()
                except Exception as exc:
                    secploy_logger.warning(f"Identity flush loop error: {exc}")

        self._thread = threading.Thread(
            target=_loop, daemon=True, name="secploy-identity-report"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        try:
            self.flush()
        except Exception:
            pass

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
