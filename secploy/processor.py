import threading
import time
import requests
from queue import Queue, Empty

from .events import EventBatch
from .lib import secploy_logger
from .transport import (
    DELIVERED,
    DROP,
    RETRY,
    backoff_delay,
    classify_status,
    parse_retry_after,
)


class EventProcessor:
    """
    Drains the event queue and delivers batches to the ingest.

    The governing constraint is that this runs inside somebody else's
    application. An observability agent that grows without bound, blocks the
    host, or retries forever is worse than one that loses events, so every
    failure path here ends in bounded memory and a counted loss rather than an
    unbounded wait.
    """

    def __init__(self, queue: Queue, ingest_url: str, headers_callback,
                 batch_size: int = 100, flush_interval: int = 60,
                 max_retry: int = 5):
        """
        Initialize the event processor.

        Args:
            queue: Queue to process events from
            ingest_url: URL to send events to
            headers_callback: Callback to get current headers
            batch_size: Maximum number of events per batch
            flush_interval: Maximum time between flushes in seconds
            max_retry: Maximum number of delivery attempts per batch
        """
        self.queue = queue
        self.ingest_url = ingest_url.rstrip("/")
        self._get_headers = headers_callback
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retry = max_retry
        self._session = requests.Session()

        self._stop_event = threading.Event()
        self._thread = None
        self._event_batch = EventBatch()

        # Events lost after delivery was given up on, as opposed to events the
        # queue dropped under pressure. Kept separate because they mean
        # different things: one says the ingest would not take them, the other
        # says we produced faster than we could send.
        self.dropped_events = 0

    def _post(self, events: list):
        """
        One delivery attempt.

        Returns ``(outcome, retry_after)``. Never raises: a transport failure is
        an outcome, not an exception, and this runs on a daemon thread where an
        escape would end event delivery for the life of the process.
        """
        try:
            response = self._session.post(
                self.ingest_url,
                json={"events": events},
                headers=self._get_headers(),
                timeout=5,
            )
        except Exception as exc:
            secploy_logger.debug(f"Send batch failed: {exc}")
            return RETRY, None

        outcome = classify_status(response.status_code)

        if outcome == DROP:
            # Log the body: a 4xx is a complaint about our payload and the
            # detail is the only way anyone will work out which event caused it.
            secploy_logger.error(
                f"Ingest rejected a batch of {len(events)} events "
                f"({response.status_code}): {response.text[:500]}"
            )
        elif outcome == RETRY:
            secploy_logger.debug(f"Ingest returned {response.status_code}, will retry")

        return outcome, parse_retry_after(response.headers.get("Retry-After"))

    def _send_batch(self, events: list, max_attempts: int = None) -> bool:
        """
        Deliver a batch, retrying transient failures with jittered backoff.

        Returns True when the batch should be cleared - which includes the case
        where it was permanently rejected. The caller must not keep a batch the
        server has refused on its content; that is what turned a single
        malformed event into a stuck pipeline.
        """
        if not events:
            return True

        attempts = self.max_retry if max_attempts is None else max_attempts

        for attempt in range(attempts):
            outcome, retry_after = self._post(events)

            if outcome == DELIVERED:
                secploy_logger.debug(f"Batch of {len(events)} events sent successfully")
                return True

            if outcome == DROP:
                self.dropped_events += len(events)
                secploy_logger.warning(
                    f"Discarded {len(events)} events the ingest rejected "
                    f"(total discarded: {self.dropped_events})"
                )
                return True

            if attempt == attempts - 1:
                break

            delay = backoff_delay(attempt, retry_after)
            # Wait on the stop event rather than sleeping, so shutdown is not
            # held up by a backoff that may run to half a minute.
            if self._stop_event.wait(delay):
                return False

        self.dropped_events += len(events)
        secploy_logger.warning(
            f"Giving up on {len(events)} events after {attempts} attempts "
            f"(total discarded: {self.dropped_events})"
        )
        return True

    def _should_flush(self, now: float) -> bool:
        if self._event_batch.size >= self.batch_size:
            return True
        return (
            self._event_batch.size > 0
            and now - self._event_batch.last_flush >= self.flush_interval
        )

    def _process_events(self):
        """Process queued events and send them in batches."""
        while not self._stop_event.is_set():
            try:
                try:
                    # The one-second block is what makes the time-based flush
                    # work on a quiet application: without it this loop would
                    # only wake when an event arrived, and a lone event would
                    # sit unsent until the next one came along.
                    event = self.queue.get(timeout=1)
                    self._event_batch.events.append(event)
                    self._event_batch.size += 1
                except Empty:
                    pass

                if self._should_flush(time.time()):
                    batch = self._event_batch.events
                    # Reset before sending. Whatever happens to this batch, it
                    # is no longer the buffer's problem, and events arriving
                    # during a slow send accumulate in the new one.
                    self._event_batch = EventBatch()
                    self._send_batch(batch)

            except Exception as e:
                secploy_logger.error(f"Error processing events: {e}")

    def start(self):
        """Start processing events in the background."""
        if self._thread and self._thread.is_alive():
            return

        secploy_logger.info("Starting event processor...")
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._process_events,
            name="secploy-events",
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop processing events and flush what is still buffered."""
        if not self._thread:
            return

        secploy_logger.info("Stopping event processor...")
        self._stop_event.set()
        self._thread.join(timeout=5)

        # Drain the queue as well as the batch. Events sitting in the queue at
        # shutdown were previously discarded silently, which lost exactly the
        # events a crashing process most needs to report.
        #
        # Bounded by batch_size: a backlog of thousands would turn stop() into a
        # multi-megabyte upload while the application is trying to exit. What
        # does not fit is reported rather than dropped quietly.
        drained = []
        while len(drained) < self.batch_size:
            try:
                drained.append(self.queue.get_nowait())
            except Empty:
                break

        abandoned = self.queue.qsize()
        if abandoned:
            self.dropped_events += abandoned
            secploy_logger.warning(
                f"{abandoned} events were still queued at shutdown and were not sent"
            )

        remaining = self._event_batch.events + drained
        if remaining:
            # One attempt, no backoff. Shutdown is not the moment to spend half
            # a minute sleeping between retries - an application waiting on
            # close() would rather lose the batch than hang.
            self._send_batch(remaining, max_attempts=1)

        self._event_batch = EventBatch()
        self._session.close()

        self._thread = None
