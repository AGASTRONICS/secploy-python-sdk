import threading
import time
import requests
from queue import Queue, Empty

from .events import EventBatch
from .lib import secploy_logger


class EventProcessor:
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
            max_retry: Maximum number of retry attempts
        """
        self.queue = queue
        self.ingest_url = ingest_url.rstrip("/")
        self._get_headers = headers_callback
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retry = max_retry
        
        self._stop_event = threading.Event()
        self._thread = None
        self._event_batch = EventBatch()

    def _send_batch(self, events: list) -> bool:
        """
        Send a batch of events to the server.
        
        Args:
            events: List of event dictionaries to send
        
        Returns:
            bool: True if batch was sent successfully
        """
        url = self.ingest_url
        for attempt in range(self.max_retry):
            try:
                resp = requests.post(
                    url, 
                    json={"events": events}, 
                    headers=self._get_headers(),
                    timeout=5
                )
                secploy_logger.debug(f"Send batch response: {resp.status_code} - {resp.text}")
                if resp.status_code == 200:
                    secploy_logger.info(f"Batch of {len(events)} events sent successfully")
                    return True
            except Exception as e:
                secploy_logger.error(f"Send batch failed: {e}")
            time.sleep(1)
        return False

    def _process_events(self):
        """Process queued events and send them in batches."""
        while not self._stop_event.is_set():
            try:
                # Get an event from the queue
                try:
                    event = self.queue.get(timeout=1)
                    self._event_batch.events.append(event)
                    self._event_batch.size += 1
                except Empty:
                    pass

                current_time = time.time()
                should_flush = (
                    self._event_batch.size >= self.batch_size or
                    (self._event_batch.size > 0 and
                     current_time - self._event_batch.last_flush >= self.flush_interval)
                )

                if should_flush:
                    if self._send_batch(self._event_batch.events):
                        self._event_batch = EventBatch()
                    else:
                        # If send fails, wait before retrying
                        time.sleep(1)

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
        """Stop processing events and flush remaining batch."""
        if not self._thread:
            return
            
        secploy_logger.info("Stopping event processor...")
        self._stop_event.set()
        self._thread.join(timeout=5)
        
        # Flush any remaining events
        if self._event_batch.events:
            self._send_batch(self._event_batch.events)
            
        self._thread = None
