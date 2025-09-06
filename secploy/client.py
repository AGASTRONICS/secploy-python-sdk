import threading
import time
import queue
from typing import Any, Dict, Optional
import requests
from dataclasses import dataclass, field

from secploy.lib.secploy_logger import setup_logger
from secploy.utils import log
from secploy.lib.config import load_config, DEFAULT_CONFIG
from secploy.schemas import SecployConfig, LogLevel

@dataclass
class EventBatch:
    events: list = field(default_factory=list)
    size: int = 0
    last_flush: float = field(default_factory=time.time)

class SecployClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        config_file: Optional[str] = None,
        config: Optional[SecployConfig] = DEFAULT_CONFIG,
    ):
        """
        Initialize the Secploy client.

        Args:
            api_key: Optional API key to override configuration
            config_file: Optional path to configuration file
            config: Configuration object, defaults to DEFAULT_CONFIG
        
        Raises:
            ValueError: If required configuration is missing
            TypeError: If configuration values have invalid types
        """
        # Load config from file if provided
        if config_file:
            config = load_config(config_file)
            
        # Override api_key if provided directly
        if api_key:
            config.api_key = api_key
            
        # Special handling for log_level if it's a string
        if isinstance(config.get('log_level'), str):
            try:
                config['log_level'] = LogLevel(config['log_level'].upper())
            except ValueError:
                raise ValueError(
                    f"Invalid log level: {config.get('log_level')}. Must be one of: "
                    f"{', '.join(level.value for level in LogLevel)}"
                )

        # Validate required fields
        if not config.api_key:
            raise ValueError("API key is required")
        if not config.ingest_url:
            raise ValueError("Ingest URL is required")

        # Set instance attributes from config
        self.api_key = config.api_key
        self.ingest_url = config.ingest_url.rstrip("/")
        self.heartbeat_interval = config.heartbeat_interval
        self.max_retry = config.max_retry
        self.debug = config.debug
        self.log_level = config.log_level
        
        # Batch processing configuration
        self.batch_size = getattr(config, 'batch_size', 100)  # Max events per batch
        self.flush_interval = getattr(config, 'flush_interval', 60)  # Max seconds between flushes

        # Initialize internal state
        self._stop_event = threading.Event()
        self._thread = None
        self._event_queue = queue.Queue()
        self._event_batch = EventBatch()
        
        # Setup logging
        setup_logger(log_level=self.log_level)
    
    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

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
            self._event_queue.put({
                "type": event_type,
                "payload": payload,
                "timestamp": time.time()
            })
            return True
        except Exception as e:
            log(f"Failed to queue event: {e}", self.debug)
            return False

    def _send_batch(self, events: list) -> bool:
        """
        Send a batch of events to the server.
        
        Args:
            events: List of event dictionaries to send
        
        Returns:
            bool: True if batch was sent successfully
        """
        url = f"{self.ingest_url}"
        for attempt in range(self.max_retry):
            try:
                resp = requests.post(url, json={"events": events}, headers=self._headers(), timeout=5)
                if resp.status_code == 200:
                    log(f"Batch of {len(events)} events sent successfully", self.debug)
                    return True
            except Exception as e:
                log(f"Send batch failed: {e}", self.debug)
            time.sleep(1)
        return False

    def _process_events(self):
        """Process queued events and send them in batches."""
        while not self._stop_event.is_set():
            try:
                # Get an event from the queue
                try:
                    event = self._event_queue.get(timeout=1)
                    self._event_batch.events.append(event)
                    self._event_batch.size += 1
                except queue.Empty:
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
                log(f"Error processing events: {e}", self.debug)

    def _heartbeat_loop(self):
        """Send periodic heartbeats to the server."""
        url = f"{self.ingest_url}/heartbeat"
        while not self._stop_event.is_set():
            try:
                resp = requests.post(url, headers=self._headers(), timeout=5)
                if resp.status_code == 200:
                    log(f"Heartbeat sent successfully", self.debug)
                else:
                    log(f"Heartbeat failed with status {resp.status_code}", self.debug)
            except Exception as e:
                log(f"Heartbeat failed: {e}", self.debug)
            time.sleep(self.heartbeat_interval)

    def start(self):
        """Start the client's background threads for heartbeat and event processing."""
        log("Starting Secploy client...", self.debug)
        self._stop_event.clear()
        
        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="secploy-heartbeat",
            daemon=True
        )
        self._heartbeat_thread.start()
        
        # Start event processing thread
        self._event_thread = threading.Thread(
            target=self._process_events,
            name="secploy-events",
            daemon=True
        )
        self._event_thread.start()

    def stop(self):
        """Stop the client and wait for background threads to finish."""
        log("Stopping Secploy client...", self.debug)
        self._stop_event.set()
        
        # Wait for threads to finish
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
        if self._event_thread:
            self._event_thread.join(timeout=5)
            
        # Flush any remaining events
        if self._event_batch.events:
            self._send_batch(self._event_batch.events)
