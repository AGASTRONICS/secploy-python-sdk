import threading
import time
import requests

from lib.secploy_logger import setup_logger
from .utils import log

class SecployClient:
    def __init__(self, api_key, ingest_url, heartbeat_interval=30, max_retry=3, debug=False, log_level='INFO'):
        self.api_key = api_key
        self.ingest_url = ingest_url.rstrip("/")
        self.heartbeat_interval = heartbeat_interval
        self.max_retry = max_retry
        self.debug = debug
        self.log_level = log_level
        self._stop_event = threading.Event()
        self._thread = None
        setup_logger(log_level=log_level)
    
    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def send_event(self, event_type, payload):
        url = f"{self.ingest_url}/events"
        data = {"type": event_type, "payload": payload}
        for attempt in range(self.max_retry):
            try:
                resp = requests.post(url, json=data, headers=self._headers(), timeout=5)
                if resp.status_code == 200:
                    log("Event sent successfully", self.debug)
                    return True
            except Exception as e:
                log(f"Send event failed: {e}", self.debug)
            time.sleep(1)
        return False

    def _heartbeat_loop(self):
        url = f"{self.ingest_url}/heartbeat"
        while not self._stop_event.is_set():
            try:
                resp = requests.post(url, headers=self._headers(), timeout=5)
                log(f"Heartbeat sent: {resp.status_code}", self.debug)
            except Exception as e:
                log(f"Heartbeat failed: {e}", self.debug)
            time.sleep(self.heartbeat_interval)

    def start(self):
        log("Starting heartbeat...", self.debug)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()

    def stop(self):
        log("Stopping heartbeat...", self.debug)
        self._stop_event.set()
        if self._thread:
            self._thread.join()
