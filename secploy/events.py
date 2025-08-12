import queue
import threading
import requests
import time

class EventQueue(threading.Thread):
    def __init__(self, config):
        super().__init__(daemon=True)
        self.config = config
        self.events = queue.Queue()
        self._stop_event = threading.Event()

    def add_event(self, event_type, payload):
        self.events.put({"type": event_type, "payload": payload})

    def run(self):
        while not self._stop_event.is_set():
            try:
                event = self.events.get(timeout=1)
                requests.post(
                    f"{self.config.ingest_url}/event",
                    json={"api_key": self.config.api_key, **event},
                    timeout=5
                )
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Secploy] Event send error: {e}")
                time.sleep(2)

    def stop(self):
        self._stop_event.set()

