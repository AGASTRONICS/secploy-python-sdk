import requests
import threading
import time

class HeartbeatThread(threading.Thread):
    def __init__(self, config, interval=30):
        super().__init__(daemon=True)
        self.config = config
        self.interval = interval
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            try:
                requests.post(
                    f"{self.config.ingest_url}/heartbeat",
                    json={"api_key": self.config.api_key, "status": "running"},
                    timeout=5
                )
            except Exception as e:
                print(f"[Secploy] Heartbeat error: {e}")
            time.sleep(self.interval)

    def stop(self):
        self._stop_event.set()
