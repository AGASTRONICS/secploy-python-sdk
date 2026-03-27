import threading
from typing import Callable, Dict, Optional

import requests

from .lib import secploy_logger
from .realtime import ConfigRealtime


class ConfigManager:
    """
    Handles fetching, caching, and auto-refreshing project configs
    from the Secploy API.

    Expected to be composed into SecployClient rather than used standalone.
    """

    def __init__(self, api_url: str, headers_callback: Callable[[], Dict[str, str]]):
        self._api_url = api_url.rstrip("/")
        self._get_headers = headers_callback

        self._configs: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._refresh_thread: Optional[threading.Thread] = None
        self._refresh_stop = threading.Event()
        self._realtime: Optional[ConfigRealtime] = None

    # ------------------------------------------------------------------
    # Core fetch
    # ------------------------------------------------------------------

    def fetch(self) -> Dict[str, str]:
        """
        Pull all active configs for the project+environment from the API
        and replace the local cache.

        Returns:
            dict: key → plaintext value.

        Raises:
            RuntimeError: on HTTP or network failure.
        """
        url = f"{self._api_url}/projects/configs/"
        try:
            resp = requests.get(url, headers=self._get_headers(), timeout=10)
        except requests.RequestException as exc:
            raise RuntimeError(f"Config fetch failed: {exc}") from exc

        if resp.status_code == 401:
            raise RuntimeError("Config fetch: invalid API key or environment key.")
        if not resp.ok:
            raise RuntimeError(f"Config fetch failed ({resp.status_code}): {resp.text}")

        data = resp.json()
        configs = data.get("configs", {})
        with self._lock:
            self._configs = configs

        secploy_logger.info(
            f"Fetched {data.get('count', len(configs))} configs "
            f"for environment '{data.get('environment', '')}'"
        )
        return configs

    # ------------------------------------------------------------------
    # Access helpers
    # ------------------------------------------------------------------

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Return one config value, lazy-fetching on first access.
        """
        with self._lock:
            cached = bool(self._configs)

        if not cached:
            try:
                self.fetch()
            except RuntimeError as exc:
                secploy_logger.warning(f"Config lazy-fetch failed: {exc}")
                return default

        with self._lock:
            return self._configs.get(key, default)

    def all(self) -> Dict[str, str]:
        """
        Return a snapshot of all cached configs, lazy-fetching if empty.
        """
        with self._lock:
            cached = bool(self._configs)
        if not cached:
            self.fetch()
        with self._lock:
            return dict(self._configs)

    # ------------------------------------------------------------------
    # Auto-refresh
    # ------------------------------------------------------------------

    def start_refresh(
        self,
        interval: int = 60,
        on_change: Optional[Callable[[str, Optional[str], Optional[str]], None]] = None,
    ) -> None:
        """
        Start a background thread that re-fetches every ``interval`` seconds.

        Args:
            interval:  Seconds between refreshes (default 60).
            on_change: Called for every key whose value changed::

                          def on_change(key, old_value, new_value): ...
        """
        if self._refresh_thread and self._refresh_thread.is_alive():
            secploy_logger.warning("Config auto-refresh is already running.")
            return

        self._refresh_stop.clear()

        def _loop():
            while not self._refresh_stop.wait(timeout=interval):
                try:
                    with self._lock:
                        old = dict(self._configs)
                    new = self.fetch()
                    if on_change:
                        for k in set(old) | set(new):
                            if old.get(k) != new.get(k):
                                on_change(k, old.get(k), new.get(k))
                except RuntimeError as exc:
                    secploy_logger.warning(f"Config auto-refresh error: {exc}")

        self._refresh_thread = threading.Thread(
            target=_loop, daemon=True, name="secploy-config-refresh"
        )
        self._refresh_thread.start()
        secploy_logger.info(f"Config auto-refresh started (every {interval}s).")

    def stop_refresh(self) -> None:
        """Stop the background refresh thread."""
        self._refresh_stop.set()
        if self._refresh_thread:
            self._refresh_thread.join(timeout=5)
        secploy_logger.info("Config auto-refresh stopped.")

    @property
    def is_refreshing(self) -> bool:
        return bool(self._refresh_thread and self._refresh_thread.is_alive())

    # ------------------------------------------------------------------
    # Real-time / WebSocket delivery
    # ------------------------------------------------------------------

    def start_realtime(self, ws_url: str, headers_callback: Callable[[], Dict[str, str]]) -> None:
        """
        Start a WebSocket connection that pushes config updates in real time.
        Falls back to 15 s polling automatically when the socket is down.

        Args:
            ws_url:           Full WebSocket URL, e.g. ``wss://api.secploy.com/ws/sdk/configs/``.
            headers_callback: Callable that returns the current auth headers dict.
        """
        if self._realtime is not None:
            secploy_logger.warning("Config real-time is already running.")
            return

        self._realtime = ConfigRealtime(
            ws_url=ws_url,
            headers_callback=headers_callback,
            on_update=self.fetch,
        )
        self._realtime.start()

    def stop_realtime(self) -> None:
        """Stop the WebSocket connection (and any polling fallback)."""
        if self._realtime is not None:
            self._realtime.stop()
            self._realtime = None
            secploy_logger.info("Config real-time stopped.")

    @property
    def is_realtime(self) -> bool:
        """True while a WebSocket connection is open."""
        return self._realtime is not None and self._realtime.is_connected
