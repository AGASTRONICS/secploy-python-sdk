"""
Real-time config delivery via WebSocket with polling fallback.

Requires the optional ``websocket-client`` package for WebSocket support.
If not installed, the client automatically falls back to polling.

    pip install websocket-client
"""

import json
import threading
from typing import Callable, Dict, Optional, Sequence

from .lib import secploy_logger

_INITIAL_BACKOFF = 1    # seconds
_MAX_BACKOFF = 60       # seconds
_POLL_FALLBACK_INTERVAL = 15  # seconds


class RealtimeChannel:
    """
    Maintains a long-lived WebSocket connection to a Secploy push stream.

    When an update message arrives the ``on_update`` callback is invoked
    immediately so the local cache is refreshed.  While the socket is
    disconnected a polling thread fires every 15 s as a fallback; it stops
    automatically once the socket reconnects.

    The server pushes an invalidation, not a payload, so ``on_update`` is
    expected to refetch. That keeps delivery idempotent: a duplicated or
    out-of-order notification costs one extra fetch and can never corrupt state.

    Usage::

        realtime = RealtimeChannel(
            ws_url="wss://api.secploy.com/ws/sdk/configs/",
            headers_callback=client._headers,
            on_update=config_manager.fetch,
        )
        realtime.start()
        # …
        realtime.stop()
    """

    def __init__(
        self,
        ws_url: str,
        headers_callback: Callable[[], Dict[str, str]],
        on_update: Callable[[], None],
        channel_name: str = "config",
        thread_prefix: str = "secploy-config",
        update_message_types: Sequence[str] = ("config.update", "config.subscribed"),
    ):
        self._ws_url = ws_url
        self._get_headers = headers_callback
        self._on_update = on_update
        self._channel_name = channel_name
        self._thread_prefix = thread_prefix
        self._update_message_types = tuple(update_message_types)

        self._ws = None
        self._ws_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connected = threading.Event()

        # Polling fallback state
        self._poll_thread: Optional[threading.Thread] = None
        self._poll_stop = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the WebSocket connection thread."""
        self._stop_event.clear()
        self._ws_thread = threading.Thread(
            target=self._run_with_reconnect,
            daemon=True,
            name=f"{self._thread_prefix}-ws",
        )
        self._ws_thread.start()

    def stop(self) -> None:
        """Shut down the WebSocket and any active polling thread."""
        self._stop_event.set()
        self._stop_polling()
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
        if self._ws_thread is not None:
            self._ws_thread.join(timeout=5)

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    # ------------------------------------------------------------------
    # WebSocket lifecycle
    # ------------------------------------------------------------------

    def _run_with_reconnect(self) -> None:
        try:
            import websocket  # noqa: PLC0415 – optional dependency
        except ImportError:
            secploy_logger.warning(
                f"websocket-client is not installed; {self._channel_name} "
                "real-time push is unavailable.  Falling back to 15 s polling.  "
                "Install it with: pip install websocket-client"
            )
            self._start_polling()
            return

        backoff = _INITIAL_BACKOFF

        while not self._stop_event.is_set():
            headers = self._get_headers()
            # websocket-client expects headers as a list of "Key: Value" strings
            ws_headers = [
                f"{k}: {v}"
                for k, v in headers.items()
                if k.lower() != "content-type"
            ]

            self._ws = websocket.WebSocketApp(
                self._ws_url,
                header=ws_headers,
                on_open=self._on_open,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close,
            )

            # run_forever blocks until the connection closes
            self._ws.run_forever(ping_interval=30, ping_timeout=10)

            if self._stop_event.is_set():
                break

            secploy_logger.warning(
                f"{self._channel_name} WebSocket disconnected. "
                f"Reconnecting in {backoff}s…"
            )
            self._start_polling()
            self._stop_event.wait(timeout=backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)

    def _on_open(self, ws) -> None:
        secploy_logger.info(f"{self._channel_name} WebSocket connected.")
        self._connected.set()
        self._stop_polling()

    def _on_message(self, ws, message: str) -> None:
        try:
            data = json.loads(message)
        except (json.JSONDecodeError, ValueError):
            return

        msg_type = data.get("type", "")
        if msg_type in self._update_message_types:
            try:
                self._on_update()
            except Exception as exc:
                secploy_logger.warning(
                    f"{self._channel_name} update handler failed: {exc}"
                )

    def _on_error(self, ws, error) -> None:
        secploy_logger.warning(f"{self._channel_name} WebSocket error: {error}")

    def _on_close(self, ws, close_status_code, close_msg) -> None:
        secploy_logger.info(
            f"{self._channel_name} WebSocket closed (code={close_status_code})."
        )
        self._connected.clear()

    # ------------------------------------------------------------------
    # Polling fallback
    # ------------------------------------------------------------------

    def _start_polling(self) -> None:
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return

        self._poll_stop.clear()

        def _loop():
            while not self._poll_stop.wait(timeout=_POLL_FALLBACK_INTERVAL):
                # WebSocket reconnected – let the WS drive updates
                if self._connected.is_set():
                    return
                try:
                    self._on_update()
                except Exception as exc:
                    secploy_logger.warning(
                        f"{self._channel_name} poll failed: {exc}"
                    )

        self._poll_thread = threading.Thread(
            target=_loop,
            daemon=True,
            name=f"{self._thread_prefix}-poll",
        )
        self._poll_thread.start()
        secploy_logger.info(
            f"{self._channel_name} polling fallback started "
            f"(every {_POLL_FALLBACK_INTERVAL}s)."
        )

    def _stop_polling(self) -> None:
        self._poll_stop.set()
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=3)
            self._poll_thread = None


class ConfigRealtime(RealtimeChannel):
    """
    Config-stream channel.

    Kept as a named subclass so existing callers and any user code importing
    ``ConfigRealtime`` keep working unchanged.
    """

    def __init__(
        self,
        ws_url: str,
        headers_callback: Callable[[], Dict[str, str]],
        on_update: Callable[[], None],
    ):
        super().__init__(
            ws_url=ws_url,
            headers_callback=headers_callback,
            on_update=on_update,
            channel_name="config",
            thread_prefix="secploy-config",
            update_message_types=("config.update", "config.subscribed"),
        )
