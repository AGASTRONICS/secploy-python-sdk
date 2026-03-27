"""
System resource metrics collector — CPU, memory, and optional GPU.

Samples are collected on a background thread and pushed through the SDK's
event pipeline as ``system_metrics`` events so they appear as live data on
the Secploy dashboard.

Usage::

    client = SecployClient(...)
    # Already started automatically. To configure:
    client.metrics.interval = 5   # seconds between samples (default: 10)
    client.metrics.start()        # if you stopped it earlier
    # …
    client.metrics.stop()

psutil is a required dependency for this module.
gputil is optional; GPU metrics are silently omitted when unavailable.
"""

import threading
import time
from typing import Any, Callable, Dict, Optional

from .lib import secploy_logger

_DEFAULT_INTERVAL = 10  # seconds


def _collect_cpu() -> Dict[str, Any]:
    try:
        import psutil

        per_core = psutil.cpu_percent(interval=None, percpu=True)
        freq = psutil.cpu_freq()
        return {
            "usage_percent": psutil.cpu_percent(interval=None),
            "per_core_percent": per_core,
            "core_count": psutil.cpu_count(logical=True),
            "physical_core_count": psutil.cpu_count(logical=False),
            "frequency_mhz": round(freq.current, 2) if freq else None,
            "load_avg_1m": None,
            "load_avg_5m": None,
            "load_avg_15m": None,
        }
    except Exception as exc:
        secploy_logger.debug(f"CPU metrics collection failed: {exc}")
        return {}


def _collect_memory() -> Dict[str, Any]:
    try:
        import psutil

        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "total_mb": round(vm.total / 1024 / 1024, 2),
            "used_mb": round(vm.used / 1024 / 1024, 2),
            "available_mb": round(vm.available / 1024 / 1024, 2),
            "usage_percent": vm.percent,
            "swap_total_mb": round(swap.total / 1024 / 1024, 2),
            "swap_used_mb": round(swap.used / 1024 / 1024, 2),
            "swap_usage_percent": swap.percent,
        }
    except Exception as exc:
        secploy_logger.debug(f"Memory metrics collection failed: {exc}")
        return {}


def _collect_gpu() -> list:
    """Return a list of GPU stat dicts. Returns [] if GPUtil is not installed."""
    try:
        import GPUtil  # type: ignore

        gpus = GPUtil.getGPUs()
        return [
            {
                "id": gpu.id,
                "name": gpu.name,
                "load_percent": round(gpu.load * 100, 2),
                "memory_total_mb": round(gpu.memoryTotal, 2),
                "memory_used_mb": round(gpu.memoryUsed, 2),
                "memory_usage_percent": round(
                    (gpu.memoryUsed / gpu.memoryTotal * 100) if gpu.memoryTotal else 0, 2
                ),
                "temperature_c": gpu.temperature,
            }
            for gpu in gpus
        ]
    except ImportError:
        return []
    except Exception as exc:
        secploy_logger.debug(f"GPU metrics collection failed: {exc}")
        return []


class SystemMetricsCollector:
    """
    Background thread that periodically samples CPU, memory, and GPU usage
    and pushes the snapshot as a ``system_metrics`` event.

    The collected payload shape is:

    .. code-block:: json

        {
            "type": "system_metrics",
            "timestamp": 1711234567.123,
            "cpu": { "usage_percent": 23.4, "per_core_percent": [...], ... },
            "memory": { "usage_percent": 61.2, "used_mb": 4096, ... },
            "gpu": [ { "id": 0, "load_percent": 45.1, ... } ]
        }
    """

    def __init__(
        self,
        send_event: Callable[[str, Dict[str, Any]], bool],
        interval: float = _DEFAULT_INTERVAL,
    ) -> None:
        self._send_event = send_event
        self.interval = interval

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False

        # Warm up psutil's per-interval CPU tracking so first sample isn't 0.0
        try:
            import psutil
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background collection thread."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="secploy-system-metrics",
        )
        self._running = True
        self._thread.start()
        secploy_logger.info(
            f"System metrics collector started (interval={self.interval}s)."
        )

    def stop(self) -> None:
        """Stop the collection thread gracefully."""
        self._stop_event.set()
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 2)
            self._thread = None
        secploy_logger.info("System metrics collector stopped.")

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def collect_once(self) -> Dict[str, Any]:
        """Collect and return a single snapshot (cpu/memory/gpu dicts)."""
        return {
            "cpu": _collect_cpu(),
            "memory": _collect_memory(),
            "gpu": _collect_gpu(),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.wait(timeout=self.interval):
            self._sample()

    def _sample(self) -> None:
        try:
            data = self.collect_once()
            # Wrap in ingest-compatible shape: message + context
            payload = {
                "message": "system metrics snapshot",
                "context": data,
            }
            self._send_event("system_metrics", payload)
        except Exception as exc:
            secploy_logger.debug(f"System metrics sample failed: {exc}")
