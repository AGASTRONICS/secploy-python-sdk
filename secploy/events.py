from typing import Dict, Any
import time
from dataclasses import dataclass, field
from queue import Queue

from .lib import secploy_logger


@dataclass
class EventBatch:
    events: list = field(default_factory=list)
    size: int = 0
    last_flush: float = field(default_factory=time.time)


class EventHandler:
    def __init__(self, queue: Queue):
        self._event_queue = queue

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
            secploy_logger.error(f"Failed to queue event: {e}")
            return False
