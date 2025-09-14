"""
Secploy Log Capture Module

This module provides functionality for capturing and forwarding logs to Secploy's ingest endpoint.
"""

import logging
import threading
import traceback
from typing import Any, Dict, Optional, List, Union
from datetime import datetime
from queue import Queue

from .events import EventHandler
from .schemas import LogEntry, Context, Tags


class SecployLogCapturer:
    """
    Manages log capture and forwarding to Secploy ingest endpoint.
    """
    
    def __init__(self, client, levels: Optional[List[Union[str, int]]] = None):
        """
        Initialize the log capturer.
        
        Args:
            client: An initialized SecployClient instance
        """
        self.client = client
        self.levels = levels
        self._handler = self._create_handler()
        
    def _create_handler(self) -> logging.Handler:
        """Create the custom logging handler."""
        return SecployLogHandler(self.client, levels=self.levels)

    def start_capture(self, loggers: Union[str, List[str], None] = None):
        """
        Start capturing logs from specified loggers.
        
        Args:
            loggers: Logger name(s) to capture. Can be:
                    - None to capture the root logger
                    - A string for a single logger
                    - A list of logger names
        """
        
        if isinstance(loggers, str):
            loggers = [loggers]
        elif loggers is None:
            loggers = ['']  # Root logger
            
        for logger_name in loggers:
            logger = logging.getLogger(logger_name)
            logger.addHandler(self._handler)
            
    def stop_capture(self, loggers: Union[str, List[str], None] = None):
        """
        Stop capturing logs from specified loggers.
        
        Args:
            loggers: Logger name(s) to stop capturing. Same format as start_capture()
        """
        if isinstance(loggers, str):
            loggers = [loggers]
        elif loggers is None:
            loggers = ['']  # Root logger
            
        for logger_name in loggers:
            logger = logging.getLogger(logger_name)
            if self._handler in logger.handlers:
                logger.removeHandler(self._handler)
                
    def stop_all(self):
        """Stop all log capturing."""
        # Find all loggers that have our handler
        for logger in [logging.getLogger(name) for name in logging.root.manager.loggerDict]:
            if self._handler in logger.handlers:
                logger.removeHandler(self._handler)
        # Check root logger too
        if self._handler in logging.root.handlers:
            logging.root.removeHandler(self._handler)


class SecployLogHandler(logging.Handler):
    """
    Custom logging handler that forwards logs to Secploy ingest endpoint.
    """

    def __init__(self, client, levels: Optional[List[Union[str, int]]] = None):
        super().__init__()
        self.client = client
        self._local = threading.local()
        self._event_handler = EventHandler(self.client._event_queue)
        
        if levels:
            self.levels = {
                lvl if isinstance(lvl, int) else logging._nameToLevel[lvl.upper()]
                for lvl in levels
            }
        else:
            self.levels = None  # None = capture all levels
            
    def filter(self, record: logging.LogRecord) -> bool:
        """Return True if this record should be handled."""
        if self.levels is None:
            return True
        return record.levelno in self.levels
        
    def get_thread_id(self) -> str:
        """Get the current thread identifier."""
        return str(threading.get_ident())
        
    def format_exc_info(self, exc_info) -> Optional[Dict[str, Any]]:
        """Format exception information if available."""
        if not exc_info:
            return None
            
        exc_type, exc_value, exc_tb = exc_info
        return {
            'type': exc_type.__name__ if exc_type else None,
            'message': str(exc_value) if exc_value else None,
            'stacktrace': traceback.format_tb(exc_tb) if exc_tb else None
        }
        
    def emit(self, record: logging.LogRecord):
        """Send the log record to Secploy ingest."""
        try:
            # Get stacktrace if exception exists
            stacktrace = []
            if record.exc_info:
                exc_info = self.format_exc_info(record.exc_info)
                if exc_info['stacktrace']:
                    stacktrace = exc_info['stacktrace']

            # Build tags with log metadata
            tags = Tags(
                environment=self.client.environment,
                service=record.name,
                region=getattr(record, 'region', 'unknown')
            )

            # Build context
            context = Context(
                user_id=getattr(record, 'user_id', 'unknown'),
                session_id=self.get_thread_id(),  # Using thread_id as session_id for logging
                http_method=getattr(record, 'http_method', 'NONE'),
                http_url=getattr(record, 'path', ''),
                http_status=getattr(record, 'status_code', 0),
                stacktrace=stacktrace,
                tags=tags
            )

            # Create LogEntry using our schema
            log_entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created).timestamp(),
                type=record.levelname.lower(),  # convert DEBUG -> debug, ERROR -> error etc
                message=self.format(record),
                context=context
            )
            payload = log_entry.model_dump(mode="json") 
            # Validate and send the log entry
            self._event_handler.send_event('log', payload)

        except Exception as e:
            # Avoid infinite recursion by using sys.stderr
            import sys
            print(f"Error in SecployLogHandler.emit: {e}", file=sys.stderr)
