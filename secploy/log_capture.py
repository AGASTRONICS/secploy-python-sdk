"""
Secploy Log Capture Module

This module provides functionality for capturing and forwarding logs to Secploy's ingest endpoint.
"""

import asyncio
import json
import logging
import sys
import threading
import traceback
from typing import Any, Dict, Optional, List, Union
from datetime import datetime
from queue import Queue

from .events import EventHandler
from .schemas import LogEntry, Context, Tags


class SecployLogCapturer:
    """
    Manages log capture and exception forwarding to Secploy ingest endpoint.
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
        self._installed = False
        
    def _create_handler(self) -> logging.Handler:
        """Create the custom logging handler."""
        return SecployLogHandler(self.client, levels=self.levels)

    def start_capture(self, loggers: Union[str, List[str], None] = None):
        """Start capturing logs and exceptions."""
        if self._installed:
            return
        self._installed = True
        
        if isinstance(loggers, str):
            loggers = [loggers]
        elif loggers is None:
            loggers = ['']

        for logger_name in loggers:
            logger = logging.getLogger(logger_name)
            logger.addHandler(self._handler)

        sys.excepthook = self._capture_uncaught_exceptions

        if hasattr(threading, "excepthook"):
            threading.excepthook = self._thread_exception_handler

        try:
            loop = asyncio.get_event_loop()
            loop.set_exception_handler(self._async_exception_handler)
        except RuntimeError:
            pass
            
    def stop_capture(self, loggers: Union[str, List[str], None] = None):
        if isinstance(loggers, str):
            loggers = [loggers]
        elif loggers is None:
            loggers = ['']

        for logger_name in loggers:
            logger = logging.getLogger(logger_name)
            if self._handler in logger.handlers:
                logger.removeHandler(self._handler)
                
    def stop_all(self):
        """Stop all log capturing and exception hooks."""
        for logger in [logging.getLogger(name) for name in logging.root.manager.loggerDict]:
            if self._handler in logger.handlers:
                logger.removeHandler(self._handler)
        if self._handler in logging.root.handlers:
            logging.root.removeHandler(self._handler)

        sys.excepthook = sys.__excepthook__
        if hasattr(threading, "excepthook"):
            threading.excepthook = threading.__excepthook__
        try:
            loop = asyncio.get_event_loop()
            loop.set_exception_handler(None)
        except RuntimeError:
            pass

        self._installed = False
        
    def _capture_uncaught_exceptions(self, exc_type, exc_value, exc_tb):
        self._send_exception(exc_type, exc_value, exc_tb, source="sys")

    def _thread_exception_handler(self, args):
        self._send_exception(args.exc_type, args.exc_value, args.exc_traceback, source="thread")

    def _async_exception_handler(self, loop, context):
        exc = context.get("exception")
        if exc:
            self._send_exception(type(exc), exc, exc.__traceback__, source="asyncio")
        else:
            self._send_exception(RuntimeError, RuntimeError(context["message"]), None, source="asyncio")

    def _send_exception(self, exc_type, exc_value, exc_tb, source="system"):
        stacktrace = traceback.format_exception(exc_type, exc_value, exc_tb)

        log_entry = LogEntry(
            timestamp=datetime.now().timestamp(),
            type="error",
            message=str(exc_value),
            context=Context(
                user_id="unknown",
                session_id="global",
                http_method="NONE",
                http_url="",
                http_status=500,
                stacktrace=stacktrace,
                tags=Tags(
                    environment=self.client.environment,
                    service=f"exception.{source}",
                    region="unknown"
                )
            )
        )
        payload = log_entry.model_dump(mode="json")
        self.client._event_queue.put(("log", payload))


class SecployLogHandler(logging.Handler):
    """
    Custom logging handler that forwards logs to Secploy ingest endpoint.
    """

    def __init__(self, client, levels: Optional[List[Union[str, int]]] = None):
        super().__init__()
        self.client = client
        self._local = threading.local()
        self._event_handler = EventHandler(self.client._event_queue)
        
        # if levels:
        #     self.levels = {
        #         lvl if isinstance(lvl, int) else logging._nameToLevel[lvl.upper()]
        #         for lvl in levels
        #     }
        # else:
        #     self.levels = None  # None = capture all levels
            
    # def filter(self, record: logging.LogRecord) -> bool:
    #     """Return True if this record should be handled."""
    #     if self.levels is None:
    #         return True
    #     return record.levelno in self.levels
        
    def get_thread_id(self) -> str:
        """Get the current thread identifier."""
        return str(threading.get_ident())
        
    def emit(self, record: logging.LogRecord):
        """Send the log record to Secploy ingest."""
        print(f'\n\nLEVEL NAME: {record.levelname} -  LEVEL NO: {record.levelno}\n\n')
        try:
            # Get stacktrace if exception exists
            stacktrace = []
            if record.exc_info:
                stacktrace = traceback.format_exception(*record.exc_info)
            elif record.stack_info:
                stacktrace = [record.stack_info]

            # Build tags with log metadata
            tags = Tags(
                environment=self.client.environment,
                service=record.name,
                region=getattr(record, 'region', 'unknown')
            )

            # Build context
            context = Context(
                user_id=getattr(record, 'user_id', 'unknown'),
                session_id=self.get_thread_id(), 
                http_method=getattr(record, 'http_method', 'NONE'),
                http_status=getattr(record, 'status_code', 0),
                tags=tags,
                http_url=getattr(record, "http_url", getattr(record, "path", "")),
                stacktrace=stacktrace
            )

            # Create LogEntry using our schema
            log_entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created).timestamp(),
                type=record.levelname.lower(),
                message=self.format(record),
                context=context
            )
            payload = log_entry.model_dump(mode="json") 
            self._event_handler.send_event('log', payload)

        except Exception as e:
            # Avoid infinite recursion by using sys.stderr
            import sys
            print(f"Error in SecployLogHandler.emit: {e}", file=sys.stderr)
