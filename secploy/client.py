import threading
import logging
from typing import Any, Dict, Optional, List, Union
import queue

from .lib import setup_logger, load_config, DEFAULT_CONFIG, secploy_logger
from .schemas import SecployConfig, LogLevel
from .log_capture import SecployLogCapturer
from .events import EventHandler
from .processor import EventProcessor

class SecployClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        environment_key: Optional[str] = None,
        organization_id: Optional[str] = None,
        config_file: Optional[str] = None,
        config: Optional[SecployConfig] = DEFAULT_CONFIG,
        log_levels: Optional[List[Union[str, int]]] = None
    ):
        """
        Initialize the Secploy client.

        Args:
            api_key: Optional API key to override configuration
            environment_key: Optional Environment key to override configuration
            organization_id: Optional Organization ID to override configuration
            config_file: Optional path to configuration file
            config: Configuration object, defaults to DEFAULT_CONFIG
        
        Raises:
            ValueError: If required configuration is missing
            TypeError: If configuration values have invalid types
        """
        # Load config from file if provided else it will load from default locations or find .secploy
        config = load_config(config_file)
        
        if config is None:
            secploy_logger.error("No valid configuration found")
            return
            
        # Override api_key if provided directly
        if api_key:
            config.api_key = api_key
        if environment_key:
            config.environment_key = environment_key
        if organization_id:
            config.organization_id = organization_id

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
        if not config.get('api_key'):
            raise ValueError("API key is required")
        if not config.get('environment_key'):
            raise ValueError("Environment key is required")
        if not config.get('organization_id'):
            raise ValueError("Organization ID is required")
        if not config.get('ingest_url'):
            raise ValueError("Ingest URL is required")

        # Set instance attributes from config
        self.api_key = config['api_key']
        self.environment_key = config.get('environment_key')
        self.organization_id = config.get('organization_id')
        self.environment = config.get('environment', 'development')
        self.sampling_rate = config.get('sampling_rate', 1.0)
        self.ingest_url = config['ingest_url'].rstrip("/")
        self.heartbeat_interval = config.get('heartbeat_interval', 60)
        self.max_retry = config.get('max_retry', 5)
        self.debug = config.get('debug', False)
        self.log_level = config.get('log_level', 'INFO')
        
        # Batch processing configuration
        self.batch_size = config.get('batch_size', 100)  # Max events per batch
        self.flush_interval = config.get('flush_interval', 60)  # Max seconds between flushes

        # Initialize internal state
        self._event_queue = queue.Queue()
        self._event_handler = EventHandler(self._event_queue)
        
        # Initialize event processor
        self._event_processor = EventProcessor(
            queue=self._event_queue,
            ingest_url=self.ingest_url,
            headers_callback=self._headers,
            batch_size=self.batch_size,
            flush_interval=self.flush_interval,
            max_retry=self.max_retry
        )
        
        # Setup logging
        if self.debug:
            setup_logger(log_level=self.log_level)
        
        # Initialize log capturer
        self._log_capturer = SecployLogCapturer(self, levels=log_levels)
        
        self.start()
    
    def capture_logs(self, loggers: Union[str, List[str], None] = None):
        """
        Start capturing logs from specified loggers.
        
        Args:
            loggers: Logger name(s) to capture. Can be:
                    - None to capture the root logger
                    - A string for a single logger
                    - A list of logger names
        """
        self._log_capturer.start_capture(loggers)
        secploy_logger.info(f"Started capturing logs from {loggers or 'root'}")
        
    def stop_capturing_logs(self, loggers: Union[str, List[str], None] = None):
        """
        Stop capturing logs from specified loggers.
        
        Args:
            loggers: Logger name(s) to stop capturing
        """
        self._log_capturer.stop_capture(loggers)
        secploy_logger.info(f"Stopped capturing logs from {loggers or 'root'}")
    
    def _headers(self):
        return {
            "X-API-Key": f"{self.api_key}",
            "X-Environment-Key": f"{self.environment_key}",
            "X-Organization-ID": f"{self.organization_id}",
            "Content-Type": "application/json",
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
        return self._event_handler.send_event(event_type, payload)

    def start(self):
        """Start the client's event processing."""
        secploy_logger.info("Starting Secploy client...")
        self._event_processor.start()

    def stop(self):
        """Stop the client and wait for processing to finish."""
        secploy_logger.info("Stopping Secploy client...")
        
        # Stop all log capturing
        if hasattr(self, '_log_capturer'):
            self._log_capturer.stop_all()
        
        # Stop event processing
        self._event_processor.stop()
