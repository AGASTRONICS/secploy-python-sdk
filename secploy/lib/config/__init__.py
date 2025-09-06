"""
Secploy Python SDK Configuration Module

This module handles configuration loading, validation, and management for the Secploy SDK.
Supports multiple configuration formats and environment variable overrides.
"""

import logging
from typing import Dict, Union

from lib.config import load_config, find_project_config, DEFAULT_CONFIG

logger = logging.getLogger(__name__)

__all__ = ['load_config', 'find_project_config', 'DEFAULT_CONFIG', 'validate_config']

def validate_config(config: Dict[str, Union[str, int, float, bool, None]]) -> bool:
    """
    Validates the configuration values.
    Returns True if valid, False otherwise.
    """
    try:
        # Validate sampling rate
        sampling_rate = float(config.get('sampling_rate', 1.0))
        if not 0 <= sampling_rate <= 1:
            raise ValueError("sampling_rate must be between 0 and 1")

        # Validate batch size
        batch_size = int(config.get('batch_size', 100))
        if batch_size < 1:
            raise ValueError("batch_size must be positive")

        # Validate queue size
        max_queue_size = int(config.get('max_queue_size', 10000))
        if max_queue_size < batch_size:
            raise ValueError("max_queue_size must be greater than or equal to batch_size")

        # Validate flush interval
        flush_interval = float(config.get('flush_interval', 5))
        if flush_interval < 0:
            raise ValueError("flush_interval must be non-negative")

        # Validate retry attempts
        retry_attempts = int(config.get('retry_attempts', 3))
        if retry_attempts < 0:
            raise ValueError("retry_attempts must be non-negative")

        # Validate environment
        environment = config.get('environment', 'development')
        if environment not in ['development', 'staging', 'production']:
            raise ValueError("environment must be one of: development, staging, production")

        return True

    except (ValueError, TypeError) as e:
        logger.warning(f"Configuration validation error: {e}")
        return False
