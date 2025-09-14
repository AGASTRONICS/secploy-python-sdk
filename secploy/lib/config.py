"""
Secploy Python SDK Configuration Module

This module handles configuration loading, validation, and management for the Secploy SDK.
Supports multiple configuration formats and environment variable overrides.
"""

import yaml  # For YAML file handling
import json  # For JSON file handling
import os    # For path checks
import glob  # For finding config files
import logging
from typing import Dict, Optional, Union

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "api_key": None,
    "environment_key": None,
    "organization_id": None,
    "environment": "development",
    "sampling_rate": 1.0,
    "log_level": "INFO",
    "batch_size": 100,
    "max_queue_size": 10000,
    "flush_interval": 5,
    "retry_attempts": 3,
    "ignore_errors": True,
    "source_root": None,
    "heartbeat_interval": 60,
    "max_retry": 5,
    "debug": False,
    "ingest_url": "https://ingest.secploy.com",
}

def find_project_config() -> Optional[str]:
    """
    Look for .secploy or {project-name}.secploy config files in the current directory
    and its parent directories up to the root.
    """
    current_dir = os.getcwd()
    project_name = os.path.basename(current_dir)
    
    while current_dir != '/':
        # Check for .secploy file
        default_config = os.path.join(current_dir, '.secploy')
        if os.path.isfile(default_config):
            return default_config
            
        # Check for project-specific .secploy file
        project_config = os.path.join(current_dir, f'{project_name}.secploy')
        if os.path.isfile(project_config):
            return project_config
            
        # Check for any *.secploy file
        secploy_files = glob.glob(os.path.join(current_dir, '*.secploy'))
        if secploy_files:
            return secploy_files[0]
            
        # Move up one directory
        parent = os.path.dirname(current_dir)
        if parent == current_dir:
            break
        current_dir = parent
            
    return None

def load_config(file_path: Optional[str] = None) -> Dict[str, Union[str, int, float, bool, None]]:
    """
    Load configuration from YAML, JSON, CONF, or .secploy formats.
    If no file_path is provided, attempts to find a .secploy config file.
    Falls back to environment variables and defaults if no config file is found.
    """
    config = DEFAULT_CONFIG.copy()
    
    # If no file_path provided, try to find a config file
    if not file_path:
        file_path = find_project_config()
        
    if file_path and os.path.exists(file_path):
        logger.info(f"Loading configuration from {file_path}")

    # Load from file if it exists
    if file_path:
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                try:
                    # Try YAML parsing first (works for both .yml and .secploy)
                    file_config = yaml.safe_load(content)
                    if file_config is None:  # Empty file
                        file_config = {}
                    logger.info("Loaded YAML configuration.")
                except yaml.YAMLError:
                    # If YAML parsing fails, try JSON
                    try:
                        file_config = json.loads(content)
                        logger.info("Loaded JSON configuration.")
                    except json.JSONDecodeError:
                        # Finally, try key=value format
                        file_config = {}
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if '=' in line:
                                    key, value = line.split('=', 1)
                                    key = key.strip().lower()
                                    value = value.strip()
                                elif ':' in line:
                                    key, value = line.split(':', 1)
                                    key = key.strip().lower()
                                    value = value.strip()
                                else:
                                    continue

                                # Type conversion
                                if value.lower() == 'true':
                                    value = True
                                elif value.lower() == 'false':
                                    value = False
                                elif value.isdigit():
                                    value = int(value)
                                elif value.replace('.', '').isdigit() and value.count('.') == 1:
                                    value = float(value)
                                
                                file_config[key] = value
                        logger.info("Loaded key-value configuration.")
                
                # Update config with file values
                config.update(file_config)
        except Exception as e:
            logger.warning(f"Error loading config file: {e}")
            
    # Override with environment variables
    env_prefix = "SECPLOY_"
    for key in DEFAULT_CONFIG:
        env_key = f"{env_prefix}{key.upper()}"
        if env_key in os.environ:
            value = os.environ[env_key]
            
            # Type conversion for environment variables
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            elif value.replace('.', '').isdigit() and value.count('.') == 1:
                value = float(value)
                
            config[key] = value
            logger.debug(f"Using environment variable {env_key}")
            
    # Validate required settings
    if not config.get('api_key'):
        # Try to get from environment without prefix
        config['api_key'] = os.getenv('SECPLOY_API_KEY')
        if not config['api_key']:
            logger.warning("No API key provided. Secploy will be disabled.")
            
    return config


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
