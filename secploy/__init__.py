"""
Secploy SDK - Event tracking and monitoring for Python applications
"""

from .client import SecployClient
from .schemas import SecployConfig
from .schemas import LogLevel

__version__ = "0.2.5"
__author__ = "Agastronics"
__email__ = "support@agastronics.com"
__description__ = "Event tracking and monitoring SDK for Python applications"

__all__ = [
    "SecployClient",
    "SecployConfig",
    "LogLevel",
]

def cli():
    """Command-line interface for the Secploy SDK."""
    import argparse
    
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('--version', action='version', version=f'Secploy SDK v{__version__}')
    parser.add_argument('--test-config', help='Test a configuration file', metavar='CONFIG_FILE')
    
    args = parser.parse_args()
    
    if args.test_config:
        from .lib.config import load_config
        try:
            config = load_config(args.test_config)
            print("Configuration loaded successfully:")
            for key, value in config.items():
                print(f"  {key}: {value}")
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return 1
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(cli())