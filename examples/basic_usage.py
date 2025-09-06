"""
Secploy SDK Example Usage

This example shows how to initialize and use the Secploy SDK with configuration.
"""

from secploy import SecployClient, SecployConfig, LogLevel


# Initialize with config file (.secploy)
client = SecployClient()  # Automatically looks for .secploy file

custom_config = SecployConfig(
    api_key="your-key",
    environment="production",
    log_level=LogLevel.INFO,
    batch_size=100
)

# Or initialize with manual configuration
client = SecployClient(config=custom_config)

# Log an event
client.log_event(
    event_type="error",
    message="Database connection failed",
    context={
        "db_host": "db.example.com",
        "db_port": 5432,
        "error_code": "ECONNREFUSED"
    }
)

# Example .secploy file:
"""
api_key=your_api_key_here
environment=development
sampling_rate=0.1
batch_size=50
max_queue_size=5000
flush_interval=10
ignore_errors=true
log_level=INFO
heartbeat_interval=60
max_retry=5
debug=false
ingest_url=https://ingest.secploy.com
"""
