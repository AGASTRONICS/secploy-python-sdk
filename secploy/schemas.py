from typing import TypedDict, Optional, Union

from .enums import LogLevel


class SecployConfig(TypedDict, total=False):
    api_key: str
    organization_id: str
    environment: str
    ingest_url: str
    heartbeat_interval: int
    max_retry: int
    debug: bool
    sampling_rate: float
    log_level: Union[LogLevel, str]
    batch_size: int
    max_queue_size: int
    flush_interval: int
    retry_attempts: int
    ignore_errors: bool
    source_root: Optional[str]
