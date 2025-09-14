from typing import TypedDict, Optional, Union, List
from datetime import datetime
from pydantic import BaseModel, Extra
from .enums import LogLevel


class SecployConfig(TypedDict, total=False):
    api_key: str
    environment_key: str
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


class Tags(BaseModel):
    environment: str
    service: str
    region: str

    class Config:
        extra = Extra.allow  # Allow additional fields in tags


class Context(BaseModel):
    user_id: str
    session_id: str
    http_method: str
    http_url: str
    http_status: int
    stacktrace: List[str]
    tags: Tags


class LogEntry(BaseModel):
    timestamp: datetime
    type: str
    message: str
    context: Context
