from typing import Any, Dict, TypedDict, Optional, Union, List
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from .enums import LogLevel


class SecployConfig(TypedDict, total=False):
    api_key: str
    environment_key: str
    organization_id: str
    environment: str
    ingest_url: str
    api_url: str
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
    instrument_outbound_requests: bool
    instrument_httpx_async: bool
    auto_dependency_report: bool
    dependency_report_limit: int
    dependency_report_incidents_limit: int
    dependency_report_include_current_issues: bool
    dependency_report_include_latest_issues: bool


class SecurityControlActionRequest(TypedDict, total=False):
    action_type: str
    target_type: str
    target: str
    reason: str
    identity_key: str
    session_id: str
    auth_provider: str
    risk_score: float
    expires_at: str
    metadata: Dict[str, Any]


class SecurityGateAuthContext(TypedDict, total=False):
    identity_key: str
    session_id: str
    auth_provider: str
    authorization_scheme: str
    user_id: str
    remote_addr: str


class SecurityGateDecision(TypedDict, total=False):
    allowed: bool
    blocked: bool
    method: str
    endpoint: str
    url: str
    reason: str
    rule: Dict[str, Any]
    controls: List[Dict[str, Any]]
    auth: SecurityGateAuthContext
    metadata: Dict[str, Any]
    raw: Dict[str, Any]


class DependencyIssue(TypedDict, total=False):
    id: str
    summary: str
    details: str
    published: str
    modified: str
    aliases: List[str]
    severity: List[Dict[str, Any]]
    references: List[Dict[str, Any]]


class DependencyHealthItem(TypedDict, total=False):
    name: str
    current_version: str
    latest_version: Optional[str]
    is_outdated: bool
    latest_check_error: Optional[str]
    has_current_issues: bool
    current_issue_count: int
    has_latest_issues: bool
    latest_issue_count: int
    recent_incidents: List[DependencyIssue]


class DependencyHealthSummary(TypedDict, total=False):
    total_dependencies: int
    outdated_dependencies: int
    dependencies_with_current_issues: int
    dependencies_with_latest_issues: int


class DependencyHealthReport(TypedDict, total=False):
    summary: DependencyHealthSummary
    dependencies: List[DependencyHealthItem]


class Tags(BaseModel):
    environment: str
    service: str
    region: str

    model_config = ConfigDict(extra="allow")


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
