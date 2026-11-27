from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RawLogRecord:
    """Immutable representation of a single raw log line."""

    raw_id: str
    source: str
    file_path: str
    line_offset: int
    raw_payload: str
    ingest_mode: str = "replay"


@dataclass(frozen=True)
class NormalizedEvent:
    """Common normalized event schema shared across gateway, caddy, and erp logs."""

    event_id: str
    raw_id: str
    source: str
    event_ts_utc: str
    event_type: str
    outcome: str
    username: str | None = None
    client_ip: str | None = None
    peer_ip: str | None = None
    client_ip_trusted: bool = False
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    request_id: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    status_code: int | None = None
    ingest_mode: str = "replay"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CollectionError:
    """Metadata only: never retain the corrupt bytes or exception message."""
    source: str
    file_path: str
    line_offset: int
    byte_length: int
    content_sha256: str
    error_code: str
    ingest_mode: str
