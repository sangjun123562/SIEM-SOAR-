from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .models import NormalizedEvent, RawLogRecord

ALLOWED_SOURCES = frozenset({"gateway", "caddy", "erp"})
ALLOWED_INGEST_MODES = frozenset({"live", "replay", "synthetic"})
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "cookie",
        "cookies",
        "set_cookie",
        "authorization",
        "body",
        "request_body",
    }
)


class NormalizationError(ValueError):
    """Raised when a raw log line is malformed or violates log contract rules."""


def compute_raw_id(source: str, file_path: str, line_offset: int, raw_line: str) -> str:
    """Return a deterministic SHA-256 identifier for a raw log line."""
    digest_input = f"{source}:{file_path}:{line_offset}:{raw_line}".encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()


def normalize_utc_timestamp(ts_value: Any) -> str:
    """Parse an ISO-8601 timestamp with timezone and normalize to UTC Z-format."""
    if not isinstance(ts_value, str) or not ts_value.strip():
        raise NormalizationError("timestamp_utc must be a non-empty ISO-8601 string")

    raw_ts = ts_value.strip()
    if raw_ts.endswith("Z"):
        raw_ts = raw_ts[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(raw_ts)
    except ValueError as exc:
        raise NormalizationError(f"invalid timestamp_utc: {ts_value!r}") from exc

    if dt.tzinfo is None:
        raise NormalizationError("timestamp_utc must include explicit timezone (UTC)")

    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _strip_sensitive_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of payload excluding sensitive keys (case-insensitive)."""
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_KEYS:
            continue
        cleaned[key] = value
    return cleaned


def _optional_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise NormalizationError(f"{field_name} must be an integer")
    return value


def normalize_log_line(
    raw_line: str,
    *,
    source: str,
    file_path: str,
    line_offset: int,
    collection_mode: str = "replay",
) -> tuple[RawLogRecord, NormalizedEvent]:
    """Normalize using a collector-configured mode, never the payload alone.

    Default to replay. Only a verified live-source collector may pass live.
    Payload labels can downgrade the classification, never upgrade it.
    """
    if not isinstance(collection_mode, str) or collection_mode not in ALLOWED_INGEST_MODES:
        raise NormalizationError("invalid collection_mode")
    if source not in ALLOWED_SOURCES:
        raise NormalizationError(f"unsupported source: {source!r}")

    stripped = raw_line.rstrip("\r\n")
    if not stripped:
        raise NormalizationError("empty log line")

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise NormalizationError(f"invalid JSON log line: {exc}") from exc

    if not isinstance(payload, dict):
        raise NormalizationError("log line must decode to a JSON object")

    log_source = payload.get("source", source)
    if log_source != source:
        raise NormalizationError(f"source mismatch: expected {source!r}, got {log_source!r}")

    reported_mode = payload.get("ingest_mode", "replay")
    if not isinstance(reported_mode, str) or reported_mode not in ALLOWED_INGEST_MODES:
        raise NormalizationError("invalid ingest_mode")
    if collection_mode == "synthetic" or reported_mode == "synthetic":
        ingest_mode = "synthetic"
    elif collection_mode == "live" and reported_mode == "live":
        ingest_mode = "live"
    else:
        ingest_mode = "replay"

    client_ip_trusted = payload.get("client_ip_trusted", False)
    if type(client_ip_trusted) is not bool:
        raise NormalizationError("client_ip_trusted must be a JSON boolean")

    event_ts_utc = normalize_utc_timestamp(payload.get("timestamp_utc"))
    event_type = payload.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        raise NormalizationError("event_type is required")

    outcome = payload.get("outcome") or payload.get("action")
    if not isinstance(outcome, str) or not outcome:
        raise NormalizationError("outcome (or action) is required")

    cleaned_payload = _strip_sensitive_fields(payload)
    cleaned_payload["ingest_mode"] = ingest_mode  # authoritative collector classification
    sanitized_raw_payload = json.dumps(cleaned_payload, ensure_ascii=False, separators=(",", ":"))
    raw_id = compute_raw_id(source, file_path, line_offset, stripped)
    event_id = hashlib.sha256(f"evt:{raw_id}".encode("utf-8")).hexdigest()

    known_keys = {
        "timestamp_utc",
        "source",
        "event_type",
        "outcome",
        "action",
        "username",
        "client_ip",
        "peer_ip",
        "client_ip_trusted",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "request_id",
        "http_method",
        "http_path",
        "status_code",
        "ingest_mode",
    }
    details = {k: v for k, v in cleaned_payload.items() if k not in known_keys}
    if reported_mode != ingest_mode:
        details["reported_ingest_mode"] = reported_mode

    raw_record = RawLogRecord(
        raw_id=raw_id,
        source=source,
        file_path=file_path,
        line_offset=line_offset,
        raw_payload=sanitized_raw_payload,
        ingest_mode=ingest_mode,
    )

    event = NormalizedEvent(
        event_id=event_id,
        raw_id=raw_id,
        source=source,
        event_ts_utc=event_ts_utc,
        event_type=event_type,
        outcome=outcome,
        username=cleaned_payload.get("username"),
        client_ip=cleaned_payload.get("client_ip"),
        peer_ip=cleaned_payload.get("peer_ip"),
        client_ip_trusted=client_ip_trusted,
        src_ip=cleaned_payload.get("src_ip"),
        src_port=_optional_int(cleaned_payload.get("src_port"), "src_port"),
        dst_ip=cleaned_payload.get("dst_ip"),
        dst_port=_optional_int(cleaned_payload.get("dst_port"), "dst_port"),
        protocol=cleaned_payload.get("protocol"),
        request_id=cleaned_payload.get("request_id"),
        http_method=cleaned_payload.get("http_method"),
        http_path=cleaned_payload.get("http_path"),
        status_code=_optional_int(cleaned_payload.get("status_code"), "status_code"),
        ingest_mode=ingest_mode,
        details=details,
    )
    return raw_record, event
