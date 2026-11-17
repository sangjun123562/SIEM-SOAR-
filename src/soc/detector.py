from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import NormalizedEvent

LOGIN_FAILURE_RULE_ID = "RULE-ERP-LOGIN-BRUTE-001"
LOGIN_FAILURE_RULE_NAME = "Repeated Trusted ERP Login Failures"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300


@dataclass(frozen=True)
class AlertRecord:
    """Alert generated when a detection rule triggers."""

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    username: str
    client_ip: str
    window_start_utc: str
    window_end_utc: str
    failure_count: int
    dedup_key: str
    evidence_event_ids: tuple[str, ...]
    evidence_raw_ids: tuple[str, ...]
    ingest_modes: tuple[str, ...]


def _parse_utc(ts_str: str) -> datetime:
    raw = ts_str.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {ts_str!r}")
    return dt.astimezone(timezone.utc)


def _format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _is_trusted_login_failure(event: NormalizedEvent) -> bool:
    if event.event_type != "login_failed":
        return False
    if event.outcome not in {"failure", "failed", "deny"}:
        return False
    if not event.client_ip_trusted:
        return False
    if not event.username or not event.client_ip:
        return False
    return True


def detect_login_failures(
    events: list[NormalizedEvent],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    existing_dedup_keys: set[str] | None = None,
) -> list[AlertRecord]:
    """Detect repeated login failures per trusted (username, client_ip) within a UTC window.

    Produces 0 alerts at threshold - 1 failures, and triggers the first alert at threshold
    failures inside window_seconds. Deduplicates via deterministic dedup_key so re-runs
    do not emit duplicate alerts.
    """
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be >= 1")

    seen_keys = set(existing_dedup_keys) if existing_dedup_keys else set()
    grouped: dict[tuple[str, str], list[tuple[datetime, NormalizedEvent]]] = defaultdict(list)

    for event in events:
        if not _is_trusted_login_failure(event):
            continue
        assert event.username is not None and event.client_ip is not None
        grouped[(event.username, event.client_ip)].append((_parse_utc(event.event_ts_utc), event))

    window = timedelta(seconds=window_seconds)
    alerts: list[AlertRecord] = []

    for (username, client_ip), items in sorted(grouped.items()):
        # Sort chronologically by full UTC timestamp; tie-break by event_id for determinism.
        items.sort(key=lambda pair: (pair[0], pair[1].event_id))

        # Deduplicate identical event_ids in case caller passed overlapping batches.
        unique_items: list[tuple[datetime, NormalizedEvent]] = []
        seen_event_ids: set[str] = set()
        for dt, ev in items:
            if ev.event_id not in seen_event_ids:
                seen_event_ids.add(ev.event_id)
                unique_items.append((dt, ev))

        left = 0
        for right in range(len(unique_items)):
            right_dt, _ = unique_items[right]
            while right_dt - unique_items[left][0] > window:
                left += 1

            window_slice = unique_items[left : right + 1]
            if len(window_slice) < threshold:
                continue

            # Trigger on the exact threshold-th event in the current window.
            evidence = window_slice[:threshold]
            start_dt = evidence[0][0]
            end_dt = evidence[-1][0]
            event_ids = tuple(ev.event_id for _, ev in evidence)
            raw_ids = tuple(ev.raw_id for _, ev in evidence)
            modes = tuple(sorted({ev.ingest_mode for _, ev in evidence}))

            # Deterministic dedup key anchored on rule + (username, client_ip) + first window event.
            dedup_raw = f"{LOGIN_FAILURE_RULE_ID}:{username}:{client_ip}:{event_ids[0]}"
            dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()
            if dedup_key in seen_keys:
                continue

            seen_keys.add(dedup_key)
            alert_id = "ALT-" + dedup_key[:12].upper()
            alerts.append(
                AlertRecord(
                    alert_id=alert_id,
                    rule_id=LOGIN_FAILURE_RULE_ID,
                    rule_name=LOGIN_FAILURE_RULE_NAME,
                    severity="high",
                    username=username,
                    client_ip=client_ip,
                    window_start_utc=_format_utc(start_dt),
                    window_end_utc=_format_utc(end_dt),
                    failure_count=len(evidence),
                    dedup_key=dedup_key,
                    evidence_event_ids=event_ids,
                    evidence_raw_ids=raw_ids,
                    ingest_modes=modes,
                )
            )
            # Advance left past the triggered window so one burst emits one alert.
            left = right + 1

    return alerts
