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
MULTI_ACCOUNT_RULE_ID = "RULE-ERP-LOGIN-MULTI-ACCOUNT-001"
MULTI_SOURCE_RULE_ID = "RULE-ERP-LOGIN-MULTI-SOURCE-001"
# 새 규칙에서는 실패 횟수 대신 서로 다른 계정명 또는 IP가 3개인지 확인한다.
DISTINCT_FAILURE_THRESHOLD = 3


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


def detect_multi_account_failures(events: list[NormalizedEvent]) -> list[AlertRecord]:
    """같은 IP에서 5분 안에 서로 다른 계정명 3개로 인증에 실패하면 경보를 만든다."""
    # IP별로 기록을 모으고, 각 IP에서 실패한 서로 다른 계정명을 센다.
    return _detect_distinct_failures(
        events, group_by_ip=True, rule_id=MULTI_ACCOUNT_RULE_ID,
        rule_name="같은 출발지에서 여러 계정의 로그인 실패",
    )


def detect_multi_source_failures(events: list[NormalizedEvent]) -> list[AlertRecord]:
    """같은 계정명으로 5분 안에 서로 다른 IP 3곳에서 인증에 실패하면 경보를 만든다."""
    # 계정명별로 기록을 모으고, 그 계정명으로 실패한 서로 다른 IP를 센다.
    return _detect_distinct_failures(
        events, group_by_ip=False, rule_id=MULTI_SOURCE_RULE_ID,
        rule_name="같은 계정에서 여러 출발지의 로그인 실패",
    )


def _detect_distinct_failures(
    events: list[NormalizedEvent], *, group_by_ip: bool, rule_id: str, rule_name: str,
) -> list[AlertRecord]:
    # 바깥 딕셔너리는 IP 또는 계정명으로 묶고, 안쪽은 기록 번호로 중복을 없앤다.
    grouped: dict[str, dict[str, tuple[datetime, str, NormalizedEvent]]] = defaultdict(dict)
    for event in events:
        # ERP의 실제 인증 거부(401) 중 출발지 IP를 신뢰할 수 있는 기록만 고른다.
        if event.source != "erp" or event.status_code != 401 or not _is_trusted_login_failure(event):
            continue
        assert event.client_ip is not None and event.username is not None
        # group은 묶는 기준이고, distinct_value는 중복 없이 셀 값이다.
        group, distinct_value = (event.client_ip, event.username) if group_by_ip else (event.username, event.client_ip)
        grouped[group][event.event_id] = (_parse_utc(event.event_ts_utc), distinct_value, event)

    window = timedelta(seconds=DEFAULT_WINDOW_SECONDS)
    alerts: list[AlertRecord] = []
    for group, events_by_id in sorted(grouped.items()):
        # 먼저 일어난 일부터 본다. 시각이 같으면 기록 번호 순으로 처리한다.
        items = sorted(events_by_id.values(), key=lambda item: (item[0], item[2].event_id))
        latest: dict[str, tuple[datetime, NormalizedEvent]] = {}
        for event_time, distinct_value, event in items:
            # 지금 보는 기록에서 5분보다 오래된 기록은 집계에서 뺀다.
            latest = {
                value: item for value, item in latest.items()
                if event_time - item[0] <= window
            }
            # 같은 계정명 또는 IP가 다시 나오면 최신 기록으로 바꾼다. 개수는 그대로다.
            latest[distinct_value] = (event_time, event)
            if len(latest) < DISTINCT_FAILURE_THRESHOLD:
                continue

            # 기준에 도달한 순간, 서로 다른 값마다 기록 하나씩을 경보 근거로 남긴다.
            evidence = sorted(latest.values(), key=lambda item: (item[0], item[1].event_id))
            # 같은 기록을 다시 읽어도 같은 경보 번호가 나오도록 고정 키를 만든다.
            dedup_raw = f"{rule_id}:{group}:{event.event_id}"
            dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()
            alerts.append(
                AlertRecord(
                    alert_id="ALT-" + dedup_key[:12].upper(),
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity="medium",
                    # 여러 출발지가 얽힌 경우 차단 대상 IP 한 개를 지정하지 않는다.
                    username="" if group_by_ip else group,
                    client_ip=group if group_by_ip else "",
                    window_start_utc=_format_utc(evidence[0][0]),
                    window_end_utc=_format_utc(event_time),
                    failure_count=len(evidence),
                    dedup_key=dedup_key,
                    # 화면에서 어떤 기록으로 경보를 냈는지 원본까지 따라갈 수 있게 한다.
                    evidence_event_ids=tuple(ev.event_id for _, ev in evidence),
                    evidence_raw_ids=tuple(ev.raw_id for _, ev in evidence),
                    ingest_modes=tuple(sorted({ev.ingest_mode for _, ev in evidence})),
                )
            )
            # 이미 경보에 사용한 묶음을 비우고 이후 기록부터 다시 센다.
            latest.clear()

    return alerts
