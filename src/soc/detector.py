from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import NormalizedEvent

LOGIN_FAILURE_RULE_ID = "RULE-ERP-LOGIN-BRUTE-001"
LOGIN_FAILURE_RULE_NAME = "Repeated Trusted ERP Login Failures"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300
MULTI_ACCOUNT_RULE_ID = "RULE-ERP-LOGIN-MULTI-ACCOUNT-001"
MULTI_SOURCE_RULE_ID = "RULE-ERP-LOGIN-MULTI-SOURCE-001"
LOGIN_SUCCESS_REVIEW_RULE_ID = "RULE-ERP-LOGIN-SUCCESS-AFTER-FAILURES-001"
LOGIN_SUCCESS_REVIEW_MIN_FAILURES = 3
LOGIN_SOURCE_CHANGE_RULE_ID = "RULE-ERP-LOGIN-SUCCESS-FROM-DIFFERENT-IP-001"
LOGIN_SOURCE_DENIED_RULE_ID = "RULE-ERP-LOGIN-SOURCE-DENIED-001"
LOGIN_FAILURE_REVIEW_RULE_ID = "RULE-ERP-LOGIN-THREE-FAILURES-001"
X_LOGIN_IP = "172.28.10.13"
LOGIN_REQUEST_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
# 새 규칙에서는 실패 횟수 대신 서로 다른 계정명 또는 IP가 3개인지 확인한다.
DISTINCT_FAILURE_THRESHOLD = 3
# ERP 자료실에서 같은 계정·출발지가 5분 안에 문서 열람을 3번 이상 거부당하면(403 권한 없음, 404 없는 문서) 경보를 만든다.
DOC_DENIED_RULE_ID = "RULE-ERP-DOC-DENIED-001"
DOC_DENIED_RULE_NAME = "Repeated ERP Document Access Denials"
DOC_DENIED_THRESHOLD = 3


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


def is_x_login_denial(event: NormalizedEvent) -> bool:
    return (
        event.source == "erp" and event.event_type == "login_source_denied"
        and event.outcome == "failure" and event.status_code == 403
        and event.client_ip_trusted and event.client_ip == X_LOGIN_IP
        and event.http_method == "POST" and event.http_path == "/api/login"
        and event.details.get("reason") == "source_not_allowed"
        and bool(LOGIN_REQUEST_ID.fullmatch(event.request_id or ""))
    )


def detect_login_source_denials(events: list[NormalizedEvent]) -> list[AlertRecord]:
    # Caddy 요청 번호가 같은 기록은 한 사건으로 연결한다.
    by_request: dict[str, NormalizedEvent] = {}
    for event in events:
        if is_x_login_denial(event) and event.request_id:
            existing = by_request.get(event.request_id)
            if existing is None or (existing.ingest_mode != "live" and event.ingest_mode == "live"):
                by_request[event.request_id] = event
    alerts = []
    for request_id, event in by_request.items():
        key = f"{LOGIN_SOURCE_DENIED_RULE_ID}:{request_id}"
        alerts.append(AlertRecord(
            alert_id="ALT-" + hashlib.sha256(key.encode()).hexdigest()[:12].upper(),
            rule_id=LOGIN_SOURCE_DENIED_RULE_ID, rule_name="비인가 IP에서 ERP 로그인 시도",
            severity="medium", username=event.username or "", client_ip=X_LOGIN_IP,
            window_start_utc=event.event_ts_utc, window_end_utc=event.event_ts_utc,
            failure_count=1, dedup_key=key, evidence_event_ids=(event.event_id,),
            evidence_raw_ids=(event.raw_id,), ingest_modes=(event.ingest_mode,),
        ))
    return alerts


def _is_locked_account_failure(event: NormalizedEvent) -> bool:
    # 잠긴 계정에 틀린 비밀번호를 넣은 시도. ERP는 잠금 안내만 보내지만 관제는 인증 실패로 센다.
    return (
        event.event_type == "login_blocked" and event.status_code == 403
        and event.details.get("reason") == "account_locked"
        and event.details.get("password_valid") is False
    )


def _is_trusted_login_failure(event: NormalizedEvent) -> bool:
    # 400은 입력 형식 오류이고, 401과 잠긴 계정의 틀린 비밀번호만 ERP가 계정 인증을 실제로 거부한 기록이다.
    if event.source != "erp":
        return False
    if not ((event.event_type == "login_failed" and event.status_code == 401)
            or _is_locked_account_failure(event)):
        return False
    if event.outcome not in {"failure", "failed", "deny"}:
        return False
    if not event.client_ip_trusted:
        return False
    if not event.username or not event.client_ip:
        return False
    return True


def _is_trusted_login_success(event: NormalizedEvent) -> bool:
    """ERP에서 신뢰된 출발지의 계정 인증이 성공했는지 확인한다."""
    return (
        event.source == "erp" and event.event_type == "login_success"
        and event.status_code == 200 and event.outcome == "success"
        and event.client_ip_trusted and bool(event.username) and bool(event.client_ip)
    )


def _build_login_success_review(
    failures: list[tuple[datetime, NormalizedEvent]],
    success_time: datetime,
    success: NormalizedEvent,
    *,
    different_source: bool = False,
) -> AlertRecord:
    """실패 3~4건과 그 뒤의 로그인 성공 1건을 묶어 주의 경보 하나를 만든다."""
    if different_source:
        rule_id = LOGIN_SOURCE_CHANGE_RULE_ID
        rule_name = "주의 · 반복 실패 후 다른 출발지에서 로그인 성공"
        # 실패 지점과 성공 지점이 다르면 사건 하나에 대상 IP를 하나만 지정하지 않는다.
        client_ip = ""
    else:
        rule_id = LOGIN_SUCCESS_REVIEW_RULE_ID
        rule_name = "주의 · 반복 실패 후 로그인 성공"
        client_ip = success.client_ip or ""

    # 성공 기록 번호가 기준이라 로그를 다시 읽어도 같은 주의 사건으로 저장된다.
    dedup_key = hashlib.sha256(f"{rule_id}:{success.event_id}".encode("utf-8")).hexdigest()
    evidence = [event for _, event in failures] + [success]
    return AlertRecord(
        alert_id="ALT-" + dedup_key[:12].upper(),
        rule_id=rule_id,
        rule_name=rule_name,
        severity="medium",
        username=success.username or "",
        client_ip=client_ip,
        window_start_utc=_format_utc(failures[0][0]),
        window_end_utc=_format_utc(success_time),
        failure_count=len(failures),
        dedup_key=dedup_key,
        # 실패와 성공을 모두 남겨 담당자가 원본에서 순서를 확인할 수 있게 한다.
        evidence_event_ids=tuple(event.event_id for event in evidence),
        evidence_raw_ids=tuple(event.raw_id for event in evidence),
        ingest_modes=(success.ingest_mode,),
    )


def _is_trusted_document_denial(event: NormalizedEvent) -> bool:
    """로그인한 계정이 문서 열람을 거부당한 기록(403·404)인지 확인한다. 비로그인(401)은 계정이 없어 제외한다."""
    return (
        event.source == "erp" and event.event_type == "document_read"
        and event.status_code in {403, 404} and event.outcome in {"failure", "failed", "deny"}
        and event.client_ip_trusted and bool(event.username) and bool(event.client_ip)
    )


def detect_document_access_denials(
    events: list[NormalizedEvent],
    *,
    threshold: int = DOC_DENIED_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[AlertRecord]:
    """같은 (계정, 출발지 IP)가 window_seconds 안에 문서 열람을 threshold번 이상 거부당하면 경보를 만든다.

    남의 부서 문서나 없는 문서 번호를 계속 열어 보는 행동(권한 탐색, IDOR 시도)을 잡는다.
    경보에 쓴 기록은 다음 묶음에서 다시 세지 않고, 같은 로그를 다시 읽어도 같은 경보 번호가 나온다.
    """
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be >= 1")
    grouped: dict[tuple[str, str], dict[str, tuple[datetime, NormalizedEvent]]] = defaultdict(dict)
    for event in events:
        if not _is_trusted_document_denial(event):
            continue
        assert event.username is not None and event.client_ip is not None
        grouped[(event.username, event.client_ip)][event.event_id] = (_parse_utc(event.event_ts_utc), event)

    window = timedelta(seconds=window_seconds)
    alerts: list[AlertRecord] = []
    for (username, client_ip), by_id in sorted(grouped.items()):
        items = sorted(by_id.values(), key=lambda pair: (pair[0], pair[1].event_id))
        pending: list[tuple[datetime, NormalizedEvent]] = []
        for event_time, event in items:
            pending = [(t, e) for t, e in pending if event_time - t <= window]
            pending.append((event_time, event))
            if len(pending) < threshold:
                continue
            evidence = pending[:threshold]
            event_ids = tuple(ev.event_id for _, ev in evidence)
            dedup_key = hashlib.sha256(
                f"{DOC_DENIED_RULE_ID}:{username}:{client_ip}:{event_ids[0]}".encode("utf-8")
            ).hexdigest()
            alerts.append(
                AlertRecord(
                    alert_id="ALT-" + dedup_key[:12].upper(),
                    rule_id=DOC_DENIED_RULE_ID,
                    rule_name=DOC_DENIED_RULE_NAME,
                    # 정상 업무 중 실수로도 생길 수 있어 조사가 필요한 수준(medium)으로 둔다.
                    severity="medium",
                    username=username,
                    client_ip=client_ip,
                    window_start_utc=_format_utc(evidence[0][0]),
                    window_end_utc=_format_utc(evidence[-1][0]),
                    failure_count=len(evidence),
                    dedup_key=dedup_key,
                    evidence_event_ids=event_ids,
                    evidence_raw_ids=tuple(ev.raw_id for _, ev in evidence),
                    ingest_modes=tuple(sorted({ev.ingest_mode for _, ev in evidence})),
                )
            )
            pending.clear()
    return alerts


def detect_login_failure_reviews(
    events: list[NormalizedEvent], *, window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[AlertRecord]:
    """같은 ERP 계정의 최근 5분 안 연속 실패가 세 번이 되면 관찰 사건을 만든다.

    팀 합의대로 출발지 IP와 관계없이 계정 단위로 센다(A 2회 + B 1회도 3회).
    어느 IP에서든 로그인에 성공하면 연속이 끊긴다. IP를 막는 5회 차단 규칙은 계속 IP별로 센다.
    """
    grouped = defaultdict(dict)
    for event in events:
        if _is_trusted_login_failure(event) or _is_trusted_login_success(event):
            key = (event.username, event.ingest_mode)
            grouped[key][event.event_id] = (_parse_utc(event.event_ts_utc), event)

    alerts = []
    window = timedelta(seconds=window_seconds)
    for (username, mode), by_id in grouped.items():
        recent = deque(maxlen=3)
        reported = False
        for stamp, event in sorted(by_id.values(), key=lambda item: (item[0], item[1].event_id)):
            if event.event_type == "login_success" or (recent and stamp - recent[-1][0] > window):
                recent.clear()
                reported = False
            if event.event_type == "login_success":
                continue
            while recent and stamp - recent[0][0] > window:
                recent.popleft()
            recent.append((stamp, event))
            if reported or len(recent) != 3:
                continue
            # 같은 연속 시도는 한 번만 표시하고 5회 규칙은 별도로 작동한다.
            reported = True
            # IP가 하나면 그 IP를, 여러 개면 비워 두어 화면에 '여러 출발지'로 표시한다.
            ips = {item.client_ip for _, item in recent}
            ip = ips.pop() if len(ips) == 1 else ""
            key = f"{LOGIN_FAILURE_REVIEW_RULE_ID}:{recent[0][1].event_id}"
            alerts.append(AlertRecord(
                alert_id="ALT-" + hashlib.sha256(key.encode()).hexdigest()[:12].upper(),
                rule_id=LOGIN_FAILURE_REVIEW_RULE_ID, rule_name="관찰 · 로그인 3회 연속 실패",
                severity="medium", username=username, client_ip=ip,
                window_start_utc=_format_utc(recent[0][0]), window_end_utc=_format_utc(stamp),
                failure_count=3, dedup_key=key,
                evidence_event_ids=tuple(item.event_id for _, item in recent),
                evidence_raw_ids=tuple(item.raw_id for _, item in recent), ingest_modes=(mode,),
            ))
    return alerts


def detect_login_failures(
    events: list[NormalizedEvent],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    existing_dedup_keys: set[str] | None = None,
    include_success_reviews: bool = False,
) -> list[AlertRecord]:
    """Detect repeated login failures per trusted (username, client_ip) within a UTC window.

    같은 계정과 IP에서 인증에 성공하면 같은 수집 방식으로 기록된 앞선 실패 묶음을 끊는다.
    기준에 도달해 이미 만들어진 경보는 이후 성공과 별개로 유지한다.
    """
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be >= 1")

    seen_keys = set(existing_dedup_keys) if existing_dedup_keys else set()
    grouped: dict[tuple[str, str], list[tuple[datetime, NormalizedEvent]]] = defaultdict(list)

    for event in events:
        if not _is_trusted_login_failure(event) and not _is_trusted_login_success(event):
            continue
        assert event.username is not None and event.client_ip is not None
        grouped[(event.username, event.client_ip)].append((_parse_utc(event.event_ts_utc), event))

    window = timedelta(seconds=window_seconds)
    success_review_limit = min(threshold, DEFAULT_THRESHOLD)
    alerts: list[AlertRecord] = []

    for (username, client_ip), items in sorted(grouped.items()):
        # 시각이 같으면 실패를 먼저 확인한다. 기록만으로 어느 쪽이 먼저였는지 알 수 없기 때문이다.
        items.sort(key=lambda pair: (pair[0], pair[1].event_type == "login_success", pair[1].event_id))

        # Deduplicate identical event_ids in case caller passed overlapping batches.
        unique_items: list[tuple[datetime, NormalizedEvent]] = []
        seen_event_ids: set[str] = set()
        for dt, ev in items:
            if ev.event_id not in seen_event_ids:
                seen_event_ids.add(ev.event_id)
                unique_items.append((dt, ev))

        pending_failures: list[tuple[datetime, NormalizedEvent]] = []
        last_alert_time_by_mode: dict[str, datetime] = {}
        for event_time, event in unique_items:
            # 오래된 실패는 빼고, 성공이 들어오면 같은 수집 방식의 앞선 실패 묶음을 끝낸다.
            # 재생 기록의 성공이나 같은 시각의 성공은 실제 실패를 지울 근거로 쓰지 않는다.
            recent_failures = []
            failures_before_success = []
            for failure_time, failure in pending_failures:
                if event_time - failure_time > window:
                    continue
                if (event.event_type == "login_success" and failure_time < event_time
                        and failure.ingest_mode == event.ingest_mode):
                    failures_before_success.append((failure_time, failure))
                    continue
                recent_failures.append((failure_time, failure))
            pending_failures = recent_failures

            if event.event_type == "login_success":
                # 같은 묶음에서 이미 반복 실패 경보가 났다면 주의 사건을 하나 더 만들지 않는다.
                last_alert_time = last_alert_time_by_mode.pop(event.ingest_mode, None)
                already_alerted = last_alert_time is not None and event_time - last_alert_time <= window
                if not include_success_reviews or already_alerted:
                    continue

                # 앞서 확인한 실패가 3~4회일 때만 성공 기록을 주의 사건으로 남긴다.
                failure_count = len(failures_before_success)
                if LOGIN_SUCCESS_REVIEW_MIN_FAILURES <= failure_count < success_review_limit:
                    review = _build_login_success_review(failures_before_success, event_time, event)
                    if review.dedup_key not in seen_keys:
                        alerts.append(review)
                        seen_keys.add(review.dedup_key)
                continue
            pending_failures.append((event_time, event))
            if len(pending_failures) < threshold:
                continue

            # 기준에 도달하면 그때까지 모은 실패로 바로 경보를 만든다.
            evidence = pending_failures[:threshold]
            start_dt = evidence[0][0]
            end_dt = evidence[-1][0]
            event_ids = tuple(ev.event_id for _, ev in evidence)
            raw_ids = tuple(ev.raw_id for _, ev in evidence)
            modes = tuple(sorted({ev.ingest_mode for _, ev in evidence}))
            for mode in modes:
                last_alert_time_by_mode[mode] = end_dt

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
            # 경보에 사용한 실패는 다음 묶음에서 다시 세지 않는다.
            pending_failures.clear()

    return alerts


def detect_login_success_from_different_source(
    events: list[NormalizedEvent], *, window_seconds: int = DEFAULT_WINDOW_SECONDS,
    failure_threshold: int = DEFAULT_THRESHOLD,
) -> list[AlertRecord]:
    """한 출발지에서 실패 3~4회 뒤 다른 출발지에서 성공한 로그를 조사 대상으로 남긴다."""
    # 이미 5회 반복 실패 경보의 근거가 된 실패는 그 사건에서 확인한다. 주의 사건을 하나 더 만들지 않는다.
    alerted_failure_ids = set()
    for alert in detect_login_failures(events, threshold=failure_threshold, window_seconds=window_seconds):
        for event_id in alert.evidence_event_ids:
            alerted_failure_ids.add(event_id)

    # 같은 계정의 흐름만 이어 본다. 실제 기록과 재생 기록은 같은 묶음에 넣지 않는다.
    grouped: dict[tuple[str, str], dict[str, tuple[datetime, NormalizedEvent]]] = defaultdict(dict)
    for event in events:
        if not _is_trusted_login_failure(event) and not _is_trusted_login_success(event):
            continue
        assert event.username is not None
        key = (event.username, event.ingest_mode)
        grouped[key][event.event_id] = (_parse_utc(event.event_ts_utc), event)

    window = timedelta(seconds=window_seconds)
    # 기존 규칙이 더 낮은 기준으로 동작하는 경우에도 같은 실패로 경보를 겹쳐 만들지 않는다.
    review_limit = min(failure_threshold, DEFAULT_THRESHOLD)
    alerts = []
    for events_by_id in grouped.values():
        # 같은 시각의 실패를 성공 전 근거에 넣지 않도록, 시각이 같으면 성공을 먼저 확인한다.
        items = sorted(
            events_by_id.values(),
            key=lambda item: (item[0], item[1].event_type != "login_success", item[1].event_id),
        )
        pending: list[tuple[datetime, NormalizedEvent]] = []
        for event_time, event in items:
            recent = []
            for failure_time, failure in pending:
                if event_time - failure_time <= window:
                    recent.append((failure_time, failure))
            pending = recent

            if event.event_type != "login_success":
                pending.append((event_time, event))
                # 다섯 건 이상인지 알 수 있으면 충분하다. 오래된 근거를 계속 쌓지 않는다.
                pending = pending[-DEFAULT_THRESHOLD:]
                continue

            # 성공을 확인하면 앞선 실패 묶음은 끝낸다. 다음 기록부터 다시 센다.
            before_success = pending
            pending = []
            if not LOGIN_SUCCESS_REVIEW_MIN_FAILURES <= len(before_success) < review_limit:
                continue

            failure_ip = before_success[0][1].client_ip
            if failure_ip == event.client_ip:
                # 같은 IP에서 성공한 경우는 이미 있는 주의 규칙에서 처리한다.
                continue

            # 실패가 모두 한 IP에서 나왔을 때만 "출발지가 바뀌었다"고 판단한다.
            # 5회 경보에 이미 쓴 실패가 섞여 있으면 첫 실패가 5분을 넘겨 4회로 보여도 기존 사건으로 본다.
            same_failure_ip = True
            already_alerted = False
            for _, failure in before_success:
                if failure.client_ip != failure_ip:
                    same_failure_ip = False
                if failure.event_id in alerted_failure_ids:
                    already_alerted = True
            if same_failure_ip and not already_alerted:
                alerts.append(_build_login_success_review(before_success, event_time, event, different_source=True))

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
    """두 추가 규칙이 함께 쓰는 집계 함수.

    group_by_ip=True  → IP별로 묶고, 그 IP에서 실패한 '서로 다른 계정명'을 센다. (추가 1)
    group_by_ip=False → 계정명별로 묶고, 그 계정명이 실패한 '서로 다른 IP'를 센다. (추가 2)
    """
    # [1단계] 셀 대상 기록만 골라 묶음별로 모은다.
    # grouped 모양: {묶음 기준: {기록 번호: (시각, 셀 값, 기록)}}
    # 기록 번호를 키로 쓰므로 같은 기록이 두 번 들어와도 한 번만 남는다.
    # defaultdict(dict)는 처음 보는 묶음 기준이면 빈 딕셔너리를 자동으로 만들어 준다.
    grouped: dict[str, dict[str, tuple[datetime, str, NormalizedEvent]]] = defaultdict(dict)
    for event in events:
        # ERP가 인증을 거부한(401) 기록 중 출발지 IP를 믿을 수 있는 것만 센다.
        # 입력 형식 오류(400), 다른 장비의 기록, 미신뢰 IP는 여기서 건너뛴다.
        if not _is_trusted_login_failure(event):
            continue
        # 바로 위 검사에서 계정명과 IP가 비어 있지 않음을 확인했다. 그 사실을 코드에 적어 둔다.
        assert event.client_ip is not None and event.username is not None

        # group은 '무엇끼리 묶을지', distinct_value는 '그 안에서 무엇을 중복 없이 셀지'이다.
        if group_by_ip:
            group = event.client_ip
            distinct_value = event.username
        else:
            group = event.username
            distinct_value = event.client_ip
        grouped[group][event.event_id] = (_parse_utc(event.event_ts_utc), distinct_value, event)

    # [2단계] 묶음마다 시간순으로 훑으며, 최근 5분 안의 서로 다른 값이 3개가 되는지 본다.
    window = timedelta(seconds=DEFAULT_WINDOW_SECONDS)
    alerts: list[AlertRecord] = []
    for group, events_by_id in sorted(grouped.items()):
        # 먼저 일어난 일부터 본다. item[0]은 시각, item[2]는 기록이다.
        # 시각이 같으면 기록 번호 순으로 처리해서 언제 실행해도 결과가 같게 한다.
        items = sorted(events_by_id.values(), key=lambda item: (item[0], item[2].event_id))

        # latest 모양: {셀 값: (그 값의 가장 최근 실패 시각, 기록)}
        # 키가 셀 값이므로 len(latest)가 곧 '서로 다른 계정명(또는 IP)의 개수'이다.
        latest: dict[str, tuple[datetime, NormalizedEvent]] = {}
        for event_time, distinct_value, event in items:
            # 지금 기록보다 5분 넘게 오래된 값은 빼고, 최근 5분 안의 값만 남긴다.
            still_recent: dict[str, tuple[datetime, NormalizedEvent]] = {}
            for value, (value_time, value_event) in latest.items():
                if event_time - value_time <= window:
                    still_recent[value] = (value_time, value_event)
            latest = still_recent

            # 같은 계정명(또는 IP)이 다시 나오면 기존 키를 덮어쓴다. 그래서 개수는 늘지 않는다.
            latest[distinct_value] = (event_time, event)
            if len(latest) < DISTINCT_FAILURE_THRESHOLD:
                continue

            # [3단계] 서로 다른 값이 3개가 된 순간 경보를 만든다.
            # 값마다 가장 최근 기록 하나씩을 시간순으로 정리해 경보 근거로 남긴다.
            evidence = sorted(latest.values(), key=lambda item: (item[0], item[1].event_id))
            # 규칙 + 묶음 기준 + 마지막 기록 번호로 고정 키를 만든다.
            # 같은 로그를 다시 읽어도 같은 키가 나오므로 사건이 중복 저장되지 않는다.
            dedup_raw = f"{rule_id}:{group}:{event.event_id}"
            dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()
            alerts.append(
                AlertRecord(
                    alert_id="ALT-" + dedup_key[:12].upper(),
                    rule_id=rule_id,
                    rule_name=rule_name,
                    # 기존 반복 실패 규칙(high)보다 낮다. 공유 IP나 이동 근무처럼 정상 사용으로도
                    # 생길 수 있어 담당자가 조사해야 하는 사건이기 때문이다.
                    severity="medium",
                    # 값이 여러 개인 쪽은 하나로 정할 수 없어 비워 둔다. 화면에는 '여러 계정'·'여러 출발지'로 나온다.
                    # 추가 1(같은 IP): 계정명이 여러 개 → username을 비우고 client_ip에 그 IP를 넣는다.
                    # 추가 2(같은 계정명): IP가 여러 개 → client_ip를 비우고 username에 그 계정명을 넣는다.
                    username="" if group_by_ip else group,
                    client_ip=group if group_by_ip else "",
                    # 관측 시간대: 근거 중 가장 이른 실패 ~ 3번째 값이 나온 지금 기록
                    window_start_utc=_format_utc(evidence[0][0]),
                    window_end_utc=_format_utc(event_time),
                    # 새 규칙에서는 실패 횟수가 아니라 서로 다른 계정명(또는 IP)의 개수이다.
                    failure_count=len(evidence),
                    dedup_key=dedup_key,
                    # 화면에서 어떤 기록으로 경보를 냈는지 원본까지 따라갈 수 있게 한다.
                    evidence_event_ids=tuple(ev.event_id for _, ev in evidence),
                    evidence_raw_ids=tuple(ev.raw_id for _, ev in evidence),
                    ingest_modes=tuple(sorted({ev.ingest_mode for _, ev in evidence})),
                )
            )
            # 이미 경보에 쓴 값들을 비우고 이후 기록부터 다시 센다.
            # 그래서 한 번의 공격 흐름이 경보 하나로 묶인다.
            latest.clear()

    return alerts
