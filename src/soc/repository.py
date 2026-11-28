from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .detector import AlertRecord
from .incident_service import ApprovalRecord, CorrelationLink, IncidentReview, IncidentView
from .models import NormalizedEvent, RawLogRecord

FOLLOWUP_LOGIN_MINUTES = 5


@dataclass(frozen=True)
class FollowupLoginSuccess:
    """사건 화면에 표시할 로그인 성공 시각과 원본 기록 번호."""

    event_ts_utc: str
    raw_id: str


def _to_iso_utc(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(value)


def is_lock_denied_failure(event_type: str, status_code: Any, details: dict[str, Any]) -> bool:
    """ERP가 잠금 안내(403)로 거부했지만 입력한 비밀번호는 틀렸던 시도. 사건 집계와 같은 기준으로 로그인 실패에 포함한다."""
    return (
        event_type == "login_blocked" and status_code == 403
        and details.get("reason") == "account_locked" and details.get("password_valid") is False
    )


def _to_json_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        return json.loads(value)
    return {}


class SocRepository:
    """Reads and persists incidents, alerts, correlations, and approvals across SQLite or PostgreSQL."""

    def __init__(self, storage: Any) -> None:
        self._storage = storage
        self._is_pg = storage.__class__.__name__ == "PostgresSocStorage"
        self._ph = "%s" if self._is_pg else "?"

    @property
    def _conn(self) -> Any:
        return self._storage._conn

    def _sql(self, query: str) -> str:
        return query.replace("?", self._ph) if self._is_pg else query

    def _run_db(self, fn: Any) -> Any:
        runner = getattr(self._storage, "run_with_retry", None)
        if callable(runner):
            return runner(fn)
        return fn()

    def _fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        sql = self._sql(query)

        def _exec() -> list[tuple[Any, ...]]:
            if self._is_pg:
                with self._conn.cursor() as cur:
                    cur.execute(sql, params)
                    return list(cur.fetchall())
            return list(self._conn.execute(sql, params).fetchall())

        return self._run_db(_exec)

    def _execute(self, cur: Any, query: str, params: tuple[Any, ...] = ()) -> None:
        cur.execute(self._sql(query), params)

    def count_incidents(self) -> int:
        rows = self._fetchall("SELECT COUNT(*) FROM incidents")
        return int(rows[0][0]) if rows else 0

    def latest_incident_reviews(self) -> dict[str, IncidentReview]:
        rows = self._fetchall("""
            SELECT alert_id, operation_id, state, actor, decision, reason, recorded_at_utc
            FROM (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY alert_id ORDER BY recorded_at_utc DESC, operation_id DESC
                ) AS review_rank FROM incident_review_history
            ) reviews WHERE review_rank = 1
        """)
        return {row[0]: IncidentReview(*row[1:6], _to_iso_utc(row[6])) for row in rows}

    def record_incident_review(self, expected: dict[str, str], review: IncidentReview) -> bool:
        def write() -> bool:
            conn = self._conn
            with (conn.transaction() if self._is_pg else conn):
                cur = conn.cursor()
                try:
                    if self._is_pg:
                        cur.execute("SELECT pg_advisory_xact_lock(1397703490)")
                    else:
                        cur.execute("UPDATE incident_review_history SET state = state WHERE 1 = 0")
                    for key, version in expected.items():
                        self._execute(cur, """
                            SELECT operation_id FROM incident_review_history WHERE alert_id = ?
                            ORDER BY recorded_at_utc DESC, operation_id DESC LIMIT 1
                        """, (key,))
                        row = cur.fetchone()
                        if (row[0] if row else "") != version:
                            return False
                    cur.executemany(
                        self._sql("""
                            INSERT INTO incident_review_history
                            (alert_id, operation_id, state, actor, decision, reason, recorded_at_utc)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """),
                        [(key, review.operation_id, review.state, review.actor, review.decision,
                          review.reason, review.recorded_at_utc) for key in expected],
                    )
                    return True
                finally:
                    cur.close()
        return self._run_db(write)

    def count_future_events(self, reference_utc: datetime) -> int:
        """Count stored evidence held out of detection; never print payloads."""
        if reference_utc.tzinfo is None:
            raise ValueError("reference_utc must include a timezone")
        ceiling = reference_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return int(self._fetchall(
            "SELECT COUNT(*) FROM normalized_events WHERE event_ts_utc > ?", (ceiling,)
        )[0][0])

    def has_events_becoming_due(self, previous_utc: datetime, reference_utc: datetime) -> bool:
        """Previously future events must be reconsidered even without new input."""
        if previous_utc.tzinfo is None or reference_utc.tzinfo is None:
            raise ValueError("detection references must include a timezone")
        return bool(self._fetchall(
            "SELECT 1 FROM normalized_events WHERE event_ts_utc > ? AND event_ts_utc <= ? LIMIT 1",
            tuple(t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                  for t in (previous_utc, reference_utc)),
        ))

    def fetch_raw_and_events(self, *, recent_hours: int | None = None, reference_utc: datetime | None = None) -> tuple[list[RawLogRecord], list[NormalizedEvent]]:
        if recent_hours is not None:
            # Bound the anchor AND both evidence queries. Do not let a future
            # timestamp move every source's detection window into the future.
            reference = reference_utc if reference_utc is not None else datetime.now(timezone.utc)
            if reference.tzinfo is None:
                raise ValueError("reference_utc must include a timezone")
            ceiling = reference.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            max_rows = self._fetchall(
                "SELECT MAX(event_ts_utc) FROM normalized_events WHERE event_ts_utc <= ?", (ceiling,)
            )
            max_ts = max_rows[0][0] if (max_rows and max_rows[0][0] is not None) else None
            if max_ts is None:
                return [], []
            ref_dt = (
                max_ts
                if isinstance(max_ts, datetime)
                else datetime.fromisoformat(str(max_ts).strip().replace("Z", "+00:00"))
            )
            if ref_dt.tzinfo is None:
                ref_dt = ref_dt.replace(tzinfo=timezone.utc)
            cutoff = (ref_dt.astimezone(timezone.utc) - timedelta(hours=recent_hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ev_rows = self._fetchall(
                """
                SELECT event_id, raw_id, source, event_ts_utc, event_type, outcome,
                       username, client_ip, peer_ip, client_ip_trusted,
                       src_ip, src_port, dst_ip, dst_port, protocol,
                       request_id, http_method, http_path, status_code,
                       ingest_mode, details_json
                FROM normalized_events
                WHERE event_ts_utc >= ? AND event_ts_utc <= ?
                ORDER BY event_ts_utc ASC, event_id ASC
                """,
                (cutoff, ceiling),
            )
            raw_rows = self._fetchall(
                """
                SELECT DISTINCT rl.raw_id, rl.source, rl.file_path, rl.line_offset, rl.raw_payload, rl.ingest_mode
                FROM raw_logs rl
                JOIN normalized_events ne ON ne.raw_id = rl.raw_id
                WHERE ne.event_ts_utc >= ? AND ne.event_ts_utc <= ?
                """,
                (cutoff, ceiling),
            )
        else:
            raw_rows = self._fetchall(
                "SELECT raw_id, source, file_path, line_offset, raw_payload, ingest_mode FROM raw_logs"
            )
            ev_rows = self._fetchall(
                """
                SELECT event_id, raw_id, source, event_ts_utc, event_type, outcome,
                       username, client_ip, peer_ip, client_ip_trusted,
                       src_ip, src_port, dst_ip, dst_port, protocol,
                       request_id, http_method, http_path, status_code,
                       ingest_mode, details_json
                FROM normalized_events
                ORDER BY event_ts_utc ASC, event_id ASC
                """
            )
        raw_records = [
            RawLogRecord(
                raw_id=r[0],
                source=r[1],
                file_path=r[2],
                line_offset=int(r[3]),
                raw_payload=r[4],
                ingest_mode=r[5],
            )
            for r in raw_rows
        ]
        events = [
            NormalizedEvent(
                event_id=r[0],
                raw_id=r[1],
                source=r[2],
                event_ts_utc=_to_iso_utc(r[3]),
                event_type=r[4],
                outcome=r[5],
                username=r[6],
                client_ip=r[7],
                peer_ip=r[8],
                client_ip_trusted=bool(r[9]),
                src_ip=r[10],
                src_port=r[11],
                dst_ip=r[12],
                dst_port=r[13],
                protocol=r[14],
                request_id=r[15],
                http_method=r[16],
                http_path=r[17],
                status_code=r[18],
                ingest_mode=r[19],
                details=_to_json_obj(r[20]),
            )
            for r in ev_rows
        ]
        return raw_records, events

    def find_followup_login_success(self, incident: IncidentView) -> FollowupLoginSuccess | None:
        # 같은 계정과 IP가 정해진 기존 반복 실패 사건만 확인한다.
        if not incident.block_rule_eligible or not incident.username or not incident.target_ip:
            return None
        modes = {event.ingest_mode for event in incident.evidence_events}
        if len(modes) != 1:
            return None

        # 마지막 실패 직후부터 5분까지, 같은 종류의 수집 기록에서 첫 성공만 찾는다.
        # 예를 들어 과거 기록을 재생한 성공이 실제 로그인 실패와 섞이지 않게 한다.
        end_of_failures = max(
            datetime.fromisoformat(alert.window_end_utc.replace("Z", "+00:00"))
            for alert in incident.alerts
        )
        deadline = end_of_failures + timedelta(minutes=FOLLOWUP_LOGIN_MINUTES)
        rows = self._fetchall(
            """
            SELECT event_ts_utc, raw_id
            FROM normalized_events
            WHERE username = ? AND client_ip = ? AND ingest_mode = ?
              AND source = 'erp' AND event_type = 'login_success' AND outcome = 'success'
              AND status_code = 200 AND client_ip_trusted = TRUE
              AND event_ts_utc > ? AND event_ts_utc <= ?
            ORDER BY event_ts_utc ASC, event_id ASC
            LIMIT 1
            """,
            (incident.username, incident.target_ip, next(iter(modes)), _to_iso_utc(end_of_failures), _to_iso_utc(deadline)),
        )
        if not rows:
            return None
        event_time, raw_id = rows[0]
        return FollowupLoginSuccess(event_ts_utc=_to_iso_utc(event_time), raw_id=raw_id)

    def _events_where(
        self,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
        exclude_event_types: tuple[str, ...] | None = None,
        ingest_mode: str | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if source is not None:
            clauses.append("ne.source = ?")
            params.append(source)
        if event_types:
            placeholders = ", ".join("?" for _ in event_types)
            clauses.append(f"ne.event_type IN ({placeholders})")
            params.extend(event_types)
        if exclude_event_types:
            # event_type은 NOT NULL 열이라 NOT IN이 NULL 때문에 행을 놓치지 않는다.
            placeholders = ", ".join("?" for _ in exclude_event_types)
            clauses.append(f"ne.event_type NOT IN ({placeholders})")
            params.extend(exclude_event_types)
        if ingest_mode is not None:
            clauses.append("ne.ingest_mode = ?")
            params.append(ingest_mode)
        if since_utc is not None:
            clauses.append("ne.event_ts_utc >= ?")
            params.append(since_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        if until_utc is not None:
            clauses.append("ne.event_ts_utc < ?")
            params.append(until_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return where_sql, params

    def count_recent_events(
        self,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
        ingest_mode: str | None = None,
    ) -> int:
        where_sql, params = self._events_where(ingest_mode=ingest_mode, 
            source=source, event_types=event_types, since_utc=since_utc, until_utc=until_utc
        )
        rows = self._fetchall(f"SELECT COUNT(*) FROM normalized_events ne {where_sql}", tuple(params))
        return int(rows[0][0]) if rows else 0

    def fetch_event_hours(
        self,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        exclude_event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
        ingest_mode: str | None = None,
    ) -> list[tuple[str, int]]:
        """출처·종류별 시간 단위(UTC) 이벤트 수. 보고서의 수집 공백 계산용.

        fetch_icmp_denial_hours와 같은 방식으로 시간 칸을 SQL에서 만들어 집계하므로 전체 행을
        파이썬으로 끌어오지 않는다. 반환: [("2026-11-25T02", 12), ...] (이벤트가 있는 시간만).
        count_recent_events와 같은 where 규칙을 쓰기 때문에 기간 합계가 건수 집계와 일치한다.
        한국 시간(UTC+9)은 정시 단위로 어긋나지 않아 UTC 시간 칸이 곧 KST 시간 칸이 된다.
        """
        hour_expr = ("to_char(ne.event_ts_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24')"
                     if self._is_pg else "substr(ne.event_ts_utc, 1, 13)")
        where_sql, params = self._events_where(ingest_mode=ingest_mode, 
            source=source, event_types=event_types, since_utc=since_utc,
            until_utc=until_utc, exclude_event_types=exclude_event_types,
        )
        rows = self._fetchall(
            f"SELECT {hour_expr}, COUNT(*) FROM normalized_events ne {where_sql} GROUP BY 1 ORDER BY 1",
            tuple(params),
        )
        return [(str(hour).replace(" ", "T"), int(count)) for hour, count in rows]

    def fetch_first_event_utc(
        self,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        exclude_event_types: tuple[str, ...] | None = None,
        until_utc: datetime | None = None,
        ingest_mode: str | None = None,
    ) -> str | None:
        """조건에 맞는 가장 이른 이벤트 시각(UTC ISO). 없으면 None.

        기간 앞쪽의 빈 칸이 '수집이 끊긴 공백'인지 '수집 시작 전'인지 가르는 데 쓴다.
        """
        where_sql, params = self._events_where(ingest_mode=ingest_mode, 
            source=source, event_types=event_types, until_utc=until_utc,
            exclude_event_types=exclude_event_types,
        )
        rows = self._fetchall(f"SELECT MIN(ne.event_ts_utc) FROM normalized_events ne {where_sql}", tuple(params))
        return _to_iso_utc(rows[0][0]) if rows and rows[0][0] is not None else None

    def fetch_icmp_denial_hours(self, since_utc: datetime, until_utc: datetime) -> list[tuple[str, int]]:
        """Hourly live ICMP denials; aggregate in SQL so the chart has no row cap."""
        hour_expr = ("to_char(ne.event_ts_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24')"
                     if self._is_pg else "substr(ne.event_ts_utc, 1, 13)")
        rows = self._fetchall(
            f"SELECT {hour_expr}, COUNT(*) FROM normalized_events ne "
            "WHERE ne.source = 'gateway' AND ne.event_type = 'fw_deny' "
            "AND ne.protocol = 'ICMP' AND ne.ingest_mode = 'live' "
            "AND ne.event_ts_utc >= ? AND ne.event_ts_utc < ? GROUP BY 1 ORDER BY 1",
            (_to_iso_utc(since_utc), _to_iso_utc(until_utc)),
        )
        return [(str(hour).replace(" ", "T"), int(count)) for hour, count in rows]

    def fetch_recent_icmp_denials(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self._fetchall(
            "SELECT ne.event_ts_utc, ne.src_ip, ne.dst_ip, ne.raw_id, rl.file_path, rl.line_offset, ne.details_json "
            "FROM normalized_events ne JOIN raw_logs rl ON rl.raw_id = ne.raw_id "
            "WHERE ne.source = 'gateway' AND ne.event_type = 'fw_deny' "
            "AND ne.protocol = 'ICMP' AND ne.ingest_mode = 'live' "
            "ORDER BY ne.event_ts_utc DESC, ne.event_id DESC LIMIT ?",
            (max(1, int(limit)),),
        )
        return [{"event_ts_utc": _to_iso_utc(ts), "src_ip": src, "dst_ip": dst,
                 "raw_id": raw, "file_path": path, "line_offset": offset,
                 "rule_id": _to_json_obj(details).get("rule_id")}
                for ts, src, dst, raw, path, offset, details in rows]

    def fetch_recent_events(
        self,
        limit: int = 50,
        *,
        offset: int = 0,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
        since_utc: datetime | None = None,
        until_utc: datetime | None = None,
        ingest_mode: str | None = None,
    ) -> list[dict[str, Any]]:
        where_sql, params = self._events_where(ingest_mode=ingest_mode, 
            source=source, event_types=event_types, since_utc=since_utc, until_utc=until_utc
        )
        params.extend([max(1, int(limit)), max(0, int(offset))])

        rows = self._fetchall(
            f"""
            SELECT ne.event_ts_utc, rl.received_at_utc, ne.source, ne.event_type, ne.outcome,
                   ne.username, ne.client_ip, ne.src_ip, ne.src_port, ne.dst_ip, ne.dst_port,
                   ne.client_ip_trusted, ne.request_id, ne.http_method, ne.http_path,
                   ne.status_code, ne.ingest_mode, ne.raw_id, ne.details_json
            FROM normalized_events ne
            JOIN raw_logs rl ON rl.raw_id = ne.raw_id
            {where_sql}
            ORDER BY ne.event_ts_utc DESC, ne.event_id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        results: list[dict[str, Any]] = []
        for r in rows:
            details = _to_json_obj(r[18])
            results.append(
                {
                    "event_ts_utc": _to_iso_utc(r[0]),
                    "received_at_utc": _to_iso_utc(r[1]),
                    "source": r[2],
                    "event_type": r[3],
                    "outcome": r[4],
                    "username": r[5],
                    "client_ip": r[6],
                    "src_ip": r[7],
                    "src_port": r[8],
                    "dst_ip": r[9],
                    "dst_port": r[10],
                    "device_ip": r[6] or r[7] or "-",
                    "client_ip_trusted": bool(r[11]),
                    "request_id": r[12],
                    "http_method": r[13],
                    "http_path": r[14],
                    "status_code": r[15],
                    "ingest_mode": r[16],
                    "raw_id": r[17],
                    "rule_id": details.get("rule_id"),
                    "department": details.get("department"),
                    "user_role": details.get("role"),
                    "access_time": details.get("access_time"),
                }
            )
        return results

    def fetch_hourly_summary(self, now_utc: datetime | None = None) -> dict[str, int]:
        cutoff = ((now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        rows = self._fetchall(
            """
            SELECT source, event_type, outcome, status_code, details_json
            FROM normalized_events
            WHERE event_ts_utc >= ?
            """,
            (cutoff,),
        )
        summary = {
            "erp_login_success": 0,
            "erp_login_failed": 0,
            "fw_allow": 0,
            "fw_deny": 0,
            "caddy_requests": 0,
            "caddy_errors": 0,
        }
        for src, ev_type, outcome, status_code, details_json in rows:
            if src == "erp":
                if ev_type == "login_success":
                    summary["erp_login_success"] += 1
                elif (ev_type == "login_failed" and status_code != 400) or is_lock_denied_failure(
                        ev_type, status_code, _to_json_obj(details_json)):
                    # 400은 입력 형식 오류라 계정 인증 실패(401)와 따로 센다.
                    summary["erp_login_failed"] += 1
            elif src == "gateway":
                if ev_type == "fw_allow":
                    summary["fw_allow"] += 1
                elif ev_type == "fw_deny":
                    summary["fw_deny"] += 1
            elif src == "caddy":
                summary["caddy_requests"] += 1
                if (status_code is not None and int(status_code) >= 400) or outcome == "failure":
                    summary["caddy_errors"] += 1
        return summary

    def fetch_login_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str]]:
        """since_utc 이후의 ERP 로그인 성공·실패 이벤트를 (UTC 시각, 종류, 출발지 IP, 계정) 목록으로 돌려준다."""
        cutoff = since_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        rows = self._fetchall(
            """
            SELECT event_ts_utc, event_type, client_ip, username, status_code, details_json
            FROM normalized_events
            WHERE source = 'erp' AND event_type IN ('login_failed', 'login_success', 'login_blocked')
              AND event_ts_utc >= ?
            ORDER BY event_ts_utc ASC
            """,
            (cutoff,),
        )
        out: list[tuple[datetime, str, str, str]] = []
        for ts, ev_type, ip, user, status_code, details_json in rows:
            if ev_type == "login_failed" and status_code == 400:
                continue  # 입력 형식 오류(비밀번호 칸 비움 등)는 인증 실패 그래프에서 제외한다.
            if ev_type == "login_blocked":
                # 잠긴 계정에 틀린 비밀번호를 넣은 시도(5번째 실패 포함)는 사건과 같이 실패로 센다. 그 밖의 잠금 거부는 제외한다.
                if not is_lock_denied_failure(ev_type, status_code, _to_json_obj(details_json)):
                    continue
                ev_type = "login_failed"
            if isinstance(ts, datetime):
                dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            out.append((dt.astimezone(timezone.utc), str(ev_type), str(ip or ""), str(user or "")))
        return out

    def fetch_trend_events(self, since_utc: datetime) -> list[tuple[datetime, str, str, str, int | None, str]]:
        """since_utc 이후의 정규화 이벤트를 (UTC 시각, 출처, 이벤트 종류, 결과, HTTP 상태코드, 요청 경로) 목록으로 돌려준다."""
        cutoff = since_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        rows = self._fetchall(
            """
            SELECT event_ts_utc, source, event_type, outcome, status_code, http_path
            FROM normalized_events
            WHERE event_ts_utc >= ?
            ORDER BY event_ts_utc ASC
            """,
            (cutoff,),
        )
        out: list[tuple[datetime, str, str, str, int | None, str]] = []
        for ts, src, ev_type, outcome, status_code, http_path in rows:
            if isinstance(ts, datetime):
                dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            code = int(status_code) if status_code is not None else None
            out.append((dt.astimezone(timezone.utc), str(src or ""), str(ev_type or ""), str(outcome or ""), code,
                        str(http_path or "")))
        return out

    def fetch_source_stats(self) -> list[dict[str, Any]]:
        rows = self._fetchall(
            """
            SELECT source, COUNT(*) AS cnt, MAX(received_at_utc) AS last_received_utc
            FROM raw_logs
            GROUP BY source
            ORDER BY source ASC
            """
        )
        return [
            {
                "source": r[0],
                "count": int(r[1]),
                "last_received_utc": _to_iso_utc(r[2]) if r[2] is not None else "-",
            }
            for r in rows
        ]

    def sync_incidents(self, incidents: list[IncidentView]) -> None:
        if not incidents:
            return

        def _do_sync() -> None:
            if self._is_pg:
                with self._conn.transaction():
                    with self._conn.cursor() as cur:
                        self._upsert_incidents(cur, incidents)
            else:
                with self._conn:
                    cur = self._conn.cursor()
                    self._upsert_incidents(cur, incidents)

        self._run_db(_do_sync)

    def _upsert_incidents(self, cur: Any, incidents: list[IncidentView]) -> None:
        for inc in incidents:
            self._execute(
                cur,
                """
                INSERT INTO incidents (incident_id, title, status, severity, target_ip, username, created_at_utc, updated_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (incident_id) DO NOTHING
                """,
                (
                    inc.incident_id,
                    inc.title,
                    inc.status,
                    inc.severity,
                    inc.target_ip,
                    inc.username,
                    inc.created_at_utc,
                    inc.updated_at_utc,
                ),
            )
            for alert in inc.alerts:
                self._execute(
                    cur,
                    """
                    INSERT INTO alerts (
                        alert_id, rule_id, rule_name, severity, status,
                        username, client_ip, window_start_utc, window_end_utc,
                        failure_count, dedup_key
                    )
                    VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        alert.alert_id,
                        alert.rule_id,
                        alert.rule_name,
                        alert.severity,
                        alert.username,
                        alert.client_ip,
                        alert.window_start_utc,
                        alert.window_end_utc,
                        alert.failure_count,
                        alert.dedup_key,
                    ),
                )
                self._execute(
                    cur,
                    "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    (inc.incident_id, alert.alert_id),
                )
                for ev_id in alert.evidence_event_ids:
                    self._execute(
                        cur,
                        "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
                        (alert.alert_id, ev_id),
                    )
            for corr in inc.correlations:
                self._execute(
                    cur,
                    """
                    INSERT INTO incident_correlations (correlation_id, incident_id, event_id, link_type, reason)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        corr.correlation_id,
                        corr.incident_id,
                        corr.event_id,
                        corr.link_type,
                        corr.reason,
                    ),
                )

    def load_incidents(self) -> list[IncidentView]:
        inc_rows = self._fetchall(
            """
            SELECT incident_id, title, status, severity, target_ip, username, created_at_utc, updated_at_utc
            FROM incidents
            ORDER BY created_at_utc DESC
            """
        )
        if not inc_rows:
            return []

        ev_rows = self._fetchall(
            """
            SELECT DISTINCT ne.event_id, ne.raw_id, ne.source, ne.event_ts_utc, ne.event_type, ne.outcome,
                   ne.username, ne.client_ip, ne.peer_ip, ne.client_ip_trusted,
                   ne.src_ip, ne.src_port, ne.dst_ip, ne.dst_port, ne.protocol,
                   ne.request_id, ne.http_method, ne.http_path, ne.status_code,
                   ne.ingest_mode, ne.details_json
            FROM normalized_events ne
            WHERE ne.event_id IN (
                SELECT event_id FROM alert_events
                UNION
                SELECT event_id FROM incident_correlations
            )
            ORDER BY ne.event_ts_utc ASC, ne.event_id ASC
            """
        )
        raw_rows = self._fetchall(
            """
            SELECT DISTINCT rl.raw_id, rl.source, rl.file_path, rl.line_offset, rl.raw_payload, rl.ingest_mode
            FROM raw_logs rl
            JOIN normalized_events ne ON ne.raw_id = rl.raw_id
            WHERE ne.event_id IN (
                SELECT event_id FROM alert_events
                UNION
                SELECT event_id FROM incident_correlations
            )
            """
        )
        raw_by_id = {
            r[0]: RawLogRecord(
                raw_id=r[0],
                source=r[1],
                file_path=r[2],
                line_offset=int(r[3]),
                raw_payload=r[4],
                ingest_mode=r[5],
            )
            for r in raw_rows
        }
        ev_by_id = {
            r[0]: NormalizedEvent(
                event_id=r[0],
                raw_id=r[1],
                source=r[2],
                event_ts_utc=_to_iso_utc(r[3]),
                event_type=r[4],
                outcome=r[5],
                username=r[6],
                client_ip=r[7],
                peer_ip=r[8],
                client_ip_trusted=bool(r[9]),
                src_ip=r[10],
                src_port=r[11],
                dst_ip=r[12],
                dst_port=r[13],
                protocol=r[14],
                request_id=r[15],
                http_method=r[16],
                http_path=r[17],
                status_code=r[18],
                ingest_mode=r[19],
                details=_to_json_obj(r[20]),
            )
            for r in ev_rows
        }

        alert_rows = self._fetchall(
            """
            SELECT ia.incident_id, a.alert_id, a.rule_id, a.rule_name, a.severity,
                   a.username, a.client_ip, a.window_start_utc, a.window_end_utc,
                   a.failure_count, a.dedup_key
            FROM incident_alerts ia
            JOIN alerts a ON a.alert_id = ia.alert_id
            """
        )
        ae_rows = self._fetchall("SELECT alert_id, event_id FROM alert_events")
        events_by_alert: dict[str, list[str]] = {}
        for aid, eid in ae_rows:
            events_by_alert.setdefault(aid, []).append(eid)

        alerts_by_inc: dict[str, list[AlertRecord]] = {}
        for r in alert_rows:
            inc_id, aid = r[0], r[1]
            ev_ids = tuple(events_by_alert.get(aid, []))
            raw_ids = tuple(ev_by_id[eid].raw_id for eid in ev_ids if eid in ev_by_id)
            modes = tuple(sorted({ev_by_id[eid].ingest_mode for eid in ev_ids if eid in ev_by_id}))
            alerts_by_inc.setdefault(inc_id, []).append(
                AlertRecord(
                    alert_id=aid,
                    rule_id=r[2],
                    rule_name=r[3],
                    severity=r[4],
                    username=r[5] or "",
                    client_ip=r[6] or "",
                    window_start_utc=_to_iso_utc(r[7]),
                    window_end_utc=_to_iso_utc(r[8]),
                    failure_count=int(r[9]),
                    dedup_key=r[10],
                    evidence_event_ids=ev_ids,
                    evidence_raw_ids=raw_ids,
                    ingest_modes=modes,
                )
            )

        corr_rows = self._fetchall(
            "SELECT correlation_id, incident_id, event_id, link_type, reason FROM incident_correlations"
        )
        corrs_by_inc: dict[str, list[CorrelationLink]] = {}
        for cid, inc_id, eid, link_type, reason in corr_rows:
            rid = ev_by_id[eid].raw_id if eid in ev_by_id else ""
            corrs_by_inc.setdefault(inc_id, []).append(
                CorrelationLink(
                    correlation_id=cid,
                    incident_id=inc_id,
                    event_id=eid,
                    raw_id=rid,
                    link_type=link_type,
                    reason=reason,
                )
            )

        ap_rows = self._fetchall(
            """
            SELECT approval_id, incident_id, target_ip, action_type, approved_by,
                   approved_at_utc, expires_at_utc, status, gateway_response
            FROM action_approvals
            ORDER BY approved_at_utc ASC
            """
        )
        aps_by_inc: dict[str, list[ApprovalRecord]] = {}
        for r in ap_rows:
            aps_by_inc.setdefault(r[1], []).append(
                ApprovalRecord(
                    approval_id=r[0],
                    incident_id=r[1],
                    target_ip=r[2],
                    action_type=r[3],
                    approved_by=r[4],
                    approved_at_utc=_to_iso_utc(r[5]),
                    expires_at_utc=_to_iso_utc(r[6]),
                    status=r[7],
                    gateway_response=_to_json_obj(r[8]),
                )
            )

        views: list[IncidentView] = []
        for r in inc_rows:
            inc_id = r[0]
            inc_alerts = alerts_by_inc.get(inc_id, [])
            inc_corrs = corrs_by_inc.get(inc_id, [])

            ev_list: list[NormalizedEvent] = []
            seen_ev: set[str] = set()
            for a in inc_alerts:
                for eid in a.evidence_event_ids:
                    if eid in ev_by_id and eid not in seen_ev:
                        seen_ev.add(eid)
                        ev_list.append(ev_by_id[eid])

            inc_raws: dict[str, RawLogRecord] = {}
            for ev in ev_list:
                if ev.raw_id in raw_by_id:
                    inc_raws[ev.raw_id] = raw_by_id[ev.raw_id]
            for c in inc_corrs:
                if c.raw_id in raw_by_id:
                    inc_raws[c.raw_id] = raw_by_id[c.raw_id]

            views.append(
                IncidentView(
                    incident_id=inc_id,
                    title=r[1],
                    status=r[2],
                    severity=r[3],
                    target_ip=r[4] or "",
                    username=r[5] or "",
                    created_at_utc=_to_iso_utc(r[6]),
                    updated_at_utc=_to_iso_utc(r[7]),
                    alerts=inc_alerts,
                    evidence_events=ev_list,
                    correlations=inc_corrs,
                    raw_logs_by_id=inc_raws,
                    approvals=aps_by_inc.get(inc_id, []),
                )
            )
        return views

    def save_approval(self, approval: ApprovalRecord, incident_status: str, updated_at_utc: str) -> None:
        db_status = "rejected" if approval.status == "apply_failed" else approval.status
        resp_json = json.dumps(approval.gateway_response, ensure_ascii=False)

        def _write(cur: Any) -> None:
            self._execute(
                cur,
                """
                INSERT INTO action_approvals (
                    approval_id, incident_id, target_ip, action_type, approved_by,
                    approved_at_utc, expires_at_utc, status, gateway_response, updated_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (approval_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    gateway_response = EXCLUDED.gateway_response,
                    updated_at_utc = EXCLUDED.updated_at_utc
                """,
                (
                    approval.approval_id,
                    approval.incident_id,
                    approval.target_ip,
                    approval.action_type,
                    approval.approved_by,
                    approval.approved_at_utc,
                    approval.expires_at_utc,
                    db_status,
                    resp_json,
                    updated_at_utc,
                ),
            )
            self._execute(
                cur,
                "UPDATE incidents SET status = ?, updated_at_utc = ? WHERE incident_id = ?",
                (incident_status, updated_at_utc, approval.incident_id),
            )

        def _do_save() -> None:
            if self._is_pg:
                with self._conn.transaction():
                    with self._conn.cursor() as cur:
                        _write(cur)
            else:
                with self._conn:
                    _write(self._conn.cursor())

        self._run_db(_do_save)
