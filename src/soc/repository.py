from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .detector import AlertRecord
from .incident_service import ApprovalRecord, CorrelationLink, IncidentView
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
        self._conn = storage._conn
        self._is_pg = storage.__class__.__name__ == "PostgresSocStorage"
        self._ph = "%s" if self._is_pg else "?"

    def _sql(self, query: str) -> str:
        return query.replace("?", self._ph) if self._is_pg else query

    def _fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        sql = self._sql(query)
        if self._is_pg:
            with self._conn.cursor() as cur:
                cur.execute(sql, params)
                return list(cur.fetchall())
        return list(self._conn.execute(sql, params).fetchall())

    def _execute(self, cur: Any, query: str, params: tuple[Any, ...] = ()) -> None:
        cur.execute(self._sql(query), params)

    def fetch_raw_and_events(self) -> tuple[list[RawLogRecord], list[NormalizedEvent]]:
        raw_rows = self._fetchall(
            "SELECT raw_id, source, file_path, line_offset, raw_payload, ingest_mode FROM raw_logs"
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

    def fetch_recent_events(
        self,
        limit: int = 50,
        *,
        source: str | None = None,
        event_types: tuple[str, ...] | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if source is not None:
            clauses.append("ne.source = ?")
            params.append(source)
        if event_types:
            placeholders = ", ".join("?" for _ in event_types)
            clauses.append(f"ne.event_type IN ({placeholders})")
            params.extend(event_types)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

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
            LIMIT ?
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
                }
            )
        return results

    def fetch_hourly_summary(self, now_utc: datetime | None = None) -> dict[str, int]:
        cutoff = ((now_utc or datetime.now(timezone.utc)).astimezone(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        rows = self._fetchall(
            """
            SELECT source, event_type, outcome, status_code
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
        for src, ev_type, outcome, status_code in rows:
            if src == "erp":
                if ev_type == "login_success":
                    summary["erp_login_success"] += 1
                elif ev_type == "login_failed":
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

        if self._is_pg:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    self._upsert_incidents(cur, incidents)
        else:
            with self._conn:
                cur = self._conn.cursor()
                self._upsert_incidents(cur, incidents)

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
        raw_records, events = self.fetch_raw_and_events()
        raw_by_id = {r.raw_id: r for r in raw_records}
        ev_by_id = {e.event_id: e for e in events}

        inc_rows = self._fetchall(
            """
            SELECT incident_id, title, status, severity, target_ip, username, created_at_utc, updated_at_utc
            FROM incidents
            ORDER BY created_at_utc DESC
            """
        )
        if not inc_rows:
            return []

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

        if self._is_pg:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    _write(cur)
        else:
            with self._conn:
                _write(self._conn.cursor())
