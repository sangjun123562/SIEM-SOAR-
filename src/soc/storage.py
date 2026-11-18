from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from .models import NormalizedEvent, RawLogRecord


class SocStorage(Protocol):
    """Storage interface for raw logs, normalized events, and collector offsets."""

    def get_offset(self, source: str, file_path: str) -> int:
        ...

    def save_batch_and_advance_offset(
        self,
        source: str,
        file_path: str,
        records: list[tuple[RawLogRecord, NormalizedEvent]],
        new_offset: int,
    ) -> int:
        ...

    def count_raw_logs(self, source: str | None = None) -> int:
        ...

    def count_normalized_events(self, source: str | None = None) -> int:
        ...


class SQLiteSocStorage:
    """SQLite-backed SOC storage for local unit tests and offline verification."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS collector_offsets (
                source          TEXT NOT NULL,
                file_path       TEXT NOT NULL,
                byte_offset     INTEGER NOT NULL DEFAULT 0,
                updated_at_utc  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                PRIMARY KEY (source, file_path)
            );

            CREATE TABLE IF NOT EXISTS raw_logs (
                raw_id          TEXT PRIMARY KEY,
                source          TEXT NOT NULL,
                file_path       TEXT NOT NULL,
                line_offset     INTEGER NOT NULL,
                raw_payload     TEXT NOT NULL,
                ingest_mode     TEXT NOT NULL DEFAULT 'live',
                received_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                UNIQUE (source, file_path, line_offset)
            );

            CREATE TABLE IF NOT EXISTS normalized_events (
                event_id          TEXT PRIMARY KEY,
                raw_id            TEXT NOT NULL REFERENCES raw_logs(raw_id) ON DELETE RESTRICT,
                source            TEXT NOT NULL,
                event_ts_utc      TEXT NOT NULL,
                event_type        TEXT NOT NULL,
                outcome           TEXT NOT NULL,
                username          TEXT,
                client_ip         TEXT,
                peer_ip           TEXT,
                client_ip_trusted INTEGER NOT NULL DEFAULT 0,
                src_ip            TEXT,
                src_port          INTEGER,
                dst_ip            TEXT,
                dst_port          INTEGER,
                protocol          TEXT,
                request_id        TEXT,
                http_method       TEXT,
                http_path         TEXT,
                status_code       INTEGER,
                ingest_mode       TEXT NOT NULL DEFAULT 'live',
                details_json      TEXT NOT NULL DEFAULT '{}',
                UNIQUE (raw_id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id          TEXT PRIMARY KEY,
                rule_id           TEXT NOT NULL,
                rule_name         TEXT NOT NULL,
                severity          TEXT NOT NULL,
                status            TEXT NOT NULL DEFAULT 'open',
                username          TEXT,
                client_ip         TEXT,
                window_start_utc  TEXT NOT NULL,
                window_end_utc    TEXT NOT NULL,
                failure_count     INTEGER NOT NULL,
                dedup_key         TEXT NOT NULL UNIQUE,
                created_at_utc    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id  TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
                event_id  TEXT NOT NULL REFERENCES normalized_events(event_id) ON DELETE RESTRICT,
                PRIMARY KEY (alert_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id     TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'open',
                severity        TEXT NOT NULL,
                target_ip       TEXT,
                username        TEXT,
                created_at_utc  TEXT NOT NULL,
                updated_at_utc  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                alert_id    TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE RESTRICT,
                PRIMARY KEY (incident_id, alert_id)
            );

            CREATE TABLE IF NOT EXISTS incident_correlations (
                correlation_id  TEXT PRIMARY KEY,
                incident_id     TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                event_id        TEXT NOT NULL REFERENCES normalized_events(event_id) ON DELETE RESTRICT,
                link_type       TEXT NOT NULL,
                reason          TEXT NOT NULL,
                created_at_utc  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                UNIQUE (incident_id, event_id, link_type)
            );

            CREATE TABLE IF NOT EXISTS action_approvals (
                approval_id       TEXT PRIMARY KEY,
                incident_id       TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
                target_ip         TEXT NOT NULL,
                action_type       TEXT NOT NULL,
                approved_by       TEXT NOT NULL,
                approved_at_utc   TEXT NOT NULL,
                expires_at_utc    TEXT NOT NULL,
                status            TEXT NOT NULL DEFAULT 'pending',
                gateway_response  TEXT NOT NULL DEFAULT '{}',
                updated_at_utc    TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def get_offset(self, source: str, file_path: str) -> int:
        row = self._conn.execute(
            "SELECT byte_offset FROM collector_offsets WHERE source = ? AND file_path = ?",
            (source, file_path),
        ).fetchone()
        return int(row["byte_offset"]) if row else 0

    def save_batch_and_advance_offset(
        self,
        source: str,
        file_path: str,
        records: list[tuple[RawLogRecord, NormalizedEvent]],
        new_offset: int,
    ) -> int:
        inserted = 0
        with self._conn:
            for raw_rec, norm_evt in records:
                cur = self._conn.execute(
                    """
                    INSERT INTO raw_logs (raw_id, source, file_path, line_offset, raw_payload, ingest_mode)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        raw_rec.raw_id,
                        raw_rec.source,
                        raw_rec.file_path,
                        raw_rec.line_offset,
                        raw_rec.raw_payload,
                        raw_rec.ingest_mode,
                    ),
                )
                if cur.rowcount > 0:
                    inserted += 1

                self._conn.execute(
                    """
                    INSERT INTO normalized_events (
                        event_id, raw_id, source, event_ts_utc, event_type, outcome,
                        username, client_ip, peer_ip, client_ip_trusted,
                        src_ip, src_port, dst_ip, dst_port, protocol,
                        request_id, http_method, http_path, status_code,
                        ingest_mode, details_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        norm_evt.event_id,
                        norm_evt.raw_id,
                        norm_evt.source,
                        norm_evt.event_ts_utc,
                        norm_evt.event_type,
                        norm_evt.outcome,
                        norm_evt.username,
                        norm_evt.client_ip,
                        norm_evt.peer_ip,
                        1 if norm_evt.client_ip_trusted else 0,
                        norm_evt.src_ip,
                        norm_evt.src_port,
                        norm_evt.dst_ip,
                        norm_evt.dst_port,
                        norm_evt.protocol,
                        norm_evt.request_id,
                        norm_evt.http_method,
                        norm_evt.http_path,
                        norm_evt.status_code,
                        norm_evt.ingest_mode,
                        json.dumps(norm_evt.details, ensure_ascii=False),
                    ),
                )

            self._conn.execute(
                """
                INSERT INTO collector_offsets (source, file_path, byte_offset, updated_at_utc)
                VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                ON CONFLICT (source, file_path) DO UPDATE SET
                    byte_offset = excluded.byte_offset,
                    updated_at_utc = excluded.updated_at_utc
                """,
                (source, file_path, new_offset),
            )
        return inserted

    def count_raw_logs(self, source: str | None = None) -> int:
        if source is None:
            row = self._conn.execute("SELECT COUNT(*) AS cnt FROM raw_logs").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM raw_logs WHERE source = ?", (source,)
            ).fetchone()
        return int(row["cnt"])

    def count_normalized_events(self, source: str | None = None) -> int:
        if source is None:
            row = self._conn.execute("SELECT COUNT(*) AS cnt FROM normalized_events").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM normalized_events WHERE source = ?", (source,)
            ).fetchone()
        return int(row["cnt"])

    def list_events(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM normalized_events ORDER BY event_ts_utc ASC, event_id ASC"
        ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self._conn.close()


class PostgresSocStorage:
    """PostgreSQL-backed SOC storage targeting db/init/001_schema.sql."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("psycopg is required for PostgresSocStorage") from exc
        # autocommit=True prevents get_offset() SELECT from opening an implicit
        # transaction, ensuring with self._conn.transaction() commits at top level.
        self._conn = psycopg.connect(dsn, autocommit=True)

    def get_offset(self, source: str, file_path: str) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT byte_offset FROM collector_offsets WHERE source = %s AND file_path = %s",
                (source, file_path),
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def save_batch_and_advance_offset(
        self,
        source: str,
        file_path: str,
        records: list[tuple[RawLogRecord, NormalizedEvent]],
        new_offset: int,
    ) -> int:
        inserted = 0
        with self._conn.transaction():
            with self._conn.cursor() as cur:
                for raw_rec, norm_evt in records:
                    cur.execute(
                        """
                        INSERT INTO raw_logs (raw_id, source, file_path, line_offset, raw_payload, ingest_mode)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (
                            raw_rec.raw_id,
                            raw_rec.source,
                            raw_rec.file_path,
                            raw_rec.line_offset,
                            raw_rec.raw_payload,
                            raw_rec.ingest_mode,
                        ),
                    )
                    if cur.rowcount > 0:
                        inserted += 1

                    cur.execute(
                        """
                        INSERT INTO normalized_events (
                            event_id, raw_id, source, event_ts_utc, event_type, outcome,
                            username, client_ip, peer_ip, client_ip_trusted,
                            src_ip, src_port, dst_ip, dst_port, protocol,
                            request_id, http_method, http_path, status_code,
                            ingest_mode, details_json
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s::jsonb
                        )
                        ON CONFLICT DO NOTHING
                        """,
                        (
                            norm_evt.event_id,
                            norm_evt.raw_id,
                            norm_evt.source,
                            norm_evt.event_ts_utc,
                            norm_evt.event_type,
                            norm_evt.outcome,
                            norm_evt.username,
                            norm_evt.client_ip,
                            norm_evt.peer_ip,
                            norm_evt.client_ip_trusted,
                            norm_evt.src_ip,
                            norm_evt.src_port,
                            norm_evt.dst_ip,
                            norm_evt.dst_port,
                            norm_evt.protocol,
                            norm_evt.request_id,
                            norm_evt.http_method,
                            norm_evt.http_path,
                            norm_evt.status_code,
                            norm_evt.ingest_mode,
                            json.dumps(norm_evt.details, ensure_ascii=False),
                        ),
                    )

                cur.execute(
                    """
                    INSERT INTO collector_offsets (source, file_path, byte_offset, updated_at_utc)
                    VALUES (%s, %s, %s, NOW())
                    ON CONFLICT (source, file_path) DO UPDATE SET
                        byte_offset = EXCLUDED.byte_offset,
                        updated_at_utc = NOW()
                    """,
                    (source, file_path, new_offset),
                )
        return inserted

    def count_raw_logs(self, source: str | None = None) -> int:
        with self._conn.cursor() as cur:
            if source is None:
                cur.execute("SELECT COUNT(*) FROM raw_logs")
            else:
                cur.execute("SELECT COUNT(*) FROM raw_logs WHERE source = %s", (source,))
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def count_normalized_events(self, source: str | None = None) -> int:
        with self._conn.cursor() as cur:
            if source is None:
                cur.execute("SELECT COUNT(*) FROM normalized_events")
            else:
                cur.execute("SELECT COUNT(*) FROM normalized_events WHERE source = %s", (source,))
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def close(self) -> None:
        self._conn.close()
