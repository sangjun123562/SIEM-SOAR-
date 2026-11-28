"""Practice-only SOC reset: keep source files and checkpoint their current EOF."""
from __future__ import annotations

import os
import time
from pathlib import Path
from .repository import SocRepository

TABLES = ("collector_errors", "action_approvals", "incident_correlations", "incident_alerts", "incidents", "alert_events", "incident_review_history", "alerts", "normalized_events", "raw_logs")


def reset_records(storage, log_sources: dict[str, Path]) -> dict[str, int]:
    deadline = storage.get_offset("__practice_reset", "maintenance")
    if deadline <= int(time.time()) or storage.get_offset("__practice_reset", "collector-paused") != deadline:
        raise RuntimeError("Collector pause was not acknowledged")
    checkpoints = []
    for source, path in log_sources.items():
        # Keep the inode of the opened file even if a rotation happens concurrently.
        with path.open("rb") as handle:
            st = os.fstat(handle.fileno())
            partial = False
            if st.st_size:
                handle.seek(st.st_size - 1)
                partial = handle.read(1) != b"\n"
            checkpoints.append((source, path.name, st.st_size, f"{st.st_dev}:{st.st_ino}", partial))
    repo = SocRepository(storage)
    conn = repo._conn
    with (conn.transaction() if repo._is_pg else conn):
        with_cursor = conn.cursor()
        try:
            if repo._is_pg:
                with_cursor.execute("TRUNCATE TABLE " + ", ".join(TABLES))
            else:
                for table in TABLES:
                    with_cursor.execute("DELETE FROM " + table)
            with_cursor.execute("DELETE FROM collector_offsets WHERE source <> '__practice_reset'")
            query = repo._sql("INSERT INTO collector_offsets(source,file_path,byte_offset,file_inode,generation) VALUES (?,?,?,?,?)")
            for source, name, size, inode, partial in checkpoints:
                with_cursor.execute(query, (source, name, size, inode, 0))
                if partial:
                    with_cursor.execute(query, ("__practice_reset_partial", source, size, inode, 1))
        finally:
            with_cursor.close()
    return {source: size for source, _, size, _, _ in checkpoints}


def main():
    import json
    from .live_collector import default_log_sources
    from .storage import PostgresSocStorage
    storage = PostgresSocStorage(os.environ["SOC_DB_DSN"])
    try:
        print(json.dumps(reset_records(storage, default_log_sources())))
    finally:
        storage.close()


if __name__ == "__main__":
    main()
