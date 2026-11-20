from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from .collector import collect_file
from .incident_service import build_incidents
from .repository import SocRepository
from .storage import PostgresSocStorage, SocStorage


def run_once(
    storage: SocStorage,
    log_sources: dict[str, Path],
    *,
    collection_mode: str = "live",
    skip_idle_sync: bool = False,
    startup_boundaries: dict[str, tuple[str, int]] | None = None,
) -> tuple[int, int]:
    """Collect new lines from all configured log sources (isolated per source) and sync incidents."""
    total_inserted = 0
    for source, path in log_sources.items():
        try:
            replay_before: int | None = None
            if startup_boundaries and source in startup_boundaries and path.exists():
                b_inode, b_size = startup_boundaries[source]
                st = path.stat()
                if f"{st.st_dev}:{st.st_ino}" == b_inode:
                    replay_before = b_size
            res = collect_file(
                source,
                path,
                storage,
                collection_mode=collection_mode,
                isolate_errors=True,
                replay_before_offset=replay_before,
            )
            total_inserted += res.inserted_records
        except Exception as exc:
            print(f"[collector] source error source={source}: {type(exc).__name__}: {exc}", flush=True)

    repo = SocRepository(storage)
    if skip_idle_sync and total_inserted == 0:
        return 0, repo.count_incidents()

    raws, events = repo.fetch_raw_and_events(recent_hours=24)
    incidents = build_incidents(raws, events)
    repo.sync_incidents(incidents)
    return total_inserted, len(incidents)


def run_live(
    storage: SocStorage,
    log_sources: dict[str, Path],
    *,
    interval: float = 2.0,
    max_passes: int | None = None,
) -> int:
    """Poll forever (or max_passes times).

    Live/Replay boundary:
    - Pass 0 at startup classifies all complete lines currently in the files as `replay`.
    - Any partial line that had already started before startup (`offset < startup_size`)
      stays `replay` even when completed on a later pass.
    - Only complete lines started & appended after startup are classified as `live`.
    """
    startup_boundaries: dict[str, tuple[str, int]] = {}
    for source, path in log_sources.items():
        if path.exists():
            try:
                st = path.stat()
                startup_boundaries[source] = (f"{st.st_dev}:{st.st_ino}", st.st_size)
            except OSError:
                pass

    passes = 0
    while max_passes is None or passes < max_passes:
        deadline = storage.get_offset("__practice_reset", "maintenance")
        if deadline > int(time.time()):
            # Ack only between completed passes: no DB transaction is left open.
            storage.save_batch_and_advance_offset("__practice_reset", "collector-paused", [], deadline)
            handled = False
            while storage.get_offset("__practice_reset", "maintenance") > int(time.time()):
                observed_deadline = storage.get_offset("__practice_reset", "maintenance")
                if observed_deadline > int(time.time()) and observed_deadline != deadline:
                    deadline, handled = observed_deadline, False
                    storage.save_batch_and_advance_offset("__practice_reset", "collector-paused", [], deadline)
                if not handled and storage.get_offset("__practice_reset", "reset-request") == deadline:
                    handled = True
                    try:
                        # Reuse this interpreter and connection instead of starting another Python process.
                        from .practice_reset import reset_records
                        reset_records(storage, log_sources)
                        storage.save_batch_and_advance_offset("__practice_reset", "reset-done", [], deadline)
                    except Exception as exc:
                        print(f"[collector] practice reset failed: {type(exc).__name__}", flush=True)
                        storage.save_batch_and_advance_offset("__practice_reset", "reset-failed", [], deadline)
                time.sleep(0.1)
            # EOF checkpoints now define the new practice session, including live provenance.
            startup_boundaries.clear()
            passes = max(1, passes)
            continue
        mode = "replay" if passes == 0 else "live"
        inserted, inc_count = run_once(
            storage,
            log_sources,
            collection_mode=mode,
            skip_idle_sync=(passes > 0),
            startup_boundaries=startup_boundaries,
        )
        if inserted > 0 or passes == 0:
            print(f"pass={passes} mode={mode} collected={inserted} incidents={inc_count}", flush=True)
        passes += 1
        if max_passes is not None and passes >= max_passes:
            break
        time.sleep(interval)
    return passes


def default_log_sources() -> dict[str, Path]:
    return {
        "gateway": Path(os.environ.get("SOC_GW_LOG", "/var/log/gw/gateway.jsonl")),
        "caddy": Path(os.environ.get("SOC_CADDY_LOG", "/var/log/caddy/caddy.jsonl")),
        "erp": Path(os.environ.get("SOC_ERP_LOG", "/var/log/erp/erp.jsonl")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live SOC log collector and incident detector")
    parser.add_argument("--once", action="store_true", help="Run a single collection pass and exit")
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("SOC_POLL_INTERVAL_SECONDS", "2.0")),
        help="Polling interval in seconds",
    )
    args = parser.parse_args(argv)

    dsn = os.environ["SOC_DB_DSN"]
    sources = default_log_sources()
    storage = PostgresSocStorage(dsn)
    try:
        # --once는 시작 직후 1회만 읽으므로 기존 파일 내용 = replay로 저장된다.
        run_live(storage, sources, interval=args.interval, max_passes=1 if args.once else None)
        return 0
    finally:
        storage.close()


if __name__ == "__main__":
    raise SystemExit(main())
