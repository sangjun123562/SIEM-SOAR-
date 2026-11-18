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
) -> tuple[int, int]:
    """Collect new lines from all configured log sources and sync detected incidents to DB."""
    total_inserted = 0
    for source, path in log_sources.items():
        res = collect_file(source, path, storage, collection_mode=collection_mode)
        total_inserted += res.inserted_records

    repo = SocRepository(storage)
    raws, events = repo.fetch_raw_and_events()
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

    The first pass after startup stores lines that already existed in the files as
    replay (backlog). Only lines appended after the collector started are stored as
    live, so past test events can never become eligible for a real block.
    """
    passes = 0
    while max_passes is None or passes < max_passes:
        mode = "replay" if passes == 0 else "live"
        inserted, inc_count = run_once(storage, log_sources, collection_mode=mode)
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
