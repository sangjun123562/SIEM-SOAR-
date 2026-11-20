from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from .collector import StartupBoundary, collect_file
from .incident_service import build_incidents
from .repository import SocRepository
from .storage import PostgresSocStorage, SocStorage


def run_once(
    storage: SocStorage,
    log_sources: dict[str, Path],
    *,
    collection_mode: str = "live",
    skip_idle_sync: bool = False,
    startup_boundaries: dict[str, StartupBoundary] | None = None,
) -> tuple[int, int]:
    """Collect new lines from all configured log sources (isolated per source) and sync incidents."""
    total_inserted = 0
    for source, path in log_sources.items():
        try:
            res = collect_file(
                source,
                path,
                storage,
                collection_mode=collection_mode,
                isolate_errors=True,
                startup_boundary=startup_boundaries.get(source) if startup_boundaries is not None else None,
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
    replay_only: bool = False,
) -> int:
    """시작할 때 이미 쓰인 줄과 운영 중 새로 쓰인 줄을 나눠 수집한다."""
    startup_boundaries: dict[str, StartupBoundary] = {}
    for source, path in log_sources.items():
        # 파일마다 시작할 때의 크기를 기억한다. 첫 읽기 전에 새 줄이 들어와도 구분할 수 있다.
        try:
            st = path.stat()
        except FileNotFoundError:
            # 처음 설치한 직후에는 첫 로그인 요청 전까지 ERP 로그 파일이 없을 수 있다.
            # 나중에 생긴 파일의 줄은 모두 시작 후에 쓰였으므로 새 기록으로 본다.
            startup_boundaries[source] = StartupBoundary()
        except OSError:
            # 권한 문제 등으로 확인하지 못했으면 이미 쓰인 줄이 있을 수 있어 조사용으로 둔다.
            startup_boundaries[source] = StartupBoundary(checked=False)
        else:
            startup_boundaries[source] = StartupBoundary(f"{st.st_dev}:{st.st_ino}", st.st_size)

    mode = "replay" if replay_only else "live"
    # 팀 설치 점검(testbed/scripts/setup_all.sh)은 수집기 로그에서 "mode=replay" 글자를 찾는다.
    if replay_only:
        mode_label = "replay"
    else:
        mode_label = "replay-before-start,live-after-start"
    passes = 0
    while max_passes is None or passes < max_passes:
        deadline = storage.get_offset("__practice_reset", "maintenance")
        if deadline > int(time.time()):
            # Ack only between completed passes: no DB transaction is left open.
            storage.save_batch_and_advance_offset("__practice_reset", "collector-paused", [], deadline)
            handled = False
            reset_completed = False
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
                        reset_completed = True
                        storage.save_batch_and_advance_offset("__practice_reset", "reset-done", [], deadline)
                    except Exception as exc:
                        print(f"[collector] practice reset failed: {type(exc).__name__}", flush=True)
                        storage.save_batch_and_advance_offset("__practice_reset", "reset-failed", [], deadline)
                time.sleep(0.1)
            # 초기화가 성공한 경우에만 새 읽기 위치를 쓴다. 중단되면 시작 기준선을 유지한다.
            if reset_completed:
                startup_boundaries.clear()
            continue
        inserted, inc_count = run_once(
            storage,
            log_sources,
            collection_mode=mode,
            skip_idle_sync=(passes > 0),
            startup_boundaries=startup_boundaries,
        )
        if inserted > 0 or passes == 0:
            print(f"pass={passes} mode={mode_label} collected={inserted} incidents={inc_count}", flush=True)
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
        # --once는 조사용으로 한 번만 읽는다. 그사이 새 줄이 들어와도 replay로 저장한다.
        run_live(
            storage,
            sources,
            interval=args.interval,
            max_passes=1 if args.once else None,
            replay_only=args.once,
        )
        return 0
    finally:
        storage.close()


if __name__ == "__main__":
    raise SystemExit(main())
