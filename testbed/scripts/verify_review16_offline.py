"""A-owned acceptance probes for review items 1/4/6/14/15.

No Docker, sockets, production files or PostgreSQL. Temporary synthetic JSONL,
in-memory SQLite and FakeIptables only. Exit 1 means an OPEN acceptance defect,
not a successful fix. Run from any directory with Python 3.10+.
"""
from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "testbed" / "gateway"))

from soc.collector import collect_file
from soc.incident_service import build_incidents
from soc.live_collector import run_live
from soc.normalizer import normalize_log_line
from soc.storage import SQLiteSocStorage
from test_actionapi import ActionStoreTest, body


def log_line(username="alice"):
    return (json.dumps({"timestamp_utc": "2026-11-20T00:00:00Z", "source": "erp",
                       "event_type": "login_failed", "outcome": "failure", "status_code": 401,
                       "username": username, "client_ip": "172.28.10.11",
                       "client_ip_trusted": True, "ingest_mode": "live"},
                      separators=(",", ":")) + "\n").encode()


def rotation_same_size(folder, storage):
    path = folder / "erp.jsonl"
    path.write_bytes(log_line("alice"))
    collect_file("erp", path, storage)
    # Atomic replacement models rotation; the old file is deliberately retained.
    replacement = folder / "next.jsonl"
    replacement.write_bytes(log_line("carol"))
    path.rename(folder / "erp.jsonl.1")
    replacement.rename(path)
    collect_file("erp", path, storage)
    assert {e["username"] for e in storage.list_events()} == {"alice", "carol"}, "new generation skipped"


def truncate_smaller(folder, storage):
    path = folder / "erp.jsonl"
    path.write_bytes(log_line("alice") + log_line("carol"))
    collect_file("erp", path, storage)
    path.write_bytes(log_line("david"))
    collect_file("erp", path, storage)
    assert len(storage.list_events()) == 3, "new generation lost"


def malformed_line(folder, storage):
    path = folder / "erp.jsonl"
    path.write_bytes(log_line("alice") + b"{invalid-json}\n" + log_line("carol"))
    collect_file("erp", path, storage)
    assert len(storage.list_events()) == 2, "valid lines blocked by malformed line"


def malformed_line_live(folder, storage):
    # 6번의 운영 경로(run_live). collect_file 직접 호출만으로는 B의 격리 위치를 확인할 수 없어 추가했다.
    path = folder / "erp.jsonl"
    path.write_bytes(log_line("alice") + b"{invalid-json}\n" + log_line("carol"))
    with patch("soc.live_collector.time.sleep"):
        run_live(storage, {"erp": path}, max_passes=2)
    assert len(storage.list_events()) == 2, "valid lines blocked by malformed line in run_live"


def startup_partial(folder, storage):
    path = folder / "erp.jsonl"
    data = log_line()
    boundary = len(data) // 2
    path.write_bytes(data[:boundary])
    def complete(_):
        with path.open("ab") as output:
            output.write(data[boundary:])
    with patch("soc.live_collector.time.sleep", side_effect=complete):
        run_live(storage, {"erp": path}, max_passes=2)
    assert storage.list_events()[0]["ingest_mode"] == "replay", "startup partial line promoted to live"


def unrelated_gateway(folder, storage):
    raw, base = normalize_log_line(log_line().decode(), source="erp", file_path="memory", line_offset=0)
    failures = [replace(base, event_id=f"erp-{i}", raw_id=f"raw-{i}") for i in range(5)]
    unrelated = replace(base, event_id="unrelated", source="gateway", event_type="fw_allow",
                        src_ip=base.client_ip, dst_ip="172.28.20.99", dst_port=22, protocol="TCP")
    incidents = build_incidents([], failures + [unrelated])
    assert not incidents[0].correlations, "unrelated destination/port attached as candidate"


def duplicate_target(folder, storage):
    # The approved contract currently deduplicates by approval ID, NOT target IP.
    # This exposes item 4 for A/B agreement; it does not silently change that contract.
    harness = ActionStoreTest()
    harness.setUp()
    try:
        harness.store.block(body(aid="APR-first"), "offline")
        harness.store.block(body(aid="APR-second"), "offline")
        harness.store.release("APR-first", "offline")
        assert not harness.ipt.rules, "different approval ID leaves another active block on same target"
    finally:
        harness.tearDown()


def main():
    checks = [("1.same-size-rotation", rotation_same_size), ("1.truncate", truncate_smaller),
              ("4.duplicate-target", duplicate_target), ("6.malformed", malformed_line),
              ("6b.malformed-live-path", malformed_line_live),
              ("14.partial-startup", startup_partial), ("15.unrelated-gateway", unrelated_gateway)]
    opened = 0
    for name, check in checks:
        with tempfile.TemporaryDirectory(prefix="soc-review16-") as directory:
            storage = SQLiteSocStorage()
            try:
                check(Path(directory), storage)
                print(f"PASS {name}")
            except Exception as error:
                opened += 1
                print(f"OPEN {name}: {type(error).__name__}: {error}")
            finally:
                storage.close()
    print(f"acceptance_pass={len(checks)-opened} open={opened} real_network_calls=0")
    return 1 if opened else 0


if __name__ == "__main__":
    raise SystemExit(main())
