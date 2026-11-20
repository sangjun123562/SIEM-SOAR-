"""수집기 시작 전에 이미 있던 로그는 replay, 시작 후 추가된 줄만 live로 저장되는지 확인한다."""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc.live_collector import run_live, run_once  # noqa: E402
from soc.repository import SocRepository  # noqa: E402
from soc.storage import SQLiteSocStorage  # noqa: E402


def _fail(i: int, username: str = "alice", client_ip: str = "172.28.10.11") -> str:
    return json.dumps({
        "timestamp_utc": f"2026-11-18T04:00:{i:02d}Z", "source": "erp", "event_type": "login_failed",
        "outcome": "failure", "username": username, "client_ip": client_ip, "peer_ip": "172.28.20.5",
        "client_ip_trusted": True, "request_id": f"req-backlog-{i}", "http_method": "POST",
        "http_path": "/api/login", "status_code": 401, "ingest_mode": "live",
    })


class LiveBacklogReplayTests(unittest.TestCase):
    def test_existing_lines_are_replay_and_not_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text("".join(_fail(i) + "\n" for i in range(5)), encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                run_live(storage, {"erp": erp}, interval=0, max_passes=1)
                modes = {e["ingest_mode"] for e in storage.list_events()}
                self.assertEqual(modes, {"replay"})
                for inc in SocRepository(storage).load_incidents():
                    self.assertFalse(inc.live_and_trusted_eligible)
            finally:
                storage.close()

    def test_lines_appended_after_start_are_live(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                run_live(storage, {"erp": erp}, interval=0, max_passes=1)
                with erp.open("a", encoding="utf-8") as f:
                    f.write("".join(_fail(i) + "\n" for i in range(10, 15)))
                run_once(storage, {"erp": erp}, collection_mode="live")
                modes = [e["ingest_mode"] for e in storage.list_events()]
                self.assertEqual(modes.count("replay"), 1)
                self.assertEqual(modes.count("live"), 5)
            finally:
                storage.close()

    def test_restart_recovers_backlog_and_detects_new_lines_in_first_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0, "already-read", "172.28.10.12") + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                # 먼저 한 줄을 저장해 수집기가 꺼지기 전의 읽기 위치를 남긴다.
                run_live(storage, {"erp": erp}, max_passes=1)
                with erp.open("a", encoding="utf-8") as handle:
                    handle.writelines(_fail(i) + "\n" for i in range(1, 6))

                def append_before_first_read(*args, **kwargs):
                    # 재시작 기준선은 잡힌 상태이고 아직 첫 읽기는 시작하지 않았다.
                    with erp.open("a", encoding="utf-8") as handle:
                        handle.writelines(_fail(i, "bob") + "\n" for i in range(6, 11))
                    return run_once(*args, **kwargs)

                with patch("soc.live_collector.run_once", side_effect=append_before_first_read):
                    run_live(storage, {"erp": erp}, max_passes=1)

                events = storage.list_events()
                self.assertEqual(len(events), 11)
                self.assertEqual(sum(event["ingest_mode"] == "replay" for event in events), 6)
                self.assertEqual(sum(event["ingest_mode"] == "live" for event in events), 5)
                incidents = {item.username: item for item in SocRepository(storage).load_incidents()}
                self.assertEqual(set(incidents), {"alice", "bob"})
                self.assertFalse(incidents["alice"].live_and_trusted_eligible)
                self.assertTrue(incidents["bob"].live_and_trusted_eligible)
                for incident in incidents.values():
                    self.assertEqual(len(incident.raw_logs_by_id), 5)

                # 같은 파일로 다시 켜도 이미 저장한 기록과 사건은 추가되지 않는다.
                run_live(storage, {"erp": erp}, max_passes=1)
                self.assertEqual(len(storage.list_events()), 11)
                self.assertEqual(SocRepository(storage).count_incidents(), 2)
            finally:
                storage.close()

    def test_partial_startup_line_in_rotated_generation_stays_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            rotated = erp.with_name("erp.jsonl.1")
            erp.write_bytes((_fail(0) + "\n").encode())
            line = (_fail(1) + "\n").encode()
            split = len(line) // 2
            storage = SQLiteSocStorage(":memory:")
            try:
                run_live(storage, {"erp": erp}, max_passes=1)
                erp.rename(rotated)
                erp.write_bytes(line[:split])

                def complete_line(_):
                    with erp.open("ab") as handle:
                        handle.write(line[split:] + (_fail(2) + "\n").encode())

                with patch("soc.live_collector.time.sleep", side_effect=complete_line):
                    run_live(storage, {"erp": erp}, max_passes=2)
                self.assertEqual(
                    {event["request_id"]: event["ingest_mode"] for event in storage.list_events()},
                    {"req-backlog-0": "replay", "req-backlog-1": "replay", "req-backlog-2": "live"},
                )
            finally:
                storage.close()

    def test_file_replaced_after_start_keeps_old_lines_replay_and_new_file_live(self) -> None:
        # 수집기를 켠 직후 파일이 교체됐다. 옛 파일의 시작 전 줄은 조사용, 새 파일의 줄은 새 기록이다.
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            rotated = erp.with_name("erp.jsonl.1")
            erp.write_bytes((_fail(0) + "\n").encode())
            storage = SQLiteSocStorage(":memory:")
            try:
                run_live(storage, {"erp": erp}, max_passes=1)
                with erp.open("ab") as handle:
                    handle.write((_fail(1) + "\n").encode())
                line = (_fail(2) + "\n").encode()
                split = len(line) // 2

                def replace_before_first_read(*args, **kwargs):
                    if not rotated.exists():
                        erp.rename(rotated)
                        erp.write_bytes(line[:split])
                    return run_once(*args, **kwargs)

                def complete_line(_):
                    with erp.open("ab") as handle:
                        handle.write(line[split:] + (_fail(3) + "\n").encode())

                with patch("soc.live_collector.run_once", side_effect=replace_before_first_read):
                    with patch("soc.live_collector.time.sleep", side_effect=complete_line):
                        run_live(storage, {"erp": erp}, max_passes=2)
                self.assertEqual(
                    {event["request_id"]: event["ingest_mode"] for event in storage.list_events()},
                    {"req-backlog-0": "replay", "req-backlog-1": "replay", "req-backlog-2": "live",
                     "req-backlog-3": "live"},
                )
            finally:
                storage.close()

    def test_log_file_created_after_start_is_live(self) -> None:
        # 처음 설치한 직후처럼 수집기를 켤 때 ERP 로그 파일이 아직 없는 경우다.
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            storage = SQLiteSocStorage(":memory:")
            try:
                def first_logins_create_file(_):
                    # 첫 읽기가 끝난 뒤 로그인 실패 5건이 파일을 새로 만든다.
                    if not erp.exists():
                        erp.write_text("".join(_fail(i) + "\n" for i in range(5)), encoding="utf-8")

                with patch("soc.live_collector.time.sleep", side_effect=first_logins_create_file):
                    run_live(storage, {"erp": erp}, max_passes=2)
                self.assertEqual([event["ingest_mode"] for event in storage.list_events()], ["live"] * 5)
                incident, = SocRepository(storage).load_incidents()
                self.assertTrue(incident.live_and_trusted_eligible)
            finally:
                storage.close()

    def test_unknown_start_state_keeps_first_read_for_review(self) -> None:
        # 시작할 때 권한 문제 등으로 파일을 확인하지 못했다면, 처음 읽은 줄까지는 조사용으로 둔다.
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                original_stat = Path.stat
                stat_calls = []

                def stat_fails_once(path, *args, **kwargs):
                    if path == erp and not stat_calls:
                        stat_calls.append(path)
                        raise PermissionError("not readable yet")
                    return original_stat(path, *args, **kwargs)

                def append_after_first_read(_):
                    with erp.open("a", encoding="utf-8") as handle:
                        handle.write(_fail(1) + "\n")

                with patch.object(Path, "stat", stat_fails_once):
                    with patch("soc.live_collector.time.sleep", side_effect=append_after_first_read):
                        run_live(storage, {"erp": erp}, max_passes=2)
                self.assertEqual(
                    {event["request_id"]: event["ingest_mode"] for event in storage.list_events()},
                    {"req-backlog-0": "replay", "req-backlog-1": "live"},
                )
            finally:
                storage.close()

    def test_first_pass_log_keeps_setup_check_text(self) -> None:
        # 팀 설치 점검 스크립트가 수집기 로그에서 "mode=replay" 글자를 확인한다.
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    run_live(storage, {"erp": erp}, max_passes=1)
                self.assertIn("pass=0 mode=replay", output.getvalue())
            finally:
                storage.close()

    def test_replay_only_keeps_new_lines_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                def append_before_first_read(*args, **kwargs):
                    with erp.open("a", encoding="utf-8") as handle:
                        handle.write(_fail(1) + "\n")
                    return run_once(*args, **kwargs)

                with patch("soc.live_collector.run_once", side_effect=append_before_first_read):
                    run_live(storage, {"erp": erp}, max_passes=1, replay_only=True)
                self.assertEqual([event["ingest_mode"] for event in storage.list_events()], ["replay", "replay"])
            finally:
                storage.close()

    def test_retry_after_storage_failure_keeps_startup_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                save_batch = storage.save_batch_and_advance_offset

                def fail_first_save(*args, **kwargs):
                    if store.call_count == 1:
                        raise OSError("temporary storage failure")
                    return save_batch(*args, **kwargs)

                def append_before_retry(_):
                    self.assertEqual(storage.get_offset("erp", erp.name), 0)
                    with erp.open("a", encoding="utf-8") as handle:
                        handle.write(_fail(1) + "\n")

                with patch.object(storage, "save_batch_and_advance_offset", side_effect=fail_first_save) as store:
                    with patch("soc.live_collector.time.sleep", side_effect=append_before_retry):
                        run_live(storage, {"erp": erp}, max_passes=2)
                self.assertEqual(
                    {event["request_id"]: event["ingest_mode"] for event in storage.list_events()},
                    {"req-backlog-0": "replay", "req-backlog-1": "live"},
                )
            finally:
                storage.close()

    def test_cancelled_practice_reset_keeps_startup_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            erp = Path(tmp) / "erp.jsonl"
            erp.write_text(_fail(0) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage(":memory:")
            try:
                storage.save_batch_and_advance_offset("__practice_reset", "maintenance", [], 200)

                def cancel_reset(_):
                    storage.save_batch_and_advance_offset("__practice_reset", "maintenance", [], 0)
                    with erp.open("a", encoding="utf-8") as handle:
                        handle.write(_fail(1) + "\n")

                # 연습 초기화 준비 중 취소돼도 먼저 쌓인 로그를 실시간 기록으로 바꾸지 않는다.
                with patch("soc.live_collector.time.time", return_value=100):
                    with patch("soc.live_collector.time.sleep", side_effect=cancel_reset):
                        run_live(storage, {"erp": erp}, max_passes=1)
                self.assertEqual(
                    {event["request_id"]: event["ingest_mode"] for event in storage.list_events()},
                    {"req-backlog-0": "replay", "req-backlog-1": "live"},
                )
            finally:
                storage.close()


if __name__ == "__main__":
    unittest.main()
