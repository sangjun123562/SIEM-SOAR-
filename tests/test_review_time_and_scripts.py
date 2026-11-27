"""Regression checks for review findings 1 and 2; no real actions."""
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from soc.dashboard import _page_shell
from soc.live_collector import run_once
from soc.repository import SocRepository
from soc.storage import SQLiteSocStorage


def failure(stamp, index, username="alice"):
    return json.dumps({"timestamp_utc": stamp.isoformat(), "source": "erp",
        "event_type": "login_failed", "outcome": "failure", "username": username,
        "client_ip": "172.28.10.11", "peer_ip": "172.28.20.5",
        "client_ip_trusted": True, "request_id": f"review-{username}-{index}",
        "status_code": 401})


class ReviewRegressionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is required for JavaScript parsing")
    def test_generated_scripts_parse_and_long_block_confirmation(self):
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", _page_shell("check", "").decode(), re.S)
        program = r"""
const vm = require('vm');
const scripts = JSON.parse(require('fs').readFileSync(0, 'utf8'));
for (const script of scripts) new vm.Script(script);
const source = scripts.find(s => s.includes('function confirmLongBlock'));
const fn = source.slice(source.indexOf('function confirmLongBlock'), source.indexOf('function toggleManualRefreshPause'));
let calls = 0, answer = false;
const ctx = {window:{confirm:()=>{calls++;return answer}}};
vm.createContext(ctx); vm.runInContext(fn, ctx);
const form = n => ({duration_minutes:{value:String(n)}});
if (!ctx.confirmLongBlock(form(1440)) || calls !== 0) throw Error('short block confirmation');
if (ctx.confirmLongBlock(form(1441)) !== false || calls !== 1) throw Error('cancel ignored');
answer = true;
if (ctx.confirmLongBlock(form(43200)) !== true || calls !== 2) throw Error('confirmation ignored');
"""
        result = subprocess.run([shutil.which("node"), "-e", program], input=json.dumps(scripts),
                                text=True, encoding="utf-8", capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_future_record_does_not_hide_current_failure_group(self):
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "erp.jsonl"
            lines = [failure(now - timedelta(seconds=10-i), i) for i in range(5)]
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage()
            try:
                self.assertEqual(run_once(storage, {"erp":path})[0], 5)
                repo = SocRepository(storage)
                baseline = {inc.incident_id for inc in repo.load_incidents()}
                self.assertTrue(baseline)
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(failure(now + timedelta(days=3650), 99, "future") + "\n")
                inserted, count = run_once(storage, {"erp":path}, collection_mode="live")
                self.assertEqual(inserted, 1)
                self.assertEqual(count, len(baseline))
                self.assertEqual({inc.incident_id for inc in repo.load_incidents()}, baseline)
                raws, events = repo.fetch_raw_and_events()
                self.assertEqual(len(raws), 6)
                self.assertEqual(len(events), 6)
                self.assertTrue(any(e.username == "future" for e in events))
                _, selected = repo.fetch_raw_and_events(recent_hours=24)
                self.assertNotIn("future", {e.username for e in selected})
                self.assertEqual(run_once(storage, {"erp":path}, collection_mode="live"), (0,count))
            finally:
                storage.close()

    def test_reference_boundary_and_deferred_records_are_reconsidered(self):
        ref = datetime(2020, 1, 2, 0, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "erp.jsonl"
            stamps = [ref - timedelta(seconds=4-i) for i in range(5)]
            path.write_text("\n".join(failure(t, i) for i,t in enumerate(stamps)) + "\n", encoding="utf-8")
            storage = SQLiteSocStorage()
            try:
                before = ref - timedelta(seconds=1)
                run_once(storage, {"erp":path}, reference_utc=before)
                repo = SocRepository(storage)
                self.assertFalse(any(i.block_rule_eligible for i in repo.load_incidents()))
                _, events = repo.fetch_raw_and_events(recent_hours=24, reference_utc=before)
                self.assertEqual(len(events), 4)
                # No new file bytes: the fifth record becomes due at the exact boundary.
                inserted, count = run_once(storage, {"erp":path}, skip_idle_sync=True,
                    reference_utc=ref, previous_reference_utc=before)
                self.assertEqual(inserted, 0)
                self.assertGreater(count, 0)
                self.assertTrue(any(i.block_rule_eligible for i in repo.load_incidents()))
                ids = {i.incident_id for i in repo.load_incidents()}
                run_once(storage, {"erp":path}, skip_idle_sync=True,
                    reference_utc=ref + timedelta(seconds=1), previous_reference_utc=ref)
                self.assertEqual({i.incident_id for i in repo.load_incidents()}, ids)
                self.assertEqual(len(repo.fetch_raw_and_events()[1]), 5)
                with self.assertRaises(ValueError):
                    repo.fetch_raw_and_events(recent_hours=24, reference_utc=ref.replace(tzinfo=None))
            finally:
                storage.close()

    def test_historical_replay_is_not_discarded_by_wall_clock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "erp.jsonl"
            ref = datetime(2001,1,1,tzinfo=timezone.utc)
            path.write_text("\n".join(failure(ref+timedelta(seconds=i), i) for i in range(5))+"\n", encoding="utf-8")
            storage = SQLiteSocStorage()
            try:
                inserted,count = run_once(storage, {"erp":path}, collection_mode="replay")
                self.assertEqual(inserted, 5)
                self.assertGreater(count, 0)
                self.assertTrue(all(not i.live_and_trusted_eligible for i in SocRepository(storage).load_incidents()))
            finally:
                storage.close()
