import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from soc.collector import collect_file
from soc.live_collector import run_live
from soc.practice_reset import reset_records
from soc.storage import SQLiteSocStorage


class PracticeResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'erp.jsonl'
        self.storage = SQLiteSocStorage(':memory:')
        self.sample = dict(ingest_mode='live', timestamp_utc='2026-11-20T08:00:00Z', source='erp', event_type='login_failed', outcome='failure', username='alice', client_ip='172.28.10.11', peer_ip='172.28.20.5', client_ip_trusted=True, request_id='old', http_method='POST', http_path='/api/login', status_code=401)
        self.old = (json.dumps(self.sample) + '\n').encode()
        self.path.write_bytes(self.old)
        collect_file('erp', self.path, self.storage, collection_mode='live')

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def arm(self):
        deadline = int(time.time()) + 180
        for key in ('maintenance', 'collector-paused'):
            self.storage.save_batch_and_advance_offset('__practice_reset', key, [], deadline)

    def test_eof_checkpoint_preserves_original_and_collects_only_new_live(self):
        before = self.path.read_bytes()
        self.arm()
        reset_records(self.storage, {'erp': self.path})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.storage.count_normalized_events(), 0)
        self.assertEqual(collect_file('erp', self.path, self.storage, collection_mode='live').inserted_records, 0)
        fresh = dict(self.sample, request_id='new')
        with self.path.open('ab') as f:
            f.write((json.dumps(fresh) + '\n').encode())
        self.assertEqual(collect_file('erp', self.path, self.storage, collection_mode='live').inserted_records, 1)
        rows = self.storage.list_events()
        self.assertEqual(rows[0]['request_id'], 'new')
        self.assertEqual(rows[0]['ingest_mode'], 'live')

    def test_partial_line_from_before_reset_is_discarded_when_completed(self):
        partial = self.old[:len(self.old)//2]
        with self.path.open('ab') as f:
            f.write(partial)
        self.arm()
        reset_records(self.storage, {'erp': self.path})
        with self.path.open('ab') as f:
            f.write(self.old[len(partial):])
            f.write((json.dumps(dict(self.sample, request_id='after-reset'))+'\n').encode())
        self.assertEqual(collect_file('erp', self.path, self.storage, collection_mode='live').inserted_records, 1)
        self.assertEqual(self.storage.list_events()[0]['request_id'], 'after-reset')

    def test_no_ack_does_not_delete_records(self):
        with self.assertRaises(RuntimeError):
            reset_records(self.storage, {'erp': self.path})
        self.assertEqual(self.storage.count_normalized_events(), 1)

    def test_missing_source_does_not_delete_records(self):
        self.arm()
        with self.assertRaises(FileNotFoundError):
            reset_records(self.storage, {'erp': Path(self.tmp.name)/'missing.jsonl'})
        self.assertEqual(self.storage.count_normalized_events(), 1)

    def test_checkpoint_insert_failure_rolls_back_deleted_records(self):
        self.arm()
        self.storage._conn.execute("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON collector_offsets WHEN NEW.source='erp' BEGIN SELECT RAISE(ABORT, 'test checkpoint failure'); END")
        with self.assertRaises(Exception):
            reset_records(self.storage, {'erp': self.path})
        self.assertEqual(self.storage.count_normalized_events(), 1)
        self.assertEqual(self.path.read_bytes(), self.old)

    def test_running_collector_executes_reset_request_without_subprocess(self):
        deadline = int(time.time())+180
        self.storage.save_batch_and_advance_offset('__practice_reset','maintenance',[],deadline)
        self.storage.save_batch_and_advance_offset('__practice_reset','reset-request',[],deadline)
        observed=[]
        def resume(_seconds):
            observed.append(self.storage.get_offset('__practice_reset','reset-done'))
            self.storage.save_batch_and_advance_offset('__practice_reset','maintenance',[],0)
        with patch('soc.live_collector.time.sleep',side_effect=resume):
            run_live(self.storage, {'erp': self.path}, max_passes=2)
        self.assertIn(deadline,observed)
        self.assertEqual(self.storage.count_normalized_events(),0)
        self.assertEqual(self.path.read_bytes(),self.old)

    def test_cooperative_pause_ack_and_resume(self):
        self.storage.save_batch_and_advance_offset('__practice_reset', 'maintenance', [], int(time.time())+180)
        acknowledgements=[]
        def resume(_seconds):
            acknowledgements.append(self.storage.get_offset('__practice_reset','collector-paused'))
            self.storage.save_batch_and_advance_offset('__practice_reset', 'maintenance', [], 0)
        with patch('soc.live_collector.time.sleep', side_effect=resume):
            run_live(self.storage, {}, max_passes=2)
        self.assertTrue(any(ack > int(time.time()) for ack in acknowledgements))


if __name__ == '__main__':
    unittest.main()