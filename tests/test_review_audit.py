"""Audit metadata only: no real gateways or source-file changes."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from soc.collector import collect_file
from soc.storage import SQLiteSocStorage
from soc.audit import AuditRepository, release_with_audit
from soc.incident_service import ActionPolicyError, IncidentReview

class ReviewAuditTests(unittest.TestCase):
    def setUp(self):
        self.storage = SQLiteSocStorage()
        self.addCleanup(self.storage.close)
        self.audit = AuditRepository(self.storage)

    def incident(self):
        ap = SimpleNamespace(approval_id='APR-review',status='applied',gateway_response={})
        return SimpleNamespace(incident_id='INC-review',status='blocked',updated_at_utc='',approvals=[ap])

    def test_incident_review_batch_is_atomic_and_rejects_stale_versions(self):
        stamp = "2026-11-28T01:00:00.000000Z"
        with self.storage._conn as conn:
            conn.executemany("""
                INSERT INTO alerts (alert_id, rule_id, rule_name, severity, window_start_utc,
                                    window_end_utc, failure_count, dedup_key)
                VALUES (?, 'RULE', 'Rule', 'high', ?, ?, 1, ?)
            """, [(key, stamp, stamp, key) for key in ("ALT-A", "ALT-B")])
        repo = self.audit.repo
        start = IncidentReview("start", "reviewing", "operator", "", "", stamp)
        close = IncidentReview("close", "closed", "operator", "benign", "Verified",
                               "2026-11-28T01:00:01.000000Z")
        self.assertTrue(repo.record_incident_review({"ALT-A": ""}, start))
        self.assertFalse(repo.record_incident_review({"ALT-B": "", "ALT-A": ""}, close))
        self.assertEqual(repo.latest_incident_reviews(), {"ALT-A": start})
        self.assertTrue(repo.record_incident_review({"ALT-B": "", "ALT-A": "start"}, close))
        self.assertEqual(repo.latest_incident_reviews(), {"ALT-A": close, "ALT-B": close})

    def test_release_is_presaved_attributed_and_duplicate_is_not_sent(self):
        inc = self.incident()
        def release(approval_id):
            row, = self.audit.list_releases(inc.incident_id)
            self.assertEqual((row['requested_by'],row['reason'],row['result']),('releaser','verified recovery','pending'))
            return {'status':'released'}
        client = Mock(); client.release.side_effect=release
        store = SimpleNamespace(storage=self.storage,action_client=client)
        release_with_audit(store,inc,approval_id='APR-review',requested_by='releaser',reason='verified recovery',operation_id='op-review')
        row, = self.audit.list_releases(inc.incident_id)
        self.assertEqual(row['result'],'succeeded')
        self.assertTrue(row['completed_at_utc'])
        with self.assertRaises(ActionPolicyError):
            release_with_audit(store,inc,approval_id='APR-review',requested_by='releaser',reason='verified recovery',operation_id='op-review')
        self.assertEqual(client.release.call_count,1)
        with self.assertRaises(ActionPolicyError):
            release_with_audit(store,inc,approval_id='APR-review',requested_by='other',reason='different',operation_id='op-review')

    def test_release_uncertainty_and_observation_do_not_claim_success(self):
        inc=self.incident(); client=Mock(); client.release.side_effect=TimeoutError('do-not-save-exception-payload')
        store=SimpleNamespace(storage=self.storage,action_client=client)
        release_with_audit(store,inc,approval_id='APR-review',requested_by='ops',reason='investigation complete',operation_id='op-timeout')
        self.audit.observe_release('APR-review',{'status':'released','rule_present':False})
        row, = self.audit.list_releases(inc.incident_id)
        self.assertEqual(row['result'],'unknown')
        self.assertEqual(row['observed_status'],'released')
        self.assertNotIn('do-not-save',json.dumps(row))

    def test_audit_failure_and_missing_reason_prevent_gateway_call(self):
        inc=self.incident(); client=Mock(); store=SimpleNamespace(storage=self.storage,action_client=client)
        with patch.object(AuditRepository,'begin_release',side_effect=OSError('DB unavailable')):
            with self.assertRaises(OSError):
                release_with_audit(store,inc,approval_id='APR-review',requested_by='ops',reason='done',operation_id='op-fail')
        with self.assertRaises(ActionPolicyError):
            release_with_audit(store,inc,approval_id='APR-review',requested_by='ops',reason='',operation_id='op-empty')
        client.release.assert_not_called()

    def test_corrupt_lines_have_metadata_but_no_raw_secret_and_no_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'erp.jsonl'
            raw=b'{"password":"DO_NOT_KEEP",broken}\n\xff\n'
            path.write_bytes(raw)
            result=collect_file('erp',path,self.storage,isolate_errors=True)
            self.assertEqual(result.skipped_lines,2)
            rows=self.audit.list_collection_errors('erp')
            self.assertEqual(len(rows),2)
            self.assertNotIn('DO_NOT_KEEP',json.dumps(rows))
            first=next(r for r in rows if r['line_offset']==0)
            self.assertEqual(first['content_sha256'],hashlib.sha256(raw.splitlines(keepends=True)[0]).hexdigest())
            self.assertEqual(first['byte_length'],len(raw.splitlines(keepends=True)[0]))
            self.assertTrue(first['file_inode'])
            self.assertEqual(self.storage.count_raw_logs(),0)
            collect_file('erp',path,self.storage,isolate_errors=True)
            self.assertEqual(len(self.audit.list_collection_errors('erp')),2)
            self.storage._conn.execute("UPDATE collector_offsets SET byte_offset=0 WHERE source='erp'")
            self.storage._conn.commit()
            collect_file('erp',path,self.storage,isolate_errors=True)
            self.assertEqual(len(self.audit.list_collection_errors('erp')),2)

    def test_error_metadata_and_offset_rollback_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'erp.jsonl';path.write_bytes(b'broken\n')
            self.storage._conn.executescript("CREATE TRIGGER reject_offset BEFORE INSERT ON collector_offsets BEGIN SELECT RAISE(ABORT,'test failure'); END;")
            with self.assertRaises(Exception):
                collect_file('erp',path,self.storage,isolate_errors=True)
            self.assertEqual(self.storage.get_offset('erp',path.name),0)
            self.assertEqual(self.audit.list_collection_errors('erp'),[])
            self.storage._conn.execute('DROP TRIGGER reject_offset');self.storage._conn.commit()
            collect_file('erp',path,self.storage,isolate_errors=True)
            self.assertEqual(len(self.audit.list_collection_errors('erp')),1)
            self.assertEqual(self.storage.get_offset('erp',path.name),7)

    def test_rotation_keeps_error_file_identity_and_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'erp.jsonl';path.write_bytes(b'first bad\nunfinished')
            collect_file('erp',path,self.storage,isolate_errors=True)
            path.rename(Path(tmp)/'erp.jsonl.1')
            with (Path(tmp)/'erp.jsonl.1').open('ab') as f:
                f.write(b'\n')
            path.write_bytes(b'new bad\n')
            collect_file('erp',path,self.storage,isolate_errors=True)
            rows=self.audit.list_collection_errors('erp')
            self.assertEqual(len(rows),3)
            self.assertEqual(len({r['file_inode'] for r in rows}),2)
            self.assertTrue(any('#g1' in r['file_path'] for r in rows))
            self.assertEqual(self.storage.get_offset('erp',path.name),len(b'new bad\n'))

    def test_ui_escapes_reason_and_shows_error_summary_without_payload(self):
        from soc.audit import release_audit_panel, collection_error_panel
        row={'requested_at_utc':'2026-11-27T00:00:00Z','requested_by':'ops',
             'reason':'<script>alert(1)</script>','result':'unknown','completed_at_utc':None,
             'observed_status':'released','observed_at_utc':'2026-11-27T00:01:00Z'}
        page=release_audit_panel([row])
        self.assertNotIn('<script>alert',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn('unknown',str(row))
        panel=collection_error_panel(SimpleNamespace(storage=self.storage),'erp')
        self.assertIn('collection-errors',panel)
