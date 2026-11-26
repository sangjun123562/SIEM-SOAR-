import json
import sys
import unittest
from dataclasses import asdict, replace
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from soc.access_time import evaluate_access_time, night_bands, case_time_context, LOGIN_ATTEMPTS
from soc.normalizer import normalize_log_line
from soc.incident_service import build_incidents


class AccessTimeTests(unittest.TestCase):
    def test_kst_boundaries_and_weekend(self):
        for stamp,night in [('2026-11-26T06:59:59+09:00',True),('2026-11-26T07:00:00+09:00',False),
                            ('2026-11-26T22:59:59+09:00',False),('2026-11-26T23:00:00+09:00',True)]:
            self.assertEqual(evaluate_access_time(stamp)['night'],night)
        self.assertTrue(evaluate_access_time('2026-11-28T12:00:00+09:00')['weekend'])
        self.assertFalse(evaluate_access_time('2026-11-26T12:00:00+09:00')['outside'])

    def test_explicit_holiday_and_bounded_approved_exception(self):
        policy={'version':'test','day_start_hour':7,'night_start_hour':23,'holidays':['2026-11-26'],
                'exceptions':[{'username':'alice','approved_by':'ops','reason':'점검',
                               'starts_at':'2026-11-26T23:00:00+09:00','ends_at':'2026-11-27T01:00:00+09:00'}]}
        c=evaluate_access_time('2026-11-26T23:30:00+09:00','alice',policy)
        self.assertTrue(c['holiday'])
        self.assertFalse(c['requires_review'])
        self.assertTrue(evaluate_access_time('2026-11-27T01:00:00+09:00','alice',policy)['requires_review'])
        self.assertTrue(evaluate_access_time('2026-11-26T23:30:00+09:00','bob',policy)['requires_review'])

    def records(self,kinds,mode='live'):
        return [normalize_log_line(json.dumps({'timestamp_utc':f'2026-11-26T14:00:{i:02d}Z','source':'erp',
                'event_type':kind,'outcome':'success' if kind=='login_success' else 'failure','username':'alice',
                'client_ip':'172.28.10.11','client_ip_trusted':True,'ingest_mode':mode,
                'status_code':200 if kind=='login_success' else 401,
                'access_time':{'exception':{'approved_by':'attacker'}}}),source='erp',file_path='test.jsonl',line_offset=i,collection_mode=mode)
                for i,kind in enumerate(kinds)]

    def test_each_login_result_has_server_calculated_context_and_no_standalone_incident(self):
        for kind in LOGIN_ATTEMPTS:
            raw,event=self.records([kind])[0]
            self.assertTrue(event.details['access_time']['night'])
            self.assertIsNone(event.details['access_time']['exception'])
        for kind in ['login_failed','login_success','login_blocked']:
            raw,event=self.records([kind])[0]
            self.assertEqual(build_incidents([raw],[event]),[])

    def test_existing_rules_ids_counts_and_block_permissions_are_identical(self):
        for mode in ['live','replay','synthetic']:
            for kinds in [['login_failed']*3,['login_failed']*5,['login_failed']*3+['login_success']]:
                pairs=self.records(kinds,mode)
                raws,events=map(list,zip(*pairs))
                before=build_incidents(raws,[replace(e,details={}) for e in events])
                after=build_incidents(raws,events)
                self.assertEqual([(i.incident_id,[asdict(a) for a in i.alerts],i.block_rule_eligible,i.live_and_trusted_eligible) for i in before],
                                 [(i.incident_id,[asdict(a) for a in i.alerts],i.block_rule_eligible,i.live_and_trusted_eligible) for i in after])
                if after:
                    self.assertEqual(case_time_context(after[0])[1],mode=='live')

    def test_graph_bands_only_shade_night_not_entire_weekend(self):
        bands=night_bands('2026-11-28T00:00:00+09:00','2026-11-29T00:00:00+09:00')
        self.assertAlmostEqual(sum(b-a for a,b in bands),8/24)
        self.assertEqual(night_bands('2026-11-28T09:00:00+09:00','2026-11-28T18:00:00+09:00'),[])

    def test_policy_evidence_persists_and_badge_is_visible(self):
        from soc.storage import SQLiteSocStorage
        from soc.repository import SocRepository
        from soc.dashboard import _time_badge
        storage=SQLiteSocStorage()
        try:
            pairs=self.records(['login_failed'])
            storage.save_batch_and_advance_offset('erp','test.jsonl',pairs,100)
            event=SocRepository(storage).fetch_recent_events()[0]
            self.assertTrue(event['access_time']['night'])
            self.assertIn('policy_id',event['access_time'])
            self.assertIn('심야',_time_badge(event))
            self.assertNotIn('현재 정책으로 재평가',_time_badge(event))
        finally:
            storage.close()
