import html
import json
import re
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from soc.source_trends import source_scope


class SourceScopeTests(unittest.TestCase):
    def test_all_pages_and_collection_mode_share_chart_scope(self):
        now=datetime(2026,11,26,12,tzinfo=timezone.utc)
        rows=[{'event_ts_utc':'2026-11-26T11:30:00Z','event_type':'login_failed','ingest_mode':'live'} for _ in range(1005)]
        rows.append({'event_ts_utc':'2026-11-26T11:30:00Z','event_type':'login_success','ingest_mode':'replay'})
        class Store:
            def list_recent_events(self,limit,offset,**kw):
                self.scope=kw
                return rows[offset:offset+limit]
        store=Store()
        events,controls,panel=source_scope(store,'erp',{'range':'1h','mode':'live'},now)
        self.assertEqual(len(events),1005)
        self.assertIn('로그인 실패 1,005건',panel)
        data=json.loads(html.unescape(re.search(r'data-chart="([^"]+)"',panel).group(1)))
        self.assertEqual(sum(r['failure'] for r in data['rows']),1005)
        self.assertIn('mode=live',data['rows'][0]['href'])
        self.assertEqual(store.scope['since_utc'].hour,11)

    def test_proxy_statuses_exclude_waf_and_empty_has_no_chart(self):
        now=datetime(2026,11,26,12,tzinfo=timezone.utc)
        class Store:
            def list_recent_events(self,**kw):
                return [{'event_ts_utc':'2026-11-26T11:30:00Z','event_type':kind,'status_code':status} for kind,status in [('http_request',403),('http_request',503),('waf_blocked',403)]]
        events,_,panel=source_scope(Store(),'caddy',{},now)
        self.assertEqual(len(events),2)
        self.assertIn('전체 요청 2건 · 4xx 응답 1건 · 5xx 응답 1건',panel)
        class Empty:
            def list_recent_events(self,**kw): return []
        _,_,panel=source_scope(Empty(),'waf',{},now)
        self.assertIn('해당 기간 기록 없음',panel)
        self.assertNotIn('data-chart=',panel)
