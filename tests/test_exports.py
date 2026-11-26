import csv
import io
import json
import sys
import unittest
import threading
import http.cookiejar
from http.server import ThreadingHTTPServer
from urllib.request import build_opener, HTTPCookieProcessor
from urllib.error import HTTPError
from urllib.parse import urlencode
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from soc.exports import build_export, export_controls


class ExportTests(unittest.TestCase):
    def store(self, rows):
        return SimpleNamespace(list_recent_events=lambda limit, offset, **kw: rows[offset:offset+limit])

    def test_all_pages_filters_and_formula_safety(self):
        rows = [dict(source='erp', event_type='login_failed', outcome='failure', username='=1+1', ingest_mode='replay', raw_id=str(n)) for n in range(1005)]
        rows.append(dict(source='gateway', event_type='fw_allow', outcome='success'))
        filename, content_type, body = build_export(self.store(rows), {'kind':'events', 'chip':'erp', 'page':'2'})
        result = list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
        self.assertEqual(len(result), 1005)
        self.assertEqual(result[0]['username'], "'=1+1")
        self.assertEqual(result[0]['전체_건수'], '1005')
        self.assertEqual(result[0]['ingest_mode'], 'replay')

    def test_flow_is_exact_request_and_keeps_both_sources(self):
        rows = [dict(source=s, request_id=r, raw_id=s+r) for s,r in [('erp','one'),('caddy','one'),('erp','two')]]
        _, _, body = build_export(self.store(rows), {'kind':'flow','request_id':'one'})
        self.assertEqual(len(json.loads(body)['events']), 2)

    def test_empty_and_invalid_export(self):
        _, _, body = build_export(self.store([]), {'kind':'events'})
        self.assertEqual(list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))[0]['전체_건수'], '0')
        with self.assertRaises(ValueError):
            build_export(self.store([]), {'kind':'events','from':'invalid'})
        self.assertEqual(export_controls('/reports'), '')

    def test_download_route_requires_login_and_returns_attachment(self):
        from soc.dashboard import AuthConfig, DbDashboardStore, make_handler
        from soc.storage import SQLiteSocStorage
        storage = SQLiteSocStorage()
        self.addCleanup(storage.close)
        handler = make_handler(DbDashboardStore(storage), auth_config=AuthConfig(username='ops', password='test'))
        with ThreadingHTTPServer(('127.0.0.1', 0), handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            base = f'http://127.0.0.1:{server.server_port}'
            client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            try:
                with self.assertRaises(HTTPError) as caught:
                    client.open(base+'/exports?kind=events')
                self.assertEqual(caught.exception.code, 401)
                caught.exception.close()
                client.open(base+'/login', urlencode({'username':'ops','password':'test'}).encode()).close()
                with client.open(base+'/exports?kind=events') as response:
                    self.assertIn('attachment;', response.headers['Content-Disposition'])
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                    self.assertTrue(response.read().startswith(b'\xef\xbb\xbf'))
                with client.open(base+'/events') as response:
                    self.assertIn('CSV 저장', response.read().decode())
            finally:
                server.shutdown()
                worker.join()


if __name__ == '__main__':
    unittest.main()
