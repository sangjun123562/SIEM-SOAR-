import http.cookiejar
import json
import os
import re
import sys
import threading
import unittest
from datetime import date
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from soc.ai_draft import (AiConfig, AiError, Masker, RateLimiter, build_facts, extract_numbers, generate,
                          invalid_numbers)
from soc.dashboard import AuthConfig, DbDashboardStore, make_handler, parse_user_roles
from soc.reports import ReportRepository, report_key, report_period
from soc.storage import SQLiteSocStorage

WEEK = date(2026, 11, 23)
SNAPSHOT = {
    "metrics": {"신규 사건": 10, "ERP 계정 자동 잠금": 4, "IP 차단 요청": 3, "IP 차단 적용": 3, "IP 차단 거부": 0,
                "차단으로 막은 접속 시도": None},
    "open": {"action": 1, "review": 9},
    "open_cases": {"action": [{"id": "INC-1", "title": "Repeated login failures: bob from 172.28.10.11",
                               "severity": "high", "target_ip": "172.28.10.11", "age_hours": 28}], "review": []},
    "unsettled": {"pending": 0}, "effect": {"state": "none", "reason": "x"}, "excluded": {"incidents": 72},
    "cases": [{"id": "INC-1", "title": "Repeated login failures: bob from 172.28.10.11", "severity": "high",
               "target_ip": "172.28.10.11", "username": "bob", "new": True, "locks": 1, "ip": ["applied"]}],
    "daily": [{"date": "2026-11-26", "cases": 8, "locks": 1, "requests": 1}, {"date": "2026-11-27", "cases": 2, "locks": 0, "requests": 0}],
}


def openai_reply(text):
    return {"choices": [{"message": {"content": text}}]}


class ConfigAndLimiterTests(unittest.TestCase):
    def test_enabled_needs_flag_and_key_and_never_prints_key(self):
        self.assertFalse(AiConfig({"SOC_AI_ENABLED": "1"}).enabled)
        self.assertFalse(AiConfig({"SOC_AI_API_KEY": "sk-secret"}).enabled)
        config = AiConfig({"SOC_AI_ENABLED": "1", "SOC_AI_API_KEY": "sk-secret"})
        self.assertTrue(config.enabled)
        self.assertNotIn("sk-secret", repr(config))

    def test_rate_limit_is_per_user_and_expires(self):
        now = [0.0]
        limiter = RateLimiter(limit=3, window=60, clock=lambda: now[0])
        self.assertEqual([limiter.allow("a") for _ in range(4)], [True, True, True, False])
        self.assertTrue(limiter.allow("b"))            # 다른 사용자는 영향 없음
        now[0] = 61
        self.assertTrue(limiter.allow("a"))            # 1분이 지나면 다시 가능


class MaskingAndNumbersTests(unittest.TestCase):
    def test_ip_and_account_are_masked_and_restored(self):
        masker = Masker()
        facts = build_facts(SNAPSHOT, WEEK, "weekly", masker)
        sent = json.dumps(facts, ensure_ascii=False)
        self.assertNotIn("172.28.10.11", sent)
        self.assertNotIn("bob", sent)
        self.assertIn("IP-1", sent)
        self.assertEqual(masker.unmask("IP-1에서 계정-1 로그인 실패"), "172.28.10.11에서 bob 로그인 실패")

    def test_facts_do_not_invent_values(self):
        facts = build_facts(SNAPSHOT, WEEK, "weekly", Masker())
        self.assertEqual(facts["사건 집계"]["차단으로 막은 접속 시도"], "집계 불가")        # 못 센 것은 0이 아니다
        self.assertEqual(facts["신규 사건이 가장 많았던 날"]["전체 대비 비율(%)"], 80)
        self.assertEqual(facts["재생·합성 근거라 집계에서 뺀 사건"], 72)

    def test_number_check_rejects_unknown_numbers_and_ignores_mask_tokens(self):
        facts = build_facts(SNAPSHOT, WEEK, "weekly", Masker())
        self.assertEqual(invalid_numbers("신규 사건 10건 중 IP-1 관련 8건이 전체의 80%였다.", facts), [])
        self.assertEqual(invalid_numbers("신규 사건이 15건이었다.", facts), ["15"])
        self.assertEqual(extract_numbers("1,234건과 IP-7, 계정-2"), {"1234"})


class GenerateTests(unittest.TestCase):
    CONFIG = AiConfig({"SOC_AI_ENABLED": "1", "SOC_AI_API_KEY": "sk-test", "SOC_AI_MODEL": "test-model"})

    def test_valid_draft_is_returned_with_original_values_and_nothing_sensitive_is_sent(self):
        sent = []

        def transport(body):
            sent.append(body.decode())
            return openai_reply("IP-1에서 로그인 실패가 반복돼 신규 사건 10건 중 8건이 몰렸다. 확인 필요하다.")

        text = generate(self.CONFIG, SNAPSHOT, WEEK, "weekly", transport=transport)
        self.assertIn("172.28.10.11", text)                      # 받은 글에서만 원래 값으로 되돌린다
        self.assertNotIn("172.28.10.11", sent[0])                # 밖으로 나간 요청에는 원문이 없다
        self.assertNotIn("bob", sent[0])
        self.assertNotIn("sk-test", sent[0])                     # 키는 본문에 없다(헤더로만 간다)
        self.assertIn('"model": "test-model"', sent[0])

    def test_unknown_numbers_trigger_one_retry_then_succeed(self):
        replies = iter(["신규 사건이 99건이었다.", "신규 사건은 10건이었다."])
        text = generate(self.CONFIG, SNAPSHOT, WEEK, "weekly", transport=lambda body: openai_reply(next(replies)))
        self.assertEqual(text, "신규 사건은 10건이었다.")

    def test_draft_with_unknown_numbers_is_discarded_after_retry(self):
        with self.assertRaises(AiError) as caught:
            generate(self.CONFIG, SNAPSHOT, WEEK, "weekly", transport=lambda body: openai_reply("신규 사건이 99건이었다."))
        self.assertIn("집계와 맞지 않아", str(caught.exception))

    def test_bad_shapes_and_unsupported_field_are_reported(self):
        with self.assertRaises(AiError):
            generate(self.CONFIG, SNAPSHOT, WEEK, "weekly", transport=lambda body: {"unexpected": 1})
        with self.assertRaises(AiError):
            generate(self.CONFIG, SNAPSHOT, WEEK, "weekly", field="assessment", transport=lambda body: openai_reply("x"))


class HttpTests(unittest.TestCase):
    def _server(self):
        storage = SQLiteSocStorage()
        self.addCleanup(storage.close)
        auth = AuthConfig(username="ops", password="test", roles=parse_user_roles("", "ops"))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(DbDashboardStore(storage), auth_config=auth))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            thread.join()
            server.server_close()
        self.addCleanup(stop)
        return storage, f"http://127.0.0.1:{server.server_port}"

    def _login(self, base, username="approver1"):
        client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        client.open(base + "/login", urlencode({"username": username, "password": "test"}).encode()).close()
        return client

    def _token(self, client, base):
        with client.open(base + "/reports?week=2026-11-23") as response:
            return re.search(r'name="csrf_token" value="([^"]+)"', response.read().decode()).group(1)

    def test_button_and_endpoint_are_off_by_default(self):
        _, base = self._server()
        client = self._login(base)
        with mock.patch.dict(os.environ, {"SOC_AI_ENABLED": "0", "SOC_AI_API_KEY": ""}):
            with client.open(base + "/reports?week=2026-11-23") as response:
                page = response.read().decode()
            self.assertNotIn("data-ai=", page)
            token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
            with self.assertRaises(HTTPError) as caught:
                client.open(base + "/reports/ai-draft", urlencode({"csrf_token": token, "week": "2026-11-23"}).encode())
            self.assertEqual(caught.exception.code, 404)
            caught.exception.close()

    def test_enabled_flow_requires_csrf_and_permission_and_limits_calls(self):
        storage, base = self._server()
        env = {"SOC_AI_ENABLED": "1", "SOC_AI_API_KEY": "sk-test"}
        with mock.patch.dict(os.environ, env), mock.patch("soc.dashboard.ai_generate", return_value="AI가 쓴 초안") as stub, \
                mock.patch("soc.dashboard._AI_LIMITER", RateLimiter(limit=2)):
            editor = self._login(base)
            with editor.open(base + "/reports?week=2026-11-23") as response:
                page = response.read().decode()
            self.assertIn('data-ai="summary"', page)
            token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
            post = lambda client, tok: client.open(base + "/reports/ai-draft", urlencode(
                {"csrf_token": tok, "week": "2026-11-23", "kind": "weekly", "field": "summary"}).encode())
            with self.assertRaises(HTTPError) as bad_csrf:
                post(editor, "wrong")
            self.assertEqual(bad_csrf.exception.code, 403)
            bad_csrf.exception.close()
            with post(editor, token) as response:
                self.assertEqual(json.loads(response.read()), {"ok": True, "text": "AI가 쓴 초안"})
            with post(editor, token):
                pass
            with self.assertRaises(HTTPError) as limited:
                post(editor, token)
            self.assertEqual(limited.exception.code, 429)
            limited.exception.close()
            self.assertEqual(stub.call_count, 2)
            viewer = self._login(base, "analyst1")                      # 읽기 전용 역할
            with viewer.open(base + "/reports?week=2026-11-23") as response:
                self.assertNotIn("data-ai=", response.read().decode())   # 버튼도 안 보인다
            with self.assertRaises(HTTPError) as denied:
                post(viewer, token)
            self.assertEqual(denied.exception.code, 403)
            denied.exception.close()

    def test_ai_usage_is_recorded_on_the_saved_report_and_shown_to_readers(self):
        storage, base = self._server()
        with mock.patch.dict(os.environ, {"SOC_AI_ENABLED": "1", "SOC_AI_API_KEY": "sk-test"}):
            editor = self._login(base)
            token = self._token(editor, base)
            form = {"week": "2026-11-23", "csrf_token": token, "intent": "draft", "summary": "AI 초안을 고친 결론", "ai_summary": "1"}
            with editor.open(base + "/reports?week=2026-11-23", urlencode(form).encode()) as response:
                page = response.read().decode()
            self.assertIn("AI 초안을 바탕으로 사람이 고쳐 썼습니다", page)
            saved = ReportRepository(storage).get(report_key(report_period("2026-11-23", "weekly"), "weekly"))
            self.assertEqual(saved["ai"], {"summary": True})
            form.update(ai_summary="0", summary="직접 쓴 결론")
            with editor.open(base + "/reports?week=2026-11-23", urlencode(form).encode()) as response:
                self.assertNotIn("AI 초안을 바탕으로", response.read().decode())


if __name__ == "__main__":
    unittest.main()
