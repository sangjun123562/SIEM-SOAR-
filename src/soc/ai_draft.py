"""보고서 'AI 초안'. 서버가 이미 집계한 숫자만 가려서 보내고, 받은 글의 숫자를 검증한다.

원칙(바꾸지 말 것)
- 원본 로그·요청 본문·비밀번호는 보내지 않는다. 건수·비율·경과일·상태 라벨과, 가린 사건 제목만 보낸다.
- IP와 계정명은 IP-1, 계정-1 로 바꿔 보내고, 받은 글에서만 원래 값으로 되돌린다.
- AI가 쓴 글의 모든 숫자는 보낸 사실에 실제로 있는 값이어야 한다. 하나라도 없으면 그 초안은 버린다.
- 외부 호출은 이 파일의 call_api 한 곳뿐이다. 키는 환경 변수에서만 읽고 어디에도 기록하지 않는다.
- 결과는 입력칸에 채워 줄 뿐이다. 저장과 확정은 사람이 한다.
"""
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import timedelta

LOG = logging.getLogger("soc.ai")
API_URL = "https://api.openai.com/v1/chat/completions"
# 프로젝트가 쓸 수 있는 모델은 계정마다 다르다. 다른 모델을 쓰려면 SOC_AI_MODEL 로 바꾼다.
DEFAULT_MODEL = "gpt-4o-mini"
MAX_CASES_SENT = 5
RATE_LIMIT_PER_MINUTE = 3
SEVERITY_WORDS = {"critical": "긴급", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}
INGEST_WORDS = {"ok": "이상 없음", "gap": "공백 의심", "sparse": "활동 적음", "no_data": "구분 불가"}
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOKEN = re.compile(r"(?:IP|계정)-\d+")
NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")


class AiConfig:
    """환경 변수에서 읽은 설정. 꺼져 있거나 키가 없으면 enabled 가 False 다."""

    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.key = (env.get("SOC_AI_API_KEY") or "").strip()
        self.on = (env.get("SOC_AI_ENABLED") or "").strip().lower() in {"1", "true", "yes", "on"}
        self.model = (env.get("SOC_AI_MODEL") or DEFAULT_MODEL).strip()
        self.timeout = int(env.get("SOC_AI_TIMEOUT") or 20)

    @property
    def enabled(self):
        return self.on and bool(self.key)

    def __repr__(self):  # 키가 로그나 오류 문구에 새지 않게 한다
        return f"AiConfig(enabled={self.enabled}, model={self.model!r})"


class RateLimiter:
    """사용자당 분당 호출 수 제한."""

    def __init__(self, limit=RATE_LIMIT_PER_MINUTE, window=60.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, user):
        now = self.clock()
        with self._lock:
            hits = self._hits[user]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


class Masker:
    """IP와 계정명을 되돌릴 수 있게 가린다."""

    def __init__(self):
        self.forward = {}
        self.reverse = {}

    def _token(self, value, prefix):
        if value not in self.forward:
            token = f"{prefix}-{sum(1 for t in self.reverse if t.startswith(prefix + '-')) + 1}"
            self.forward[value] = token
            self.reverse[token] = value
        return self.forward[value]

    def learn_ip(self, value):
        return self._token(value, "IP") if value else ""

    def learn_account(self, value):
        return self._token(value, "계정") if value else ""

    def mask(self, text):
        text = str(text or "")
        for value in sorted(self.forward, key=len, reverse=True):
            if not IPV4.fullmatch(value):
                text = text.replace(value, self.forward[value])
        return IPV4.sub(lambda m: self.learn_ip(m.group(0)), text)

    def unmask(self, text):
        return TOKEN.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)


def _days(hours):
    return f"{hours // 24}일" if hours >= 24 else f"{hours}시간"


def build_facts(snapshot, week, kind, masker):
    """AI에 보낼 사실 묶음. 스냅샷에 없는 값은 만들지 않고, 못 센 것은 '집계 불가'로 적는다."""
    metrics = snapshot.get("metrics") or {}
    open_counts = snapshot.get("open") or {}
    open_cases = snapshot.get("open_cases") or {}
    for case in snapshot.get("cases", []):
        masker.learn_ip(case.get("target_ip"))
        masker.learn_account(case.get("username"))
    for items in open_cases.values():
        for item in items:
            masker.learn_ip(item.get("target_ip"))

    def oldest(group):
        items = open_cases.get(group) or []
        return _days(int(items[0]["age_hours"])) if items else "미결 없음"

    effect = snapshot.get("effect") or {}
    if effect.get("state") == "ok":
        block_effect = {"차단 시간 중 같은 IP의 로그인 성공": effect.get("success"),
                        "차단으로 막은 접속 시도": effect.get("attempts")}
    else:
        block_effect = {"상태": "산출 대상 없음" if effect.get("state") == "none" else "집계 불가"}
    daily = snapshot.get("daily") or []
    peak = max(daily, key=lambda row: row.get("cases", 0), default=None)
    total_new = sum(row.get("cases", 0) for row in daily)
    facts = {
        "기간": f"{week} ~ {week + timedelta(days=(6 if kind == 'weekly' else 27))}",
        "보고서 유형": "월간" if kind == "monthly" else "주간",
        "사건 집계": {k: ("집계 불가" if v is None else v) for k, v in metrics.items()},
        "미결 사건": {"조치 대기": open_counts.get("action", 0), "판단 대기": open_counts.get("review", 0),
                   "조치 대기 중 가장 오래된 건": oldest("action"), "판단 대기 중 가장 오래된 건": oldest("review")},
        "차단 효과": block_effect,
        "미확정 차단": sum((snapshot.get("unsettled") or {}).values()),
        "재생·합성 근거라 집계에서 뺀 사건": (snapshot.get("excluded") or {}).get("incidents", 0),
    }
    if peak and total_new and peak.get("cases"):
        facts["신규 사건이 가장 많았던 날"] = {"날짜": peak["date"], "건수": peak["cases"],
                                         "전체 대비 비율(%)": round(100 * peak["cases"] / total_new)}
    extra = snapshot.get("extra") or {}
    if extra:
        facts["추가 지표"] = {
            "WAF 판정": (extra.get("waf") or {}).get("total"),
            "ERP 문서 열람": {k: (extra.get("doc_read") or {}).get(k) for k in ("total", "ok", "unauth", "forbidden", "missing")},
            "로그인 실패 재발": {"IP 수": (extra.get("recur") or {}).get("ips"), "계정 수": (extra.get("recur") or {}).get("accounts")}}
    ingest = (snapshot.get("ingest") or {}).get("sources") or []
    if ingest:
        facts["로그 수집 상태"] = {str(s.get("label")): INGEST_WORDS.get(s.get("state"), "미확인") for s in ingest}
    cases = []
    for case in snapshot.get("cases", [])[:MAX_CASES_SENT]:
        cases.append({"심각도": SEVERITY_WORDS.get(str(case.get("severity") or "").lower(), "미지정"),
                      "제목": masker.mask(case.get("title")), "신규 여부": "신규" if case.get("new") else "후속",
                      "계정 자동 잠금": case.get("locks", 0), "IP 차단 요청 상태": list(case.get("ip") or [])})
    if cases:
        facts["대표 사건(최대 5건)"] = cases
    return facts


def extract_numbers(text):
    """글 속 숫자를 문자열로 뽑는다. 쉼표는 지운다. IP-1, 계정-1 같은 가림 표기 속 숫자는 제외한다."""
    cleaned = TOKEN.sub(" ", str(text))
    return {m.replace(",", "").rstrip(".") for m in NUMBER.findall(cleaned)}


def invalid_numbers(text, facts):
    """text 에 있는데 facts 에는 없는 숫자."""
    allowed = extract_numbers(json.dumps(facts, ensure_ascii=False))
    allowed |= {n.lstrip("0") or "0" for n in allowed}
    return sorted(n for n in extract_numbers(text) if n not in allowed and (n.lstrip("0") or "0") not in allowed)


SYSTEM_RULES = (
    "당신은 보안관제 보고서의 초안을 쓰는 보조자입니다. 반드시 지킬 규칙:\n"
    "1) 아래 사실 JSON에 있는 숫자만 쓴다. 계산해서 새 숫자를 만들거나 어림짐작하지 않는다.\n"
    "2) 침해 여부를 단정하지 않는다. 확정할 수 없는 것은 '확인 필요'라고 쓴다.\n"
    "3) '집계 불가'나 '산출 대상 없음'인 항목은 0건이라고 쓰지 말고 그대로 밝힌다.\n"
    "4) IP-1, 계정-1 같은 표기는 그대로 둔다.\n"
    "5) 보고서 문체로 쓴다. 문장 끝은 '~했다', '~이다', '~필요하다' 같은 평서형으로 한다.\n"
    "6) 마크다운, 제목, 목록 기호 없이 본문만 출력한다.")

FIELD_TASKS = {
    "summary": "이 기간의 핵심 판단을 1~3문장으로 쓰세요. 무슨 일이 있었는지, 위험한지, 사람이 지금 할 일이 있는지가 들어가야 합니다.",
}


def build_prompt(facts, field, retry_numbers=()):
    task = FIELD_TASKS[field]
    user = f"{task}\n\n사실 JSON:\n{json.dumps(facts, ensure_ascii=False, indent=1)}"
    if retry_numbers:
        user += ("\n\n앞선 답에 사실 JSON에 없는 숫자가 있었습니다: " + ", ".join(retry_numbers)
                 + ". 이 숫자를 쓰지 말고 다시 쓰세요.")
    return SYSTEM_RULES, user


class AiError(Exception):
    """사용자에게 그대로 보여 줘도 되는 한 줄 사유."""


def call_api(config, system, user, transport=None):
    """OpenAI Chat Completions 한 번 호출. transport 는 시험에서 가짜로 바꾸는 자리다."""
    body = json.dumps({"model": config.model, "max_completion_tokens": 600,
                       "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}).encode()
    if transport is not None:
        return transport(body)
    request = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "content-type": "application/json", "authorization": f"Bearer {config.key}"})
    try:
        with urllib.request.urlopen(request, timeout=config.timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        exc.close()
        reasons = {401: "AI 키가 올바르지 않습니다. 관리자에게 알려 주세요.",
                   403: "이 프로젝트에는 이 모델을 쓸 권한이 없습니다. 모델 설정을 확인하세요.",
                   404: "설정한 AI 모델을 찾지 못했습니다. SOC_AI_MODEL 을 확인하세요.",
                   429: "AI 호출 한도나 크레딧을 넘었습니다. 잠시 뒤 다시 시도하거나 결제 설정을 확인하세요."}
        raise AiError(reasons.get(exc.code, f"AI 서비스 오류({exc.code})입니다. 잠시 뒤 다시 시도하세요.")) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AiError("AI 서비스에 연결하지 못했습니다. 보고서는 계속 직접 쓸 수 있습니다.") from None
    return data


def _text_of(data):
    try:
        return str(data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError):
        raise AiError("AI 응답 형식을 읽지 못했습니다.") from None


def generate(config, snapshot, week, kind, field="summary", transport=None):
    """초안 한 번 만들기. 숫자 검증에 실패하면 한 번 더 시도하고, 그래도 안 되면 버린다."""
    if field not in FIELD_TASKS:
        raise AiError("아직 이 칸은 AI 초안을 지원하지 않습니다.")
    masker = Masker()
    facts = build_facts(snapshot, week, kind, masker)
    bad = ()
    for _ in range(2):
        system, user = build_prompt(facts, field, bad)
        text = _text_of(call_api(config, system, user, transport))
        if not text:
            raise AiError("AI가 빈 답을 보냈습니다. 다시 시도하세요.")
        bad = invalid_numbers(text, facts)
        if not bad:
            return masker.unmask(text)
    raise AiError("AI 초안의 숫자가 집계와 맞지 않아 쓰지 않았습니다. 다시 시도해 주세요.")
