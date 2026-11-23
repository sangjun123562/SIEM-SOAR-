"""자료실 문서와 열람 권한 규칙.

이 파일은 DB·Flask 없이 동작한다(권한 규칙만 따로 시험하기 위해).

등급 규칙
- public(일반): 로그인한 모든 사용자
- dept(부서): 같은 부서 소속 사용자
- secret(기밀): 같은 부서의 팀장(manager)만
다른 부서의 문서는 등급이 일반이 아니면 열 수 없다. 보안팀도 예외가 아니다.
"""
import uuid

LEVELS = ("public", "dept", "secret")
LEVEL_LABEL = {"public": "일반", "dept": "부서", "secret": "기밀"}

# 문서 번호는 제목에서 만든 고정 UUID라 다시 시작해도 바뀌지 않는다(화면·로그에서 쓰는 번호).
_NS = uuid.UUID("6f1d7c0e-3c1a-4d57-9b5e-0a6f1d7c0e31")


def doc_id(title):
    return str(uuid.uuid5(_NS, title))


# (제목, 부서 — 일반 문서는 None, 등급, 본문)
SEED_DOCUMENTS = [
    ("포털 이용 안내", None, "public",
     "업무 계정으로 로그인한 뒤 자료실에서 열람 가능한 문서를 확인합니다.\n"
     "문서 등급은 일반, 부서, 기밀 세 단계이며 등급에 맞는 문서만 목록에 표시됩니다."),
    ("정보 보호 기본 수칙", None, "public",
     "1. 계정은 본인만 사용하고 공유하지 않습니다.\n"
     "2. 업무가 끝나면 로그아웃합니다.\n"
     "3. 의심스러운 접속이나 권한 문제는 정보보안과에 알립니다."),
    ("문서 등급 분류 기준", None, "public",
     "일반: 전 직원 공개 문서.\n부서: 해당 부서 직원만 열람하는 업무 문서.\n"
     "기밀: 해당 부서 팀장만 열람하는 문서. 다른 부서는 열람 요청 절차를 거쳐야 합니다."),

    ("영업 업무 절차 안내", "영업", "dept",
     "거래처 문의 접수 → 견적 작성 → 팀장 검토 → 회신 순서로 처리합니다.\n"
     "견적서 양식과 회신 기한은 부서 내부 기준을 따릅니다."),
    ("영업팀 거래처 응대 지침", "영업", "secret",
     "거래처별 특약 조건과 응대 원칙을 정리한 팀장용 문서입니다.\n팀장은 부서원에게 필요한 범위만 공유합니다."),

    ("인사 업무 절차 안내", "인사", "dept",
     "채용 공고 → 서류 검토 → 면접 → 입사 처리 순서로 진행합니다.\n근태 정정 요청은 인사총무과로 접수합니다."),
    ("급여 지급 규정", "인사", "secret",
     "급여 산정 기준과 지급일, 공제 항목을 다루는 인사 팀장용 문서입니다.\n개인별 급여 정보는 이 문서 밖에서 관리합니다."),
    ("인사 평가 기준", "인사", "secret",
     "평가 항목과 등급 산정 방식, 이의 신청 절차를 정리한 팀장용 문서입니다."),

    ("보안 업무 절차 안내", "보안", "dept",
     "경보 확인 → 사건 분류 → 조치 승인 요청 → 결과 기록 순서로 처리합니다.\n"
     "관제 대시보드의 승인 권한은 별도 절차로 부여합니다."),
    ("계정 발급 및 회수 절차", "보안", "secret",
     "신규 계정 발급, 권한 변경, 퇴사자 계정 회수의 승인 단계와 기록 기준을 다룹니다.\n정보보안과 팀장만 열람합니다."),
]


def can_read(user, document):
    """(허용 여부, 이유)를 돌려준다. user는 {'department', 'role'}, document는 {'department', 'level'}."""
    level = document["level"]
    if level == "public":
        return True, "일반 문서"
    if document["department"] != user["department"]:
        return False, "다른 부서 문서"
    if level == "dept":
        return True, "같은 부서"
    if level == "secret":
        if user["role"] == "manager":
            return True, "같은 부서 팀장"
        return False, "기밀 문서는 팀장만 열람"
    return False, "알 수 없는 등급"


# ───────────── 열람 권한 요청 (일반 문서는 대상이 아니다) ─────────────
DEFAULT_GRANT_MINUTES = 60
MIN_GRANT_MINUTES = 5
MAX_GRANT_MINUTES = 120


def can_request(user, document):
    """열람 권한을 요청할 수 있는 문서인지 확인한다. 이미 볼 수 있거나 일반 문서는 요청할 필요가 없다."""
    if document["level"] == "public":
        return False, "일반 문서는 요청 없이 열람할 수 있음"
    if can_read(user, document)[0]:
        return False, "이미 열람할 수 있는 문서"
    return True, "요청 가능"


def _owning_manager(user, document, action):
    """문서 소속 부서의 팀장인지 확인한다(승인·반려·회수가 같은 규칙). action은 안내 문구에만 쓴다."""
    if document["level"] == "public":
        return False, "일반 문서는 요청 대상이 아님"
    if user["role"] != "manager" or user["department"] != document["department"]:
        return False, f"문서 소속 부서 팀장만 {action}할 수 있음"
    return True, f"{action} 가능"


def can_decide(approver, document, requester_id, approver_id):
    """요청을 승인·반려할 수 있는 사람인지 확인한다. 본인 요청은 처리할 수 없고, 문서 소속 부서의 팀장만 처리한다."""
    if requester_id == approver_id:
        return False, "본인 요청은 처리할 수 없음"
    return _owning_manager(approver, document, "처리")


def clamp_grant_minutes(value):
    """승인 시간(분)을 정수로 바꾸고 허용 범위로 맞춘다. 숫자가 아니면 None."""
    if value is None:
        return DEFAULT_GRANT_MINUTES
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return max(MIN_GRANT_MINUTES, min(MAX_GRANT_MINUTES, value))


def can_revoke(revoker, document):
    """승인된 임시 권한을 회수할 수 있는 사람인지 확인한다. 문서 소속 부서 팀장만 회수한다."""
    return _owning_manager(revoker, document, "회수")
