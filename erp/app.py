"""가상 기관 포털 — 보안관제 시연용 Flask 앱(로그인 + 부서·등급별 자료실 열람 차단).

읽는 순서: 1 설정 → 2 로그 → 3 요청마다 하는 일 → 4 로그인·세션·로그아웃 → 5 자료실

핵심 약속
- 로그인·로그아웃·문서 열람의 성공과 실패를 erp.jsonl에 한 줄씩 남긴다(관제 시스템이 읽는다).
- 권한이 없는 문서는 열람 요청 절차 없이 403으로 막고, 그 시도를 기록한다.
- 비밀번호, 쿠키, 요청 본문은 로그에 남기지 않는다.
- 접속자 IP(X-Client-IP)는 '직접 연결한 상대가 Caddy일 때만' 믿는다. 그 밖에는 소켓 IP를 쓴다.
- 상태를 바꾸는 요청은 기록을 먼저 남기고 커밋한다(기록이 실패하면 변경도 저장되지 않는다).
"""
import datetime
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import uuid
from urllib.parse import urlsplit

import psycopg
from flask import Flask, g, jsonify, request, send_from_directory, session
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash

import account_lock
import documents
import login_access

# ───────────────────────── 1. 설정 ─────────────────────────
DB_DSN = os.environ["ERP_DB_DSN"]                        # ERP 전용 DB 접속 문자열
TRUSTED_PROXY_IP = os.environ.get("TRUSTED_PROXY_IP", "172.28.20.5")   # 믿는 프록시(Caddy)의 IP
# 시험 단말 A와 B에서만 ERP 로그인을 허용한다. 단말 X는 기본적으로 허용 목록 밖이다.
LOGIN_ALLOWED_IPS = frozenset({"172.28.10.11", "172.28.10.12"})
LOGIN_ACCESS_TOKEN = os.environ.get("ERP_LOGIN_ACCESS_TOKEN", "")
LOGIN_ACCESS_CONTROLLER_IP = "10.250.31.60"
LOG_PATH = os.environ.get("ERP_LOG", "/var/log/erp/erp.jsonl")
LOG_MAX_BYTES = 10 * 1024 * 1024                         # 10MiB가 되면 새 파일로 교체
LOG_KEEP = 2
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=os.environ["ERP_SECRET_KEY"],             # 세션 쿠키 서명용(저장소에 올리지 않음)
    SESSION_COOKIE_NAME="__Host-erp_session",            # __Host- 접두어: HTTPS 전용, 도메인 고정
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,                        # 자바스크립트가 쿠키를 읽지 못한다
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_PATH="/",
    PERMANENT_SESSION_LIFETIME=3600,                     # 1시간
)

# 시험용 사용자. 비밀번호는 환경 변수(.env, 저장소에 올리지 않음)에서 받는다.
DEMO_USERS = [
    # (사용자명, 환경변수 이름, 부서, 직급)
    ("alice", "DEMO_PW_ALICE", "영업", "member"),    # 영업 사원
    ("bob", "DEMO_PW_BOB", "영업", "manager"),       # 영업 팀장
    ("carol", "DEMO_PW_CAROL", "보안", "member"),    # 보안 사원
    ("dave", "DEMO_PW_DAVE", "인사", "manager"),     # 인사 팀장
    ("erin", "DEMO_PW_ERIN", "인사", "member"),      # 인사 사원
    ("frank", "DEMO_PW_FRANK", "보안", "manager"),   # 보안 팀장
]
# 없는 사용자도 같은 시간이 걸리게 하려고 쓰는 가짜 해시(사용자 존재 여부 추측 방지)
DUMMY_HASH = generate_password_hash("not-a-real-password", method="pbkdf2:sha256")


def db():
    """시작할 때(요청 밖)만 쓰는 DB 연결. `with db() as conn:` 블록이 정상 종료되면 커밋하고 닫는다."""
    return psycopg.connect(DB_DSN, row_factory=dict_row)


def seed_users():
    """시험용 사용자가 없으면 만든다(여러 번 실행해도 안전)."""
    with db() as conn:
        for username, env_name, department, role in DEMO_USERS:
            password = os.environ.get(env_name)
            if not password:
                continue
            # 이미 있는 계정은 비밀번호를 건드리지 않고 부서·직급만 맞춘다.
            conn.execute(
                "INSERT INTO users (username, password_hash, department, role) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (username) DO UPDATE SET department = EXCLUDED.department, role = EXCLUDED.role",
                (username, generate_password_hash(password, method="pbkdf2:sha256"), department, role),
            )


def seed_documents():
    """자료실 표와 기본 문서를 만든다(여러 번 실행해도 안전). 이미 있는 문서는 고치지 않는다."""
    with db() as conn:
        # 워커 2개가 동시에 표를 만들면 충돌하므로, 한 번에 하나만 실행되도록 잠근다(트랜잭션이 끝나면 풀린다).
        conn.execute("SELECT pg_advisory_xact_lock(8451)")
        login_access.ensure_schema(conn)
        account_lock.ensure_schema(conn)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS documents ("
            " id BIGSERIAL PRIMARY KEY,"
            " public_id UUID UNIQUE NOT NULL,"
            " title TEXT NOT NULL,"
            " department TEXT,"
            " level TEXT NOT NULL CHECK (level IN ('public', 'dept', 'secret')),"
            " body TEXT NOT NULL,"
            " created_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        for title, department, level, body in documents.SEED_DOCUMENTS:
            conn.execute(
                "INSERT INTO documents (public_id, title, department, level, body) VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (public_id) DO NOTHING",
                (documents.doc_id(title), title, department, level, body),
            )


# ───────────────────────── 2. 로그 ─────────────────────────
def _clean(text, limit=64):
    """로그에 넣을 문자열 정리: 제어문자 제거, 길이 제한."""
    return "".join(ch for ch in str(text) if ch.isprintable())[:limit]


def _rotate():
    for i in range(LOG_KEEP, 0, -1):
        src = LOG_PATH if i == 1 else f"{LOG_PATH}.{i - 1}"
        if os.path.exists(src):
            os.replace(src, f"{LOG_PATH}.{i}")


def audit(event_type, outcome, status, username=None, **extra):
    """로그 한 줄을 남긴다. 줄 전체를 한 번에 쓰므로 반쯤 쓰인 줄이 생기지 않는다."""
    rec = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "source": "erp",
        "event_type": event_type,
        "outcome": outcome,
        "ingest_mode": "live",              # 실제 요청에서 만들어진 로그
        "request_id": g.request_id,
        "client_ip": g.client_ip,
        "peer_ip": g.peer_ip,
        "client_ip_trusted": g.client_ip_trusted,
        "http_method": request.method,
        "http_path": request.path,          # 쿼리 문자열은 남기지 않는다
        "status_code": status,
    }
    if username:
        rec["username"] = _clean(username)
    for key, value in extra.items():
        rec[key] = _clean(value, 128) if isinstance(value, str) else value
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) >= LOG_MAX_BYTES:
        _rotate()
    data = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


# ───────────────────── 3. 요청마다 하는 일 ─────────────────────
@app.before_request
def identify_client():
    """누가 보낸 요청인지 정한다. 핵심 규칙: Caddy가 직접 연결했을 때만 헤더를 믿는다."""
    peer = request.remote_addr                      # 소켓으로 직접 연결한 상대(위조 불가)
    trusted = peer == TRUSTED_PROXY_IP
    client_ip, request_id = peer, None
    if trusted:
        try:
            client_ip = str(ipaddress.ip_address(request.headers.get("X-Client-IP", "")))
        except ValueError:                          # 헤더가 없거나 형식이 틀리면 믿지 않는다
            client_ip, trusted = peer, False
        candidate = request.headers.get("X-Request-ID", "")
        request_id = candidate if UUID_RE.match(candidate) else None
    g.peer_ip, g.client_ip, g.client_ip_trusted = peer, client_ip, trusted
    g.request_id = request_id or "local-" + uuid.uuid4().hex   # Caddy를 거치지 않은 요청의 임시 번호


@app.after_request
def secure_headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def _conn():
    """이 요청이 쓰는 DB 연결(요청당 한 번만 연다). 자동 커밋 상태라서 읽기는 바로 실행되고,
    쓰기·행 잠금(FOR UPDATE)은 반드시 `with conn.transaction():` 안에서 한다(정상 종료 시 커밋, 예외 시 되돌림)."""
    if "db" not in g:
        # connect_timeout: DB가 꺼졌을 때 요청이 멈춰 워커가 강제 종료되는 대신, 3초 안에 실패해 로그인하지 않은 것으로 처리한다.
        g.db = psycopg.connect(DB_DSN, row_factory=dict_row, autocommit=True, connect_timeout=3)
    return g.db


@app.teardown_request
def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        try:
            conn.close()
        except psycopg.Error:
            pass


def same_origin():
    """다른 사이트에서 몰래 보내는 요청(CSRF)을 막는다: Origin이 우리 주소여야 한다."""
    origin = request.headers.get("Origin")
    return bool(origin) and urlsplit(origin).netloc == request.headers.get("Host")


def post_api(rule):
    """POST 경로 등록. 다른 사이트에서 보낸 요청(Origin 불일치)은 본문을 보기 전에 403으로 막는다."""
    def decorator(view):
        @functools.wraps(view)
        def guarded(*args, **kwargs):
            if not same_origin():
                return fail(403, "origin denied")
            return view(*args, **kwargs)
        return app.post(rule)(guarded)
    return decorator


def fail(status, message):
    return jsonify({"error": message}), status


def _unauth(event=None, **extra):
    """로그인하지 않은 요청에 401로 답한다. event를 주면 실패 기록도 남긴다."""
    if event:
        audit(event, "failure", 401, reason="unauthenticated", **extra)
    return fail(401, "login required")


def _reject(event, status, message, reason, username=None, **extra):
    """실패를 기록하고 같은 상태 코드로 응답한다."""
    audit(event, "failure", status, username=username, reason=reason, **extra)
    return fail(status, message)


def _meta(user, doc_id, level, department, *, role=False, **more):
    """문서와 관련된 로그에 공통으로 붙이는 항목."""
    meta = {"document_id": str(doc_id), "doc_level": level, "doc_department": department or "",
            "user_department": user["department"], **more}
    if role:
        meta["user_role"] = user["role"]
    return meta


# ───────────────────────── 4. 로그인 ─────────────────────────
def current_user():
    """로그인한 사용자. 부서·직급은 쿠키 값을 믿지 않고 매 요청마다 DB에서 다시 읽는다(강등·삭제가 바로 반영된다).
    DB를 읽지 못하면 로그인하지 않은 것으로 본다(열어 주지 않는다)."""
    uid = session.get("uid")
    if uid is None:
        return None
    try:
        row = _conn().execute(
            """
            SELECT id, username, department, role, session_version,
                EXISTS (SELECT 1 FROM account_revocations WHERE user_id = users.id
                        AND restored_at IS NULL) AS is_revoked
            FROM users WHERE id = %s
            """, (uid,),
        ).fetchone()
    except psycopg.Error:
        close_db()                                   # 끊어진 연결은 버린다
        return None
    if row is None or row.get("is_revoked") or session.get("version", 0) != row.get("session_version", 0):
        session.clear()
        return None
    return row


@app.get("/")
def home():
    return send_from_directory(os.path.join(os.path.dirname(__file__), "static"), "index.html")


@app.get("/api/session")
def get_session():
    user = current_user()
    if not user:
        return _unauth()
    return jsonify({k: user[k] for k in ("username", "department", "role")})


@post_api("/api/login")
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    username, password = data.get("username"), data.get("password")
    valid_input = (
        isinstance(username, str) and isinstance(password, str)
        and 0 < len(username) <= 254 and len(password) <= 1024
    )
    allowed_ip = g.client_ip_trusted and g.client_ip in LOGIN_ALLOWED_IPS
    access_requested = False
    # X에서도 승인된 계정만 비밀번호 확인 단계로 넘어간다.
    if (not allowed_ip and LOGIN_ACCESS_TOKEN and valid_input and len(username) <= 64 and username.isprintable()
            and g.client_ip_trusted and g.client_ip == login_access.X_LOGIN_IP and UUID_RE.fullmatch(g.request_id)):
        try:
            allowed_ip = login_access.can_log_in(_conn(), g.request_id, username, g.client_ip)
            access_requested = not allowed_ip
        except psycopg.Error:
            close_db()

    # Caddy가 확인한 출발지만 믿는다. 허용하지 않은 출발지는 비밀번호를 확인하기 전에 거부한다.
    if not allowed_ip:
        reason = "source_not_allowed" if g.client_ip_trusted else "untrusted_source"
        # 비밀번호 실패와 별도 이벤트로 기록해야 기존 반복 실패 횟수에 합산되지 않는다.
        return _reject("login_source_denied", 403, "login source not allowed", reason,
                       username=username if isinstance(username, str) else None,
                       access_requested=access_requested)

    if not valid_input:
        # 형식이 틀린 로그인 시도도 '실패'로 기록한다(자동화 도구의 이상한 입력 포함)
        audit("login_failed", "failure", 400, username=username if isinstance(username, str) else "")
        return fail(400, "invalid request")
    try:
        user = _conn().execute(
            """
            SELECT id, username, password_hash, department, role, session_version,
                EXISTS (SELECT 1 FROM account_locks WHERE user_id = users.id
                        AND unlocked_at IS NULL AND expires_at > clock_timestamp()) AS is_locked,
                EXISTS (SELECT 1 FROM account_revocations WHERE user_id = users.id
                        AND restored_at IS NULL) AS is_revoked
            FROM users WHERE username = %s
            """, (username,),
        ).fetchone()
    except psycopg.Error:                            # DB 문제는 인증 실패가 아니므로 로그인 실패로 기록하지 않는다
        close_db()
        return fail(503, "service unavailable")
    # 사용자가 없어도 해시 검사를 한 번 하고, 응답은 똑같이 만든다(존재 여부를 알려 주지 않는다)
    ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password) and user is not None
    if user and user.get("is_revoked"):
        return _reject("login_blocked", 403, "account permissions revoked", "account_revoked",
                       username=username, password_valid=ok)
    if user and not user.get("is_locked") and g.client_ip_trusted:
        key = f"RULE-ERP-LOGIN-AUTO-LOCK-001:{g.request_id}"
        incident_id = "INC-" + hashlib.sha256(key.encode()).hexdigest()[:10].upper()
        try:
            lock_result = account_lock.record_login_result(_conn(), user["id"], g.client_ip, ok, incident_id)
        except psycopg.Error:
            close_db()
            return fail(503, "service unavailable")
        if lock_result == "locked":
            audit("login_blocked", "failure", 403, username=username,
                  reason="account_locked", password_valid=False)
            audit("account_locked", "success", 403, username=username, incident_id=incident_id,
                  operator="system", reason="automatic_login_failure_limit")
            return fail(403, "account temporarily locked")
        if lock_result == "blocked":
            return _reject("login_blocked", 403, "account temporarily locked", "account_locked",
                           username=username, password_valid=ok)
    if user and user.get("is_locked"):
        # 잠긴 동안에는 비밀번호가 맞든 틀리든 같은 응답을 보내, 잠금 시간에 비밀번호를 맞혀 볼 수 없게 한다.
        # 틀린 비밀번호였는지는 로그에만 남겨 관제가 인증 실패 횟수에 포함하게 한다.
        return _reject("login_blocked", 403, "account temporarily locked", "account_locked",
                       username=username, password_valid=ok)
    if not ok:
        audit("login_failed", "failure", 401, username=username)   # 비밀번호는 기록하지 않는다
        return fail(401, "invalid credentials")
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]                      # 부서·직급은 쿠키에 넣지 않는다(current_user가 DB에서 읽는다)
    session["version"] = user.get("session_version", 0)
    audit("login_success", "success", 200, username=user["username"], department=user["department"], role=user["role"])
    return jsonify({"username": user["username"], "department": user["department"], "role": user["role"]})


def _is_soc_controller():
    # 관제 서버 전용 내부망과 전용 키를 모두 확인한다.
    bearer = request.headers.get("Authorization", "").encode("utf-8")
    return bool(LOGIN_ACCESS_TOKEN and request.remote_addr == LOGIN_ACCESS_CONTROLLER_IP
                and hmac.compare_digest(bearer, f"Bearer {LOGIN_ACCESS_TOKEN}".encode("utf-8")))


@app.route("/internal/login-access/<request_id>", methods=["GET", "POST"])
def manage_login_access(request_id):
    if not _is_soc_controller() or not UUID_RE.fullmatch(request_id):
        return fail(404, "not found")

    try:
        if request.method == "GET":
            state = login_access.get_request(
                _conn(), request_id, include_active_grant=request.args.get("scope") == "account",
            )
            return jsonify(state) if state else fail(404, "not found")

        data = request.get_json(silent=True)
        if not isinstance(data, dict) or data.get("action") not in ("approve", "revoke"):
            return fail(400, "invalid request")
        limits = {"username": 254, "client_ip": 45, "incident_id": 64, "operator": 64}
        for field, limit in limits.items():
            value = data.get(field)
            if not isinstance(value, str) or not value or not value.isprintable() or len(value) > limit:
                return fail(400, "invalid request")
        reason = data.get("reason", "")
        if data["action"] == "approve":
            reason = reason.strip() if isinstance(reason, str) else ""
            if not reason or not reason.isprintable() or len(reason) > 200:
                return fail(400, "승인 사유를 1~200자로 입력해 주세요.")
        state, error = login_access.change_request(
            _conn(), request_id, action=data["action"], reason=reason,
            **{field: data[field] for field in limits},
        )
        return fail(409, error) if error else jsonify(state)
    except psycopg.Error:
        close_db()
        return fail(503, "service unavailable")


@app.route("/internal/account-locks/<incident_id>", methods=["GET", "POST"])
def manage_account_lock(incident_id):
    if not _is_soc_controller() or not re.fullmatch(r"INC-[0-9A-F]{10}", incident_id):
        return fail(404, "not found")
    data = request.args if request.method == "GET" else request.get_json(silent=True)
    username = data.get("username") if isinstance(data, dict) or request.method == "GET" else None
    if not isinstance(username, str) or not username or not username.isprintable() or len(username) > 64:
        return fail(400, "invalid request")

    try:
        if request.method == "GET":
            state = account_lock.get_status(_conn(), username, incident_id)
            return jsonify(state) if state else fail(404, "not found")

        action, operator = data.get("action"), data.get("operator")
        if (action not in ("lock", "unlock") or not isinstance(operator, str) or not operator
                or not operator.isprintable() or len(operator) > 64):
            return fail(400, "invalid request")
        reason = data.get("reason")
        reason = reason.strip() if isinstance(reason, str) else ""
        duration = data.get("duration_minutes")
        if not reason or len(reason) > 200 or not reason.isprintable():
            return fail(400, "조치 사유를 1~200자로 입력해 주세요.")
        if action == "lock" and (type(duration) is not int or not 1 <= duration <= 30):
            return fail(400, "잠금 시간은 1~30분으로 입력해 주세요.")
        state, error = account_lock.change_status(
            _conn(), username, incident_id, operator, action, duration, reason,
            record=lambda event, **fields: audit(event, "success", 200, **fields),
        )
        return fail(409, error) if error else jsonify(state)
    except (psycopg.Error, OSError):
        close_db()
        return fail(503, "service unavailable")


@app.route("/internal/permissions", methods=["GET", "POST"])
def manage_permissions():
    if not _is_soc_controller():
        return fail(404, "not found")
    try:
        if request.method == "GET":
            return jsonify(account_lock.get_permissions_overview(_conn()))

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return fail(400, "invalid request")
        action = data.get("action")
        username = data.get("username")
        operator = data.get("operator")
        reason = data.get("reason")
        reason = reason.strip() if isinstance(reason, str) else ""
        doc_id = data.get("document_id")
        doc_id = doc_id.strip() if isinstance(doc_id, str) else ""
        if (action not in ("grant_doc", "revoke_doc", "retire_account", "restore_account")
                or not isinstance(username, str) or not username or not username.isprintable() or len(username) > 64
                or not isinstance(operator, str) or not operator or not operator.isprintable() or len(operator) > 64):
            return fail(400, "invalid request")
        if not reason or len(reason) > 200 or not reason.isprintable():
            return fail(400, "조치 사유를 1~200자로 입력해 주세요.")
        if action in ("grant_doc", "revoke_doc") and not UUID_RE.fullmatch(doc_id):
            return fail(400, "문서 번호가 올바르지 않습니다.")
        duration = data.get("duration_minutes", 60)
        if action == "grant_doc" and (type(duration) is not int or not 1 <= duration <= 1440):
            return fail(400, "권한 유지 시간은 1~1440분(최대 24시간)으로 입력해 주세요.")
        state, error = account_lock.change_permission(
            _conn(), username, operator, action, reason, doc_id or None,
            record=lambda event, **fields: audit(event, "success", 200, **fields),
            can_read_fn=documents.can_read,
            duration_minutes=duration if action == "grant_doc" else 60,
        )
        return fail(409, error) if error else jsonify(state)
    except (psycopg.Error, OSError):
        close_db()
        return fail(503, "service unavailable")


@post_api("/api/logout")
def logout():
    user = current_user()
    session.clear()
    if user:
        audit("logout", "success", 200, username=user["username"])
    return jsonify({"loggedOut": True})


# ───────────────────────── 5. 자료실 ─────────────────────────
def _doc_summary(row):
    return {"id": str(row["public_id"]), "title": row["title"], "department": row["department"],
            "level": row["level"], "levelLabel": documents.LEVEL_LABEL[row["level"]]}


@app.get("/api/documents")
def list_documents():
    """전체 문서 목록(제목·부서·등급)과 열람 가능 여부를 돌려준다. 본문은 열람 API에서만 나간다.

    열 수 없는 문서도 목록에는 보이되 allowed=false다. 눌러서 열면 서버가 403으로 막고 기록한다.
    """
    user = current_user()
    if not user:
        return _unauth()
    rows = _conn().execute("SELECT public_id, title, department, level FROM documents ORDER BY id").fetchall()
    granted = account_lock.get_granted_doc_ids(_conn(), user["id"])
    return jsonify([
        {**_doc_summary(r), "allowed": documents.can_read(user, r, granted)[0], "granted": str(r["public_id"]) in granted}
        for r in rows
    ])


@app.get("/api/documents/<doc_public_id>")
def read_document(doc_public_id):
    """문서 한 건을 연다. 성공과 실패(401·403·404) 모두 document_read 로그로 남긴다."""
    event = "document_read"
    user = current_user()
    if not user:
        return _unauth(event)
    row = None
    if UUID_RE.match(doc_public_id):
        row = _conn().execute(
            "SELECT public_id, title, department, level, body FROM documents WHERE public_id = %s",
            (doc_public_id,),
        ).fetchone()
    if row is None:
        return _reject(event, 404, "not found", "not_found", user["username"], document_id=doc_public_id)
    meta = _meta(user, row["public_id"], row["level"], row["department"], role=True)
    granted = account_lock.get_granted_doc_ids(_conn(), user["id"])
    if not documents.can_read(user, row, granted)[0]:
        return _reject(event, 403, "forbidden", "forbidden", user["username"], **meta)   # 제목·본문은 알려 주지 않는다
    audit(event, "success", 200, username=user["username"], **meta)
    return jsonify({**_doc_summary(row), "body": row["body"]})


seed_users()
seed_documents()
