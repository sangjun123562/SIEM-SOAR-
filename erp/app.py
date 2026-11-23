"""가상 기관 포털 — 보안관제 시연용 Flask 앱(로그인 + 자료실 열람 권한 요청).

읽는 순서: 1 설정 → 2 로그 → 3 요청마다 하는 일 → 4 로그인·세션·로그아웃 → 5 자료실 → 6 열람 권한 요청

핵심 약속
- 로그인·로그아웃·문서 열람·권한 요청의 성공과 실패를 erp.jsonl에 한 줄씩 남긴다(관제 시스템이 읽는다).
- 비밀번호, 쿠키, 요청 본문은 로그에 남기지 않는다.
- 접속자 IP(X-Client-IP)는 '직접 연결한 상대가 Caddy일 때만' 믿는다. 그 밖에는 소켓 IP를 쓴다.
- 상태를 바꾸는 요청은 기록을 먼저 남기고 커밋한다(기록이 실패하면 변경도 저장되지 않는다).
"""
import datetime
import functools
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

import documents

# ───────────────────────── 1. 설정 ─────────────────────────
DB_DSN = os.environ["ERP_DB_DSN"]                        # ERP 전용 DB 접속 문자열
TRUSTED_PROXY_IP = os.environ.get("TRUSTED_PROXY_IP", "172.28.20.5")   # 믿는 프록시(Caddy)의 IP
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


# 기존 DB에도 적용되는 보강(여러 번 실행해도 안전): 회수 상태·기록, 반려 사유, 열린 요청 중복 방지
_SCHEMA_UPGRADES = (
    "ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS revoked_by INT REFERENCES users(id)",
    "ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ",
    "ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS decision_reason TEXT",
    "ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_status_check",
    "ALTER TABLE access_requests ADD CONSTRAINT access_requests_status_check "
    "CHECK (status IN ('requested', 'approved', 'rejected', 'revoked'))",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_access_requests_open "
    "ON access_requests (requester_id, document_id) WHERE status = 'requested'",
)


def seed_documents():
    """자료실 표와 기본 문서를 만든다(여러 번 실행해도 안전). 이미 있는 문서는 고치지 않는다."""
    with db() as conn:
        # 워커 2개가 동시에 표를 만들면 충돌하므로, 한 번에 하나만 실행되도록 잠근다(트랜잭션이 끝나면 풀린다).
        conn.execute("SELECT pg_advisory_xact_lock(8451)")
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
        conn.execute(
            "CREATE TABLE IF NOT EXISTS access_requests ("
            " id BIGSERIAL PRIMARY KEY,"
            " public_id UUID UNIQUE NOT NULL,"
            " requester_id INT NOT NULL REFERENCES users(id),"
            " document_id BIGINT NOT NULL REFERENCES documents(id),"
            " reason TEXT NOT NULL,"
            " status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'approved', 'rejected')),"
            " requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
            " decided_by INT REFERENCES users(id),"
            " decided_at TIMESTAMPTZ,"
            " expires_at TIMESTAMPTZ)"
        )
        for statement in _SCHEMA_UPGRADES:
            conn.execute(statement)
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
        row = _conn().execute("SELECT id, username, department, role FROM users WHERE id = %s", (uid,)).fetchone()
    except psycopg.Error:
        close_db()                                   # 끊어진 연결은 버린다
        return None
    if row is None:
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
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or len(username) > 254 or len(password) > 1024:
        # 형식이 틀린 로그인 시도도 '실패'로 기록한다(자동화 도구의 이상한 입력 포함)
        audit("login_failed", "failure", 400, username=username if isinstance(username, str) else "")
        return fail(400, "invalid request")
    try:
        user = _conn().execute(
            "SELECT id, username, password_hash, department, role FROM users WHERE username = %s", (username,)
        ).fetchone()
    except psycopg.Error:                            # DB 문제는 인증 실패가 아니므로 로그인 실패로 기록하지 않는다
        close_db()
        return fail(503, "service unavailable")
    # 사용자가 없어도 해시 검사를 한 번 하고, 응답은 똑같이 만든다(존재 여부를 알려 주지 않는다)
    ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password) and user is not None
    if not ok:
        audit("login_failed", "failure", 401, username=username)   # 비밀번호는 기록하지 않는다
        return fail(401, "invalid credentials")
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]                      # 부서·직급은 쿠키에 넣지 않는다(current_user가 DB에서 읽는다)
    audit("login_success", "success", 200, username=user["username"], department=user["department"], role=user["role"])
    return jsonify({"username": user["username"], "department": user["department"], "role": user["role"]})


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


def _granted(conn, user_id):
    """지금 유효한 임시 열람 권한: {문서 public_id: (요청 번호, 만료 시각)}."""
    rows = conn.execute(
        "SELECT d.public_id AS doc, r.public_id AS rid, r.expires_at FROM access_requests r "
        "JOIN documents d ON d.id = r.document_id "
        "WHERE r.requester_id = %s AND r.status = 'approved' AND r.expires_at > now()",
        (user_id,),
    ).fetchall()
    return {str(r["doc"]): (str(r["rid"]), r["expires_at"]) for r in rows}


def _docs_and_grants(user):
    """모든 문서(본문 제외)와 이 사용자의 유효한 임시 권한."""
    conn = _conn()
    rows = conn.execute("SELECT public_id, title, department, level FROM documents ORDER BY id").fetchall()
    return rows, _granted(conn, user["id"])


@app.get("/api/documents")
def list_documents():
    """열 수 있는 문서(소속·등급 규칙 + 승인된 임시 권한)만 목록에 보여 준다. 열 수 없는 문서는 제목도 숨긴다."""
    user = current_user()
    if not user:
        return _unauth()
    rows, grants = _docs_and_grants(user)
    out = []
    for r in rows:
        grant = grants.get(str(r["public_id"]))
        if documents.can_read(user, r)[0]:
            out.append(_doc_summary(r))
        elif grant:
            out.append({**_doc_summary(r), "grantedUntil": grant[1].isoformat()})
    return jsonify(out)


@app.get("/api/documents/restricted")
def list_restricted_documents():
    """지금 열 수 없지만 열람 권한을 요청할 수 있는 문서의 제목만 보여 준다(본문은 없다)."""
    user = current_user()
    if not user:
        return _unauth()
    rows, grants = _docs_and_grants(user)
    return jsonify([_doc_summary(r) for r in rows
                    if documents.can_request(user, r)[0] and str(r["public_id"]) not in grants])


@app.get("/api/documents/<doc_public_id>")
def read_document(doc_public_id):
    """문서 한 건을 연다. 성공과 실패(401·403·404) 모두 document_read 로그로 남긴다."""
    event = "document_read"
    user = current_user()
    if not user:
        return _unauth(event)
    conn, row = _conn(), None
    if UUID_RE.match(doc_public_id):
        row = conn.execute(
            "SELECT public_id, title, department, level, body FROM documents WHERE public_id = %s",
            (doc_public_id,),
        ).fetchone()
    if row is None:
        return _reject(event, 404, "not found", "not_found", user["username"], document_id=doc_public_id)
    meta = _meta(user, row["public_id"], row["level"], row["department"], role=True)
    if documents.can_read(user, row)[0]:
        audit(event, "success", 200, username=user["username"], **meta)
        return jsonify({**_doc_summary(row), "body": row["body"]})
    grant = _granted(conn, user["id"]).get(str(row["public_id"]))
    if grant is None:
        return _reject(event, 403, "forbidden", "forbidden", user["username"], **meta)   # 제목·본문은 알려 주지 않는다
    # 승인된 임시 권한으로 연다(감사 로그에 근거를 남긴다)
    audit(event, "success", 200, username=user["username"], via="grant", grant_id=grant[0], **meta)
    return jsonify({**_doc_summary(row), "body": row["body"], "grantedUntil": grant[1].isoformat()})


# ───────────────────── 6. 열람 권한 요청 ─────────────────────
def _request_view(r):
    return {"id": str(r["rid"]), "documentId": str(r["doc"]), "title": r["title"], "department": r["department"],
            "level": r["level"], "levelLabel": documents.LEVEL_LABEL[r["level"]], "reason": r["reason"],
            "status": r["status"], "requestedAt": r["requested_at"].isoformat(),
            "requester": r["requester"],
            "expiresAt": r["expires_at"].isoformat() if r["expires_at"] else None}


_REQ_SELECT = ("SELECT r.public_id AS rid, d.public_id AS doc, d.title, d.department, d.level, r.reason, r.status, "
               "r.requested_at, r.expires_at, r.requester_id, u.username AS requester "
               "FROM access_requests r JOIN documents d ON d.id = r.document_id JOIN users u ON u.id = r.requester_id ")


def _requests(conn, tail, *params):
    """_REQ_SELECT 뒤에 조건(tail)을 붙여 요청 목록을 읽는다."""
    return conn.execute(_REQ_SELECT + tail, params).fetchall()


def _request_meta(user, r, rid, **more):
    """승인·반려·회수 로그에 붙이는 공통 항목."""
    return _meta(user, r["doc"], r["level"], r["department"], role=True,
                 request_ref=rid, requester=r["requester"], **more)


@app.get("/api/access-requests")
def list_access_requests():
    """내가 낸 요청(mine), 팀장이면 우리 부서 문서의 승인 대기(pending)와 지금 임시 열람 중인 권한(granted)을 돌려준다."""
    user = current_user()
    if not user:
        return _unauth()
    conn = _conn()
    mine = _requests(conn, "WHERE r.requester_id = %s ORDER BY r.requested_at DESC LIMIT 20", user["id"])
    pending, granted = [], []
    if user["role"] == "manager":
        pending = _requests(
            conn, "WHERE r.status = 'requested' AND d.department = %s AND r.requester_id <> %s "
                  "ORDER BY r.requested_at", user["department"], user["id"])
        granted = _requests(
            conn, "WHERE r.status = 'approved' AND r.expires_at > now() AND d.department = %s "
                  "ORDER BY r.expires_at", user["department"])
    return jsonify({"mine": [_request_view(r) for r in mine], "pending": [_request_view(r) for r in pending],
                    "granted": [_request_view(r) for r in granted]})


@post_api("/api/access-requests")
def create_access_request():
    event = "access_request_created"
    user = current_user()
    if not user:
        return _unauth(event)
    name = user["username"]
    data = request.get_json(silent=True) or {}
    doc_id, reason_text = data.get("document_id"), data.get("reason")
    if (not isinstance(doc_id, str) or not UUID_RE.match(doc_id)
            or not isinstance(reason_text, str) or not 1 <= len(reason_text.strip()) <= 200):
        return _reject(event, 400, "invalid request", "invalid_request", name)
    meta, conn = {}, _conn()
    try:
        with conn.transaction():
            row = conn.execute("SELECT id, public_id, department, level FROM documents WHERE public_id = %s",
                               (doc_id,)).fetchone()
            if row is None:
                return _reject(event, 404, "not found", "not_found", name, document_id=doc_id)
            meta = _meta(user, row["public_id"], row["level"], row["department"])
            ok, why = documents.can_request(user, row)
            if not ok:
                return _reject(event, 403, why, "not_requestable", name, **meta)
            dup = conn.execute(
                "SELECT 1 FROM access_requests WHERE requester_id = %s AND document_id = %s "
                "AND (status = 'requested' OR (status = 'approved' AND expires_at > now()))",
                (user["id"], row["id"])).fetchone()
            if dup:
                return _reject(event, 409, "already requested", "duplicate", name, **meta)
            rid = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO access_requests (public_id, requester_id, document_id, reason) VALUES (%s, %s, %s, %s)",
                (rid, user["id"], row["id"], reason_text.strip()))
            # 기록을 먼저 남기고 커밋한다. 기록이 실패하면 요청도 저장되지 않는다.
            audit(event, "success", 201, username=name, request_ref=rid, **meta)
    except psycopg.errors.UniqueViolation:     # 동시에 같은 요청이 들어온 경우(열린 요청 유일 인덱스)
        return _reject(event, 409, "already requested", "duplicate", name, **meta)
    return jsonify({"id": rid, "status": "requested"}), 201


def _request_actor(event, rid, **extra):
    """승인·반려·회수가 공통으로 먼저 하는 확인: 로그인, 요청 번호 형식. (사용자, 오류 응답)을 돌려준다."""
    user = current_user()
    if not user:
        return None, _unauth(event, **extra)
    if not UUID_RE.match(rid):
        return None, _reject(event, 404, "not found", "not_found", user["username"], **extra)
    return user, None


def _lock_request(conn, rid):
    """요청 한 건을 읽으면서 잠근다(동시에 두 사람이 처리하지 못하게). 트랜잭션 안에서만 부른다."""
    return conn.execute(_REQ_SELECT + "WHERE r.public_id = %s FOR UPDATE OF r", (rid,)).fetchone()


def _decide(rid, decision):
    event = "access_request_decided"
    user, err = _request_actor(event, rid, decision=decision)
    if err:
        return err
    name = user["username"]
    data = request.get_json(silent=True) or {}
    minutes = documents.clamp_grant_minutes(data.get("minutes")) if decision == "approved" else 0
    if minutes is None:
        return _reject(event, 400, "invalid minutes", "invalid_minutes", name, decision=decision, request_ref=rid)
    why_text = data.get("reason")
    why_text = why_text.strip()[:100] if decision == "rejected" and isinstance(why_text, str) else None
    conn = _conn()
    with conn.transaction():
        r = _lock_request(conn, rid)
        if r is None:
            return _reject(event, 404, "not found", "not_found", name, decision=decision, request_ref=rid)
        meta = _request_meta(user, r, rid, decision=decision)
        ok, why = documents.can_decide(user, r, r["requester_id"], user["id"])
        if not ok:
            return _reject(event, 403, why, "forbidden", name, **meta)
        if r["status"] != "requested":          # 이미 처리된 기록은 덮어쓰지 않는다
            return _reject(event, 409, "already decided", "already_decided", name, **meta)
        if decision == "approved":
            done = conn.execute(
                "UPDATE access_requests SET status = 'approved', decided_by = %s, decided_at = now(), "
                "expires_at = now() + make_interval(mins => %s) WHERE public_id = %s RETURNING expires_at",
                (user["id"], minutes, rid)).fetchone()
            extra = {"grant_minutes": minutes, "expires_at": done["expires_at"].isoformat()}
        else:
            conn.execute("UPDATE access_requests SET status = 'rejected', decided_by = %s, decided_at = now(), "
                         "decision_reason = %s WHERE public_id = %s", (user["id"], why_text, rid))
            extra = {"decision_reason": why_text} if why_text else {}
        # 기록을 먼저 남기고 커밋한다. 기록이 실패하면 권한도 부여되지 않는다.
        audit(event, "success", 200, username=name, **extra, **meta)
    return jsonify({"id": rid, "status": decision, "minutes": minutes})


@post_api("/api/access-requests/<rid>/approve")
def approve_access_request(rid):
    return _decide(rid, "approved")


@post_api("/api/access-requests/<rid>/reject")
def reject_access_request(rid):
    return _decide(rid, "rejected")


@post_api("/api/access-requests/<rid>/revoke")
def revoke_access_request(rid):
    """지금 유효한 임시 열람 권한을 문서 소속 부서 팀장이 즉시 회수한다. 이후 열람은 403이다."""
    event = "access_request_revoked"
    user, err = _request_actor(event, rid)
    if err:
        return err
    name = user["username"]
    conn = _conn()
    with conn.transaction():
        r = _lock_request(conn, rid)
        if r is None:
            return _reject(event, 404, "not found", "not_found", name, request_ref=rid)
        meta = _request_meta(user, r, rid)
        ok, why = documents.can_revoke(user, r)
        if not ok:
            return _reject(event, 403, why, "forbidden", name, **meta)
        done = conn.execute(
            "UPDATE access_requests SET status = 'revoked', revoked_by = %s, revoked_at = now() "
            "WHERE public_id = %s AND status = 'approved' AND expires_at > now() RETURNING id",
            (user["id"], rid)).fetchone()
        if done is None:                         # 승인 상태가 아니거나 이미 만료됨
            return _reject(event, 409, "not active", "not_active", name, **meta)
        audit(event, "success", 200, username=name, **meta)
    return jsonify({"id": rid, "status": "revoked"})


seed_users()
seed_documents()
