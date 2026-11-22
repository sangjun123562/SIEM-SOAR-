"""가상 기관 로그인 — 보안관제 시연용 Flask 앱.

읽는 순서: 1 설정 → 2 로그 → 3 요청마다 하는 일 → 4 로그인·세션·로그아웃

핵심 약속
- 로그인·로그아웃 결과를 erp.jsonl에 한 줄씩 남긴다(관제 시스템이 읽는다).
- 비밀번호, 쿠키, 요청 본문은 로그에 남기지 않는다.
- 접속자 IP(X-Client-IP)는 '직접 연결한 상대가 Caddy일 때만' 믿는다. 그 밖에는 소켓 IP를 쓴다.
"""
import datetime
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
    ("carol", "DEMO_PW_CAROL", "보안", "member"),    # 보안 사원 (2026-11-22 개발 → 보안)
    ("dave", "DEMO_PW_DAVE", "인사", "manager"),     # 인사 팀장
    ("erin", "DEMO_PW_ERIN", "인사", "member"),      # 인사 사원
    ("frank", "DEMO_PW_FRANK", "보안", "manager"),   # 보안 팀장
]
# 없는 사용자도 같은 시간이 걸리게 하려고 쓰는 가짜 해시(사용자 존재 여부 추측 방지)
DUMMY_HASH = generate_password_hash("not-a-real-password", method="pbkdf2:sha256")


def db():
    """DB 연결. `with db() as conn:` 블록이 정상 종료되면 자동으로 커밋된다."""
    return psycopg.connect(DB_DSN, row_factory=dict_row)


def seed_users():
    """시험용 사용자가 없으면 만든다(여러 번 실행해도 안전)."""
    with db() as conn:
        for username, env_name, department, role in DEMO_USERS:
            password = os.environ.get(env_name)
            if not password:
                continue
            # 이미 있는 계정은 비밀번호를 건드리지 않고 부서·직급만 맞춘다(carol: 개발 → 보안).
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


def same_origin():
    """다른 사이트에서 몰래 보내는 요청(CSRF)을 막는다: Origin이 우리 주소여야 한다."""
    origin = request.headers.get("Origin")
    return bool(origin) and urlsplit(origin).netloc == request.headers.get("Host")


def fail(status, message):
    return jsonify({"error": message}), status


# ───────────────────────── 4. 로그인 ─────────────────────────
def current_user():
    if "uid" not in session:
        return None
    return {"id": session["uid"], "username": session["username"],
            "department": session["department"], "role": session["role"]}


@app.get("/")
def home():
    return send_from_directory(os.path.join(os.path.dirname(__file__), "static"), "index.html")


@app.get("/api/session")
def get_session():
    user = current_user()
    if not user:
        return fail(401, "login required")
    return jsonify({k: user[k] for k in ("username", "department", "role")})


@app.post("/api/login")
def login():
    if not same_origin():
        return fail(403, "origin denied")
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or len(username) > 254 or len(password) > 1024:
        # 형식이 틀린 로그인 시도도 '실패'로 기록한다(자동화 도구의 이상한 입력 포함)
        audit("login_failed", "failure", 400, username=username if isinstance(username, str) else "")
        return fail(400, "invalid request")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()
    # 사용자가 없어도 해시 검사를 한 번 하고, 응답은 똑같이 만든다(존재 여부를 알려 주지 않는다)
    ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password) and user is not None
    if not ok:
        audit("login_failed", "failure", 401, username=username)   # 비밀번호는 기록하지 않는다
        return fail(401, "invalid credentials")
    session.clear()
    session.permanent = True
    session.update(uid=user["id"], username=user["username"], department=user["department"], role=user["role"])
    audit("login_success", "success", 200, username=user["username"], department=user["department"], role=user["role"])
    return jsonify({"username": user["username"], "department": user["department"], "role": user["role"]})


@app.post("/api/logout")
def logout():
    if not same_origin():
        return fail(403, "origin denied")
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


@app.get("/api/documents")
def list_documents():
    """열 수 있는 문서(소속·등급 규칙 + 승인된 임시 권한)만 목록에 보여 준다. 열 수 없는 문서는 제목도 숨긴다."""
    user = current_user()
    if not user:
        return fail(401, "login required")
    with db() as conn:
        rows = conn.execute("SELECT public_id, title, department, level FROM documents ORDER BY id").fetchall()
        grants = _granted(conn, user["id"])
    out = []
    for r in rows:
        if documents.can_read(user, r)[0]:
            out.append(_doc_summary(r))
        elif str(r["public_id"]) in grants:
            out.append({**_doc_summary(r), "grantedUntil": grants[str(r["public_id"])][1].isoformat()})
    return jsonify(out)


@app.get("/api/documents/restricted")
def list_restricted_documents():
    """지금 열 수 없지만 열람 권한을 요청할 수 있는 문서의 제목만 보여 준다(본문은 없다)."""
    user = current_user()
    if not user:
        return fail(401, "login required")
    with db() as conn:
        rows = conn.execute("SELECT public_id, title, department, level FROM documents ORDER BY id").fetchall()
        grants = _granted(conn, user["id"])
    return jsonify([_doc_summary(r) for r in rows
                    if documents.can_request(user, r)[0] and str(r["public_id"]) not in grants])


@app.get("/api/documents/<doc_public_id>")
def read_document(doc_public_id):
    """문서 한 건을 연다. 성공과 실패(401·403·404) 모두 document_read 로그로 남긴다."""
    user = current_user()
    if not user:
        audit("document_read", "failure", 401, reason="unauthenticated")
        return fail(401, "login required")
    row = None
    grant = None
    if UUID_RE.match(doc_public_id):
        with db() as conn:
            row = conn.execute(
                "SELECT public_id, title, department, level, body FROM documents WHERE public_id = %s",
                (doc_public_id,),
            ).fetchone()
            if row is not None:
                grant = _granted(conn, user["id"]).get(str(row["public_id"]))
    if row is None:
        audit("document_read", "failure", 404, username=user["username"], reason="not_found",
              document_id=doc_public_id)
        return fail(404, "not found")
    allowed, reason = documents.can_read(user, row)
    meta = {"document_id": str(row["public_id"]), "doc_level": row["level"],
            "doc_department": row["department"] or "", "user_department": user["department"],
            "user_role": user["role"]}
    if not allowed and grant is not None:          # 승인된 임시 권한으로 연다(감사 로그에 근거를 남긴다)
        audit("document_read", "success", 200, username=user["username"], via="grant", grant_id=grant[0], **meta)
        return jsonify({**_doc_summary(row), "body": row["body"], "grantedUntil": grant[1].isoformat()})
    if not allowed:
        audit("document_read", "failure", 403, username=user["username"], reason="forbidden", **meta)
        return fail(403, "forbidden")   # 제목·본문은 알려 주지 않는다
    audit("document_read", "success", 200, username=user["username"], **meta)
    return jsonify({**_doc_summary(row), "body": row["body"]})


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


@app.get("/api/access-requests")
def list_access_requests():
    """내가 낸 요청(mine)과, 팀장이면 우리 부서 문서에 대한 승인 대기 요청(pending)을 돌려준다."""
    user = current_user()
    if not user:
        return fail(401, "login required")
    with db() as conn:
        mine = conn.execute(_REQ_SELECT + "WHERE r.requester_id = %s ORDER BY r.requested_at DESC LIMIT 20",
                            (user["id"],)).fetchall()
        pending = []
        if user["role"] == "manager":
            pending = conn.execute(
                _REQ_SELECT + "WHERE r.status = 'requested' AND d.department = %s AND r.requester_id <> %s "
                "ORDER BY r.requested_at", (user["department"], user["id"])).fetchall()
    return jsonify({"mine": [_request_view(r) for r in mine], "pending": [_request_view(r) for r in pending]})


@app.post("/api/access-requests")
def create_access_request():
    if not same_origin():
        return fail(403, "origin denied")
    user = current_user()
    if not user:
        audit("access_request_created", "failure", 401, reason="unauthenticated")
        return fail(401, "login required")
    data = request.get_json(silent=True) or {}
    doc_id, reason_text = data.get("document_id"), data.get("reason")
    if (not isinstance(doc_id, str) or not UUID_RE.match(doc_id)
            or not isinstance(reason_text, str) or not 1 <= len(reason_text.strip()) <= 200):
        audit("access_request_created", "failure", 400, username=user["username"], reason="invalid_request")
        return fail(400, "invalid request")
    with db() as conn:
        row = conn.execute("SELECT id, public_id, department, level FROM documents WHERE public_id = %s",
                           (doc_id,)).fetchone()
        if row is None:
            audit("access_request_created", "failure", 404, username=user["username"], reason="not_found",
                  document_id=doc_id)
            return fail(404, "not found")
        meta = {"document_id": str(row["public_id"]), "doc_level": row["level"],
                "doc_department": row["department"] or "", "user_department": user["department"]}
        ok, why = documents.can_request(user, row)
        if not ok:
            audit("access_request_created", "failure", 403, username=user["username"], reason="not_requestable", **meta)
            return fail(403, why)
        dup = conn.execute(
            "SELECT 1 FROM access_requests WHERE requester_id = %s AND document_id = %s "
            "AND (status = 'requested' OR (status = 'approved' AND expires_at > now()))",
            (user["id"], row["id"])).fetchone()
        if dup:
            audit("access_request_created", "failure", 409, username=user["username"], reason="duplicate", **meta)
            return fail(409, "already requested")
        rid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO access_requests (public_id, requester_id, document_id, reason) VALUES (%s, %s, %s, %s)",
            (rid, user["id"], row["id"], reason_text.strip()))
    audit("access_request_created", "success", 201, username=user["username"], request_ref=rid, **meta)
    return jsonify({"id": rid, "status": "requested"}), 201


def _decide(rid, decision):
    if not same_origin():
        return fail(403, "origin denied")
    user = current_user()
    if not user:
        audit("access_request_decided", "failure", 401, reason="unauthenticated", decision=decision)
        return fail(401, "login required")
    if not UUID_RE.match(rid):
        audit("access_request_decided", "failure", 404, username=user["username"], reason="not_found", decision=decision)
        return fail(404, "not found")
    data = request.get_json(silent=True) or {}
    minutes = documents.clamp_grant_minutes(data.get("minutes")) if decision == "approved" else 0
    if minutes is None:
        audit("access_request_decided", "failure", 400, username=user["username"], reason="invalid_minutes",
              decision=decision, request_ref=rid)
        return fail(400, "invalid minutes")
    with db() as conn:
        r = conn.execute(_REQ_SELECT + "WHERE r.public_id = %s FOR UPDATE OF r", (rid,)).fetchone()
        if r is None:
            audit("access_request_decided", "failure", 404, username=user["username"], reason="not_found",
                  decision=decision, request_ref=rid)
            return fail(404, "not found")
        meta = {"request_ref": rid, "decision": decision, "document_id": str(r["doc"]), "doc_level": r["level"],
                "doc_department": r["department"] or "", "requester": r["requester"],
                "user_department": user["department"], "user_role": user["role"]}
        ok, why = documents.can_decide(user, r, r["requester_id"], user["id"])
        if not ok:
            audit("access_request_decided", "failure", 403, username=user["username"], reason="forbidden", **meta)
            return fail(403, why)
        if r["status"] != "requested":
            audit("access_request_decided", "failure", 409, username=user["username"], reason="already_decided", **meta)
            return fail(409, "already decided")
        if decision == "approved":
            conn.execute(
                "UPDATE access_requests SET status = 'approved', decided_by = %s, decided_at = now(), "
                "expires_at = now() + make_interval(mins => %s) WHERE public_id = %s", (user["id"], minutes, rid))
        else:
            conn.execute("UPDATE access_requests SET status = 'rejected', decided_by = %s, decided_at = now() "
                         "WHERE public_id = %s", (user["id"], rid))
    audit("access_request_decided", "success", 200, username=user["username"], grant_minutes=minutes, **meta)
    return jsonify({"id": rid, "status": decision, "minutes": minutes})


@app.post("/api/access-requests/<rid>/approve")
def approve_access_request(rid):
    return _decide(rid, "approved")


@app.post("/api/access-requests/<rid>/reject")
def reject_access_request(rid):
    return _decide(rid, "rejected")


# 구매/결재 API는 범위 축소로 제거. 기존 DB와 과거 로그는 보존한다.
seed_users()
seed_documents()
