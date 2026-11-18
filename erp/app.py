"""간단한 ERP (구매 요청) — Flask 한 파일짜리 시험용 앱.

읽는 순서: 1 설정 → 2 로그 → 3 요청마다 하는 일 → 4 로그인 → 5 권한 → 6 구매 요청 API

핵심 약속
- 로그인·권한 거부·업무 처리 결과를 erp.jsonl에 한 줄씩 남긴다(관제 시스템이 읽는다).
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
    ("carol", "DEMO_PW_CAROL", "개발", "member"),    # 개발 사원
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
            conn.execute(
                "INSERT INTO users (username, password_hash, department, role) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (username) DO NOTHING",
                (username, generate_password_hash(password, method="pbkdf2:sha256"), department, role),
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


# ───────────────────────── 5. 권한 규칙 ─────────────────────────
# 규칙은 두 가지뿐이다.
#   보기: 내가 쓴 요청이거나, 내 부서의 팀장일 때
#   승인/반려: 같은 부서 팀장이고, 내가 쓴 요청이 아니며, 아직 '대기' 상태일 때
def can_view(user, row):
    return row["requester_id"] == user["id"] or (user["role"] == "manager" and row["department"] == user["department"])


def can_decide(user, row):
    return user["role"] == "manager" and row["department"] == user["department"] and row["requester_id"] != user["id"]


def denied(user, action, row):
    """권한 밖 시도: 거부하고 기록한다. (이 기록이 '권한 위반 접근 탐지'의 재료가 된다)"""
    audit("access_denied", "failure", 403, username=user["username"], action=action,
          resource_type="purchase_request", resource_id=str(row["public_id"]),
          department=user["department"], role=user["role"], resource_department=row["department"])
    return fail(403, "access denied")


def login_required():
    user = current_user()
    return user, (None if user else fail(401, "login required"))


def public(row):
    return {"id": str(row["public_id"]), "title": row["title"], "amount": row["amount"], "reason": row["reason"],
            "status": row["status"], "department": row["department"], "requester": row["requester_name"],
            "createdAt": row["created_at"].isoformat()}


BASE_SELECT = ("SELECT r.*, u.username AS requester_name FROM purchase_requests r "
               "JOIN users u ON u.id = r.requester_id ")


# ───────────────────────── 6. 구매 요청 API ─────────────────────────
@app.get("/api/requests")
def list_requests():
    user, error = login_required()
    if error:
        return error
    with db() as conn:
        if user["role"] == "manager":      # 팀장: 우리 부서 전체
            rows = conn.execute(BASE_SELECT + "WHERE r.department = %s ORDER BY r.id DESC", (user["department"],)).fetchall()
        else:                              # 사원: 내가 쓴 것만
            rows = conn.execute(BASE_SELECT + "WHERE r.requester_id = %s ORDER BY r.id DESC", (user["id"],)).fetchall()
    return jsonify({"requests": [public(r) for r in rows]})


@app.post("/api/requests")
def create_request():
    if not same_origin():
        return fail(403, "origin denied")
    user, error = login_required()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    title, reason, amount = data.get("title"), data.get("reason"), data.get("amount")
    if not (isinstance(title, str) and title.strip() and len(title) <= 200
            and isinstance(reason, str) and reason.strip() and len(reason) <= 1000
            and isinstance(amount, int) and not isinstance(amount, bool) and 0 < amount <= 10**10):
        return fail(400, "invalid request")
    pid = uuid.uuid4()
    with db() as conn:                     # 부서는 화면에서 받지 않고 내 부서로 서버가 정한다
        conn.execute(
            "INSERT INTO purchase_requests (public_id, requester_id, department, title, amount, reason) "
            "VALUES (%s, %s, %s, %s, %s, %s)", (pid, user["id"], user["department"], title, amount, reason))
    audit("purchase_created", "success", 201, username=user["username"], resource_id=str(pid), department=user["department"])
    return jsonify({"id": str(pid)}), 201


def load_request(pid):
    if not UUID_RE.match(pid):
        return None
    with db() as conn:
        return conn.execute(BASE_SELECT + "WHERE r.public_id = %s", (pid,)).fetchone()


@app.get("/api/requests/<pid>")
def get_request(pid):
    user, error = login_required()
    if error:
        return error
    row = load_request(pid)
    if not row:
        return fail(404, "not found")
    if not can_view(user, row):
        return denied(user, "view", row)
    return jsonify(public(row))


@app.post("/api/requests/<pid>/<decision>")
def decide(pid, decision):
    if decision not in ("approve", "reject"):
        return fail(404, "not found")
    if not same_origin():
        return fail(403, "origin denied")
    user, error = login_required()
    if error:
        return error
    row = load_request(pid)
    if not row:
        return fail(404, "not found")
    if not can_decide(user, row):
        return denied(user, decision, row)
    if row["status"] != "pending":
        return fail(409, "already decided")
    new_status = "approved" if decision == "approve" else "rejected"
    with db() as conn:                     # 상태가 아직 '대기'일 때만 바꾼다(동시에 두 번 눌러도 한 번만)
        changed = conn.execute(
            "UPDATE purchase_requests SET status = %s, decided_by = %s, decided_at = now() "
            "WHERE public_id = %s AND status = 'pending'", (new_status, user["id"], pid)).rowcount
    if not changed:
        return fail(409, "already decided")
    audit("purchase_" + new_status, "success", 200, username=user["username"], resource_id=pid, department=user["department"])
    return jsonify({"id": pid, "status": new_status})


seed_users()
