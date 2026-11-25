"""X 단말의 임시 접속 요청과 승인 상태를 ERP DB에서 관리한다."""

from datetime import datetime, timedelta, timezone


X_LOGIN_IP = "172.28.10.13"
LOGIN_GRANT_MINUTES = 5


def ensure_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_access_requests (
            request_id UUID PRIMARY KEY,
            username TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            incident_id TEXT,
            approved_by TEXT,
            approval_reason TEXT,
            approved_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ,
            revoked_by TEXT,
            revoked_at TIMESTAMPTZ
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_access_grants
        ON login_access_requests (username, client_ip, expires_at)
        WHERE approved_at IS NOT NULL AND revoked_at IS NULL
    """)


def _active_grant(conn, username, client_ip):
    return conn.execute("""
        SELECT request_id FROM login_access_requests
        WHERE username = %s AND client_ip = %s
          AND revoked_at IS NULL AND expires_at > clock_timestamp()
        LIMIT 1
    """, (username, client_ip)).fetchone()


def can_log_in(conn, request_id, username, client_ip):
    """승인이 없으면 이번 로그인 요청을 등록하고 통과시키지 않는다."""
    if _active_grant(conn, username, client_ip):
        return True
    conn.execute("""
        INSERT INTO login_access_requests (request_id, username, client_ip)
        VALUES (%s, %s, %s) ON CONFLICT (request_id) DO NOTHING
    """, (request_id, username, client_ip))
    return False


def _public_state(row):
    if row["revoked_at"]:
        status = "revoked"
    elif not row["approved_at"]:
        status = "pending"
    elif row["expires_at"] <= datetime.now(timezone.utc):
        status = "expired"
    else:
        status = "active"
    return {
        "status": status, "username": row["username"], "client_ip": row["client_ip"],
        "incident_id": row["incident_id"], "approved_by": row["approved_by"],
        "approval_reason": row["approval_reason"], "revoked_by": row["revoked_by"],
        **{name: row[name].isoformat() if row[name] else None
           for name in ("approved_at", "expires_at", "revoked_at")},
    }


def get_request(conn, request_id):
    row = conn.execute("SELECT * FROM login_access_requests WHERE request_id = %s", (request_id,)).fetchone()
    return _public_state(row) if row else None


def change_request(conn, request_id, *, action, username, client_ip, incident_id, operator, reason):
    with conn.transaction():
        row = conn.execute(
            "SELECT * FROM login_access_requests WHERE request_id = %s FOR UPDATE", (request_id,),
        ).fetchone()
        if not row or row["username"] != username or row["client_ip"] != client_ip or client_ip != X_LOGIN_IP:
            return None, "접속 요청을 확인할 수 없습니다. X 단말에서 새로 로그인한 뒤 확인하세요."
        if row["incident_id"] and row["incident_id"] != incident_id:
            return None, "이 접속 요청은 다른 사건에 연결되어 있습니다."

        now = datetime.now(timezone.utc)
        if action == "approve":
            if row["approved_at"] and not row["revoked_at"]:
                if row["expires_at"] <= now:
                    return None, "종료된 승인입니다. 새 로그인 요청에서 승인하세요."
                return _public_state(row), None  # 같은 승인 요청이 다시 와도 종료 시각을 늘리지 않는다.

            # 같은 계정의 다른 사건을 동시에 승인해도 한 번에 하나만 허용한다.
            user = conn.execute("SELECT id FROM users WHERE username = %s FOR UPDATE", (username,)).fetchone()
            if not user:
                return None, "등록된 ERP 계정을 확인할 수 없습니다."
            if _active_grant(conn, username, client_ip):
                return None, "이 계정과 IP에 이미 유효한 승인이 있습니다."

            now = datetime.now(timezone.utc)
            row = conn.execute("""
                UPDATE login_access_requests
                SET incident_id = %s, approved_by = %s, approval_reason = %s, approved_at = %s, expires_at = %s,
                    revoked_by = NULL, revoked_at = NULL
                WHERE request_id = %s RETURNING *
            """, (incident_id, operator, reason, now, now + timedelta(minutes=LOGIN_GRANT_MINUTES), request_id)).fetchone()
        elif row["approved_at"] and not row["revoked_at"] and row["expires_at"] > now:
            row = conn.execute("""
                UPDATE login_access_requests SET revoked_by = %s, revoked_at = %s
                WHERE request_id = %s RETURNING *
            """, (operator, now, request_id)).fetchone()
        elif not row["approved_at"]:
            return None, "취소할 임시 접속 승인이 없습니다."
    return _public_state(row), None
