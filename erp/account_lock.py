"""ERP 계정 잠금 이력과 적용 여부를 PostgreSQL에서 관리한다."""

from datetime import timedelta


def ensure_schema(conn):
    # 잠금이 풀려도 이전 로그인 쿠키를 다시 쓰지 못하도록 번호를 올린다.
    conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 0")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS account_locks (
            incident_id TEXT PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            locked_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            locked_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            unlocked_by TEXT,
            unlock_reason TEXT,
            unlocked_at TIMESTAMPTZ
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS account_locks_user_idx ON account_locks (user_id, expires_at)")


def _load_lock(conn, user_id, incident_id):
    return conn.execute("""
        SELECT *, CASE WHEN unlocked_at IS NOT NULL THEN 'unlocked'
                       WHEN expires_at <= clock_timestamp() THEN 'expired'
                       ELSE 'active' END AS status
        FROM account_locks WHERE user_id = %s
          AND (incident_id = %s OR (unlocked_at IS NULL AND expires_at > clock_timestamp()))
        ORDER BY (unlocked_at IS NULL AND expires_at > clock_timestamp()) DESC, locked_at DESC
        LIMIT 1
    """, (user_id, incident_id)).fetchone()


def _public_state(username, row):
    if row is None:
        return {"username": username, "status": "available"}
    return {
        "username": username, "status": row["status"], "incident_id": row["incident_id"],
        "locked_by": row["locked_by"], "reason": row["reason"], "unlocked_by": row["unlocked_by"],
        "unlock_reason": row["unlock_reason"],
        **{key: row[key].isoformat() if row[key] else None for key in ("locked_at", "expires_at", "unlocked_at")},
    }


def get_status(conn, username, incident_id):
    user = conn.execute("SELECT id FROM users WHERE username = %s", (username,)).fetchone()
    return _public_state(username, _load_lock(conn, user["id"], incident_id)) if user else None


def change_status(conn, username, incident_id, operator, action, duration, reason, record):
    with conn.transaction():
        # 같은 계정의 사건 두 개가 동시에 잠겨도 잠금은 한 번만 적용한다.
        user = conn.execute("SELECT id FROM users WHERE username = %s FOR UPDATE", (username,)).fetchone()
        if not user:
            return None, "등록된 ERP 계정을 찾을 수 없습니다."
        user_id = user["id"]
        row = _load_lock(conn, user_id, incident_id)
        if row and row["incident_id"] != incident_id:
            return None, "다른 사건에서 이 계정이 잠겨 있습니다. 해당 사건의 상세를 확인하세요."

        if action == "lock":
            if row:
                if row["status"] == "active":
                    return _public_state(username, row), None
                return None, "이 사건의 잠금은 종료됐습니다. 새 사건에서 잠금을 검토하세요."
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            deadline = now + timedelta(minutes=duration)
            conn.execute("""
                INSERT INTO account_locks (incident_id, user_id, locked_by, reason, locked_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (incident_id, user_id, operator, reason, now, deadline))
            conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (user_id,))
            record("account_locked", username=username, incident_id=incident_id, operator=operator,
                   lock_reason=reason, expires_at_utc=deadline.isoformat())
        else:
            if not row:
                return None, "해제할 계정 잠금이 없습니다."
            if row["status"] == "active":
                updated = conn.execute("""
                    UPDATE account_locks SET unlocked_by = %s, unlock_reason = %s, unlocked_at = clock_timestamp()
                    WHERE incident_id = %s AND expires_at > clock_timestamp() RETURNING incident_id
                """, (operator, reason, incident_id)).fetchone()
                if updated:
                    record("account_unlocked", username=username, incident_id=incident_id, operator=operator,
                           unlock_reason=reason)

        return _public_state(username, _load_lock(conn, user_id, incident_id)), None
