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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_failures_by_ip (
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            client_ip INET NOT NULL,
            attempts TIMESTAMPTZ[] NOT NULL,
            PRIMARY KEY (user_id, client_ip)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS document_permissions (
            id BIGSERIAL PRIMARY KEY,
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            document_public_id UUID NOT NULL,
            granted_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            expires_at TIMESTAMPTZ,
            revoked_by TEXT,
            revoke_reason TEXT,
            revoked_at TIMESTAMPTZ
        )
    """)
    conn.execute("ALTER TABLE document_permissions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ")
    conn.execute("CREATE INDEX IF NOT EXISTS document_permissions_user_idx ON document_permissions (user_id, document_public_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS account_revocations (
            user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            revoked_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            revoked_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            restored_by TEXT,
            restore_reason TEXT,
            restored_at TIMESTAMPTZ
        )
    """)


def record_login_result(conn, user_id, client_ip, password_valid, incident_id):
    """Serialize login outcomes with manual account locking."""
    with conn.transaction():
        conn.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))
        lock = _load_lock(conn, user_id, incident_id)
        if lock and lock["status"] == "active":
            return "blocked"
        if password_valid:
            conn.execute("DELETE FROM login_failures_by_ip WHERE user_id = %s", (user_id,))
            return "available"
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        cutoff = now - timedelta(minutes=5)
        rows = conn.execute("""
            SELECT client_ip::text AS client_ip, attempts
            FROM login_failures_by_ip WHERE user_id = %s
        """, (user_id,)).fetchall()
        recent = {
            row["client_ip"].split("/")[0]: [stamp for stamp in row["attempts"] if stamp >= cutoff]
            for row in rows
        }
        attempts = recent.setdefault(client_ip, [])
        attempts.append(now)
        if sum(map(len, recent.values())) < 5:
            conn.execute("""
                INSERT INTO login_failures_by_ip (user_id, client_ip, attempts) VALUES (%s, %s, %s)
                ON CONFLICT (user_id, client_ip) DO UPDATE SET attempts = EXCLUDED.attempts
            """, (user_id, client_ip, attempts))
            return "available"
        conn.execute("""
            INSERT INTO account_locks (incident_id, user_id, locked_by, reason, locked_at, expires_at)
            VALUES (%s, %s, 'system', '같은 계정으로 5분 안에 로그인 5회 실패', %s, %s)
        """, (incident_id, user_id, now, now + timedelta(minutes=10)))
        conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (user_id,))
        conn.execute("DELETE FROM login_failures_by_ip WHERE user_id = %s", (user_id,))
        return "locked"


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


def get_granted_doc_ids(conn, user_id):
    rows = conn.execute("""
        SELECT document_public_id::text AS doc_id
        FROM document_permissions
        WHERE user_id = %s
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > clock_timestamp())
    """, (user_id,)).fetchall() or []
    return {str(r["doc_id"]) for r in rows if isinstance(r, dict) and r.get("doc_id")}


def get_permissions_overview(conn):
    user_rows = conn.execute("""
        SELECT u.id, u.username, u.department, u.role,
               r.revoked_by, r.reason AS revoke_reason, r.revoked_at,
               r.restored_by, r.restore_reason, r.restored_at
        FROM users u
        LEFT JOIN account_revocations r ON r.user_id = u.id
        ORDER BY u.username
    """).fetchall() or []
    doc_rows = conn.execute("""
        SELECT public_id::text AS id, title, department, level
        FROM documents
        ORDER BY id
    """).fetchall() or []
    grant_rows = conn.execute("""
        SELECT p.id, u.username, u.department, u.role,
               p.document_public_id::text AS document_id,
               d.title AS document_title, d.department AS doc_department, d.level AS doc_level,
               p.granted_by, p.reason, p.granted_at, p.expires_at,
               p.revoked_by, p.revoke_reason, p.revoked_at,
               CASE WHEN p.revoked_at IS NOT NULL THEN 'revoked'
                    WHEN p.expires_at IS NOT NULL AND p.expires_at <= clock_timestamp() THEN 'expired'
                    ELSE 'active' END AS perm_status
        FROM document_permissions p
        JOIN users u ON u.id = p.user_id
        JOIN documents d ON d.public_id = p.document_public_id
        ORDER BY (p.revoked_at IS NULL AND (p.expires_at IS NULL OR p.expires_at > clock_timestamp())) DESC, p.granted_at DESC
        LIMIT 50
    """).fetchall() or []

    users = []
    for u in user_rows:
        is_revoked = bool(u["revoked_at"] and u["restored_at"] is None)
        users.append({
            "username": u["username"],
            "department": u["department"],
            "role": u["role"],
            "account_status": "revoked" if is_revoked else "active",
            "revoked_by": u["revoked_by"],
            "revoke_reason": u["revoke_reason"],
            "revoked_at": u["revoked_at"].isoformat() if u["revoked_at"] else None,
            "restored_by": u["restored_by"],
            "restore_reason": u["restore_reason"],
            "restored_at": u["restored_at"].isoformat() if u["restored_at"] else None,
        })

    grants = []
    for g in grant_rows:
        grants.append({
            "id": g["id"],
            "username": g["username"],
            "department": g["department"],
            "role": g["role"],
            "document_id": g["document_id"],
            "document_title": g["document_title"],
            "doc_department": g["doc_department"],
            "doc_level": g["doc_level"],
            "granted_by": g["granted_by"],
            "reason": g["reason"],
            "granted_at": g["granted_at"].isoformat() if g["granted_at"] else None,
            "expires_at": g["expires_at"].isoformat() if g["expires_at"] else None,
            "status": g["perm_status"],
            "revoked_by": g["revoked_by"],
            "revoke_reason": g["revoke_reason"],
            "revoked_at": g["revoked_at"].isoformat() if g["revoked_at"] else None,
        })

    pending = conn.execute("""
        SELECT r.id, r.reason, r.duration_minutes, r.created_at, u.username,
               d.title AS document_title, d.department AS doc_department, d.level AS doc_level
        FROM document_access_requests r
        JOIN users u ON u.id = r.user_id JOIN documents d ON d.public_id = r.document_id
        WHERE r.status = 'pending' ORDER BY r.id LIMIT 25
    """).fetchall()
    for row in pending:
        row["created_at"] = row["created_at"].isoformat()
    return {"status": "ok", "users": users, "documents": doc_rows, "grants": grants, "requests": pending}


def change_permission(conn, username, operator, action, reason, document_id, record, can_read_fn, duration_minutes=60):
    with conn.transaction():
        user = conn.execute(
            "SELECT id, username, department, role FROM users WHERE username = %s FOR UPDATE",
            (username,),
        ).fetchone()
        if not user:
            return None, "등록된 ERP 계정을 찾을 수 없습니다."
        user_id = user["id"]
        rev_row = conn.execute(
            "SELECT revoked_at, restored_at FROM account_revocations WHERE user_id = %s",
            (user_id,),
        ).fetchone()
        is_revoked = bool(rev_row and rev_row["revoked_at"] and rev_row["restored_at"] is None)

        if action == "grant_doc":
            if is_revoked:
                return None, "퇴사(전체 권한 회수) 상태인 계정에는 문서 권한을 부여할 수 없습니다."
            doc = conn.execute(
                "SELECT public_id, title, department, level FROM documents WHERE public_id = %s",
                (document_id,),
            ).fetchone()
            if not doc:
                return None, "문서를 찾을 수 없습니다."
            if can_read_fn(user, doc)[0]:
                return None, "해당 계정이 기본 소속·직급 권한으로 이미 열람할 수 있는 문서입니다."
            existing = conn.execute("""
                SELECT id FROM document_permissions
                WHERE user_id = %s AND document_public_id = %s
                  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp())
                LIMIT 1
            """, (user_id, doc["public_id"])).fetchone()
            if not existing:
                now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                deadline = now + timedelta(minutes=duration_minutes)
                conn.execute("""
                    INSERT INTO document_permissions (user_id, document_public_id, granted_by, reason, granted_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (user_id, doc["public_id"], operator, reason, now, deadline))
                record("doc_permission_granted", username=username, operator=operator,
                       document_id=str(doc["public_id"]), doc_title=doc["title"],
                       doc_department=doc["department"] or "", doc_level=doc["level"],
                       duration_minutes=duration_minutes, expires_at_utc=deadline.isoformat(), reason=reason)
        elif action == "revoke_doc":
            updated = conn.execute("""
                UPDATE document_permissions
                SET revoked_by = %s, revoke_reason = %s, revoked_at = clock_timestamp()
                WHERE user_id = %s AND document_public_id = %s
                  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp())
                RETURNING document_public_id
            """, (operator, reason, user_id, document_id)).fetchone()
            if not updated:
                return None, "회수할 활성 문서 권한이 없습니다."
            record("doc_permission_revoked", username=username, operator=operator,
                   document_id=str(document_id), reason=reason)
        elif action == "retire_account":
            conn.execute("""
                UPDATE document_permissions
                SET revoked_by = %s, revoke_reason = %s, revoked_at = clock_timestamp()
                WHERE user_id = %s AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > clock_timestamp())
            """, (operator, f"퇴사·전면 회수: {reason}", user_id))
            conn.execute("""
                INSERT INTO account_revocations (user_id, revoked_by, reason, revoked_at, restored_by, restore_reason, restored_at)
                VALUES (%s, %s, %s, clock_timestamp(), NULL, NULL, NULL)
                ON CONFLICT (user_id) DO UPDATE SET
                    revoked_by = EXCLUDED.revoked_by,
                    reason = EXCLUDED.reason,
                    revoked_at = clock_timestamp(),
                    restored_by = NULL,
                    restore_reason = NULL,
                    restored_at = NULL
            """, (user_id, operator, reason))
            conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (user_id,))
            record("account_permissions_revoked", username=username, operator=operator, reason=reason)
        elif action == "restore_account":
            if not is_revoked:
                return None, "현재 퇴사(권한 회수) 상태인 계정이 아닙니다."
            conn.execute("""
                UPDATE account_revocations
                SET restored_by = %s, restore_reason = %s, restored_at = clock_timestamp()
                WHERE user_id = %s AND restored_at IS NULL
            """, (operator, reason, user_id))
            conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (user_id,))
            record("account_permissions_restored", username=username, operator=operator, reason=reason)

        return get_permissions_overview(conn), None
