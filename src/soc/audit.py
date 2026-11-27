"""Durable release attribution and payload-free collection error metadata."""
from __future__ import annotations
import hashlib
import html
import re
import uuid
from datetime import datetime, timezone

SCHEMA = '''
CREATE TABLE IF NOT EXISTS action_release_audit (
 operation_id TEXT PRIMARY KEY,
 incident_id TEXT NOT NULL,
 approval_id TEXT NOT NULL,
 requested_by TEXT NOT NULL,
 reason TEXT NOT NULL,
 requested_at_utc TIMESTAMPTZ NOT NULL,
 result TEXT NOT NULL CHECK (result IN ('pending','succeeded','failed','unknown')),
 completed_at_utc TIMESTAMPTZ,
 observed_status TEXT,
 observed_at_utc TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_release_audit_incident ON action_release_audit(incident_id,requested_at_utc);
CREATE INDEX IF NOT EXISTS idx_release_audit_approval ON action_release_audit(approval_id,result);
CREATE TABLE IF NOT EXISTS collector_errors (
 error_id TEXT PRIMARY KEY,
 source TEXT NOT NULL,
 file_path TEXT NOT NULL,
 file_inode TEXT NOT NULL,
 line_offset BIGINT NOT NULL,
 byte_length BIGINT NOT NULL,
 content_sha256 TEXT NOT NULL,
 error_code TEXT NOT NULL,
 ingest_mode TEXT NOT NULL,
 received_at_utc TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_collector_errors_source ON collector_errors(source,received_at_utc);
'''

def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def ensure_audit_schema(storage):
    """Additive, idempotent initialization for existing volumes as well as new PCs."""
    pg = storage.__class__.__name__ == 'PostgresSocStorage'
    conn = storage._conn
    sql = SCHEMA if pg else SCHEMA.replace('TIMESTAMPTZ', 'TEXT')
    with (conn.transaction() if pg else conn):
        cur = conn.cursor()
        try:
            if pg:
                # Dashboard and collector can start on the same existing volume together.
                cur.execute("SELECT pg_advisory_xact_lock(1397703489)")
            for statement in sql.split(';'):
                if statement.strip():
                    cur.execute(statement)
        finally:
            cur.close()


def write_collection_errors(cur, errors, file_inode, *, postgres=False):
    """Called inside the SAME transaction as events and their file offset."""
    query = '''INSERT INTO collector_errors
        (error_id,source,file_path,file_inode,line_offset,byte_length,content_sha256,error_code,ingest_mode,received_at_utc)
        VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING'''
    if postgres:
        query = query.replace('?', '%s')
    now = utc_now()
    for error in errors:
        identity = f'{error.source}\0{error.file_path}\0{file_inode}\0{error.line_offset}\0{error.content_sha256}'
        cur.execute(query, (hashlib.sha256(identity.encode()).hexdigest(),error.source,error.file_path,
            file_inode,error.line_offset,error.byte_length,error.content_sha256,error.error_code,error.ingest_mode,now))


class AuditRepository:
    def __init__(self, storage):
        from .repository import SocRepository
        self.repo = SocRepository(storage)

    def _write(self, query, values):
        def execute():
            conn=self.repo._conn
            with (conn.transaction() if self.repo._is_pg else conn):
                cur=conn.cursor()
                try:
                    self.repo._execute(cur,query,values)
                    return cur.rowcount
                finally:
                    cur.close()
        return self.repo._run_db(execute)

    def begin_release(self, operation_id, incident_id, approval_id, actor, reason):
        return self._write('''INSERT INTO action_release_audit
            (operation_id,incident_id,approval_id,requested_by,reason,requested_at_utc,result)
            VALUES (?,?,?,?,?,?,'pending') ON CONFLICT DO NOTHING''',
            (operation_id,incident_id,approval_id,actor,reason,utc_now())) == 1

    def finish_release(self, operation_id, result):
        if result not in {'succeeded','failed','unknown'}:
            raise ValueError('Invalid audit result')
        self._write('''UPDATE action_release_audit SET result=?,completed_at_utc=?
            WHERE operation_id=? AND result='pending' ''', (result,utc_now(),operation_id))

    def observe_release(self, approval_id, response):
        status = response.get('status')
        if status not in {'released','expired','applied','not_found'} or response.get('error'):
            return
        # A GET is an observation, not proof that a particular release request succeeded.
        if status in {'released','expired'} and response.get('rule_present') is not False:
            return
        if status == 'applied' and response.get('rule_present') is False:
            status = 'rule_missing'
        self._write('''UPDATE action_release_audit SET observed_status=?,observed_at_utc=?
            WHERE approval_id=? AND result IN ('pending','unknown')''', (status,utc_now(),approval_id))

    def list_releases(self, incident_id, limit=50):
        names=('operation_id','incident_id','approval_id','requested_by','reason','requested_at_utc',
               'result','completed_at_utc','observed_status','observed_at_utc')
        rows=self.repo._fetchall('SELECT '+','.join(names)+''' FROM action_release_audit
            WHERE incident_id=? ORDER BY requested_at_utc DESC,operation_id DESC LIMIT ?''',
            (incident_id,max(1,min(200,int(limit)))))
        return [{k:(v.isoformat() if isinstance(v,datetime) else v) for k,v in zip(names,row)} for row in rows]

    def list_collection_errors(self, source=None, limit=20):
        names=('error_id','source','file_path','file_inode','line_offset','byte_length','content_sha256',
               'error_code','ingest_mode','received_at_utc')
        clause=' WHERE source=?' if source else ''
        rows=self.repo._fetchall('SELECT '+','.join(names)+' FROM collector_errors'+clause+
            ' ORDER BY received_at_utc DESC,error_id DESC LIMIT ?',
            ((source,) if source else ())+(max(1,min(200,int(limit))),))
        return [{k:(v.isoformat() if isinstance(v,datetime) else v) for k,v in zip(names,row)} for row in rows]

    def count_collection_errors(self, source=None):
        rows=self.repo._fetchall('SELECT COUNT(*) FROM collector_errors'+(' WHERE source=?' if source else ''),
            (source,) if source else ())
        return int(rows[0][0])


def audit_for_store(store):
    if hasattr(store,'storage'):
        return AuditRepository(store.storage)
    # Preview store: keep the same semantics without durable production data.
    if not hasattr(store,'_audit_storage'):
        from .storage import SQLiteSocStorage
        store._audit_storage=SQLiteSocStorage()
    return AuditRepository(store._audit_storage)


def release_with_audit(store, incident, *, approval_id, requested_by, reason, operation_id=''):
    from .incident_service import ActionPolicyError, release_approval
    reason=reason.strip()
    if not requested_by or len(requested_by)>128 or not requested_by.isprintable():
        raise ActionPolicyError('해제 담당자를 확인할 수 없습니다.')
    if not reason or len(reason)>200 or not reason.isprintable():
        raise ActionPolicyError('해제 사유를 1~200자로 입력해 주세요.')
    target=next((a for a in incident.approvals if a.approval_id==approval_id),None)
    if target is None or store.action_client is None:
        raise ActionPolicyError('해제 대상 승인 또는 게이트웨이 연결이 없습니다.')
    # Legacy clients without an operation token still get a stable retry identity.
    operation_id=operation_id or str(uuid.uuid5(uuid.NAMESPACE_URL,
        f'release:{incident.incident_id}:{approval_id}:{requested_by}:{reason}'))
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',operation_id):
        raise ActionPolicyError('잘못된 해제 요청 번호입니다.')
    audit=audit_for_store(store)
    if not audit.begin_release(operation_id,incident.incident_id,approval_id,requested_by,reason):
        raise ActionPolicyError('이미 기록된 해제 요청입니다. 상태 조회 후 필요하면 새 요청을 작성해 주세요.')
    # The request is committed before any gateway side effect. A crash leaves pending.
    try:
        approval=release_approval(incident,approval_id=approval_id,action_client=store.action_client)
        response=approval.gateway_response if approval else {}
        if response.get('error')=='release_communication_error':
            result='unknown'
        elif response.get('status')=='released':
            result='succeeded'
        elif response.get('error') or response.get('status') in {'rejected','failed','not_found'}:
            result='failed'
        else:
            result='unknown'
    except Exception:
        audit.finish_release(operation_id,'unknown')
        raise
    audit.finish_release(operation_id,result)
    return approval


def release_fields():
    token=uuid.uuid4().hex
    return (f'<input type="hidden" name="operation_id" value="{token}" />'
        '<input name="reason" type="text" maxlength="200" required placeholder="해제 사유" '
        'aria-label="IP 차단 해제 사유" style="width:90px;" />')


def release_audit_panel(rows):
    esc=lambda v:html.escape(str(v if v is not None else ''))
    labels={'pending':'요청 기록됨 · 결과 미확인','unknown':'결과 미확인','succeeded':'해제 응답 확인','failed':'해제 실패'}
    body=''.join('<tr>'+''.join(f'<td>{value}</td>' for value in (
        esc(r['requested_at_utc']),esc(r['requested_by']),esc(r['reason']),
        esc(labels[r['result']]),esc(r['completed_at_utc'] or '-'),
        esc((r['observed_status'] or '-')+' · '+(r['observed_at_utc'] or '-'))))+ '</tr>' for r in rows)
    return ('<div class="panel" id="release-audit"><h2>IP 차단 해제 이력</h2>'
        '<p class="panel-sub">최근 50건 · UTC · 최초 승인자와 별도로 기록합니다. 후속 조회는 해당 요청의 성공을 증명하지 않습니다.</p>'
        '<table><thead><tr><th>요청 시각</th><th>해제 요청자</th><th>사유</th><th>요청 결과</th><th>응답 시각</th><th>후속 관측 상태 · 시각</th></tr></thead>'
        '<tbody>'+ (body or '<tr><td colspan="6">기록된 해제 요청이 없습니다. 과거 요청의 담당자는 추정하지 않습니다.</td></tr>')+'</tbody></table></div>')


def collection_error_panel(store,source):
    if not hasattr(store,'storage'):
        return ''
    repo=AuditRepository(store.storage)
    count=repo.count_collection_errors(source)
    rows=repo.list_collection_errors(source,10)
    esc=lambda v:html.escape(str(v))
    labels={'invalid_utf8':'문자 인코딩 오류','invalid_json':'JSON 형식 오류','normalization_error':'필수 필드·형식 오류','unexpected_error':'처리 오류'}
    body=''.join('<tr>'+''.join(f'<td>{v}</td>' for v in (
        esc(r['received_at_utc']),esc(r['file_path']),str(r['line_offset']),str(r['byte_length']),
        esc(labels.get(r['error_code'],'처리 오류')),f'<code>{esc(r["content_sha256"])}</code>'))+'</tr>' for r in rows)
    return (f'<div class="panel" id="collection-errors"><h2>수집 오류 {count:,}건</h2>'
        '<p class="panel-sub">전체 보관 기간 합계 · 최근 10건 · UTC · 원문은 별도 저장하지 않습니다. 위치·길이·SHA-256으로 원본 파일을 대조하세요.</p>'
        '<table><thead><tr><th>수집 시각</th><th>파일·세대</th><th>바이트 위치</th><th>길이</th><th>오류 종류</th><th>원문 해시</th></tr></thead><tbody>'+
        (body or '<tr><td colspan="6">기록된 수집 오류가 없습니다.</td></tr>')+'</tbody></table></div>')
