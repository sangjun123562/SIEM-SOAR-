"""Weekly SOC reports with immutable finalized snapshots."""
import html
import json
import uuid
from datetime import date, datetime, time, timedelta, timezone
from urllib.parse import quote, urlencode

from .repository import SocRepository

KST = timezone(timedelta(hours=9))
# summary 는 사람이 쓰는 결론이다. 기계가 만든 사실 문장은 notes 에 저장하지 않는다.
# 후속 조치는 자유 서술이 아니라 report_followups 장부로 옮겼다. 옛 확정본의 notes["followup"] 은 읽기만 한다.
FIELDS = (("summary", "핵심 판단"), ("assessment", "판단 근거"), ("opinion", "담당자 의견"))
HUMAN_ONLY_FIELDS = frozenset({"summary", "assessment", "opinion"})

# 지표 정의는 한 곳에서만 쓴다. title 속성(호버 전용)으로는 내보내지 않고 각주 절에 싣는다.
DEFINITIONS = (
    ("조치 대기", "이 기간에 생성되어 아직 열려 있는 사건 중 IP 차단 승인 경로가 있는 사건입니다."),
    ("판단 대기", "이 기간에 생성되어 아직 열려 있는 사건 중 조사용 경보만 붙어 종결 경로가 없는 사건입니다."),
    ("차단 시간 중 로그인 성공", "차단이 유효한 시간에 그 IP에서 ERP 로그인이 성공한 기록 수입니다. 조회한 로그 안에서 센 값이며, 차단 우회를 확정하는 수치는 아닙니다."),
    ("차단 요청 미확정", "승인했으나 게이트웨이 적용이 확인되지 않은 건입니다. 한 건이라도 있으면 차단했다고 보고할 수 없습니다."),
    ("신규 사건", "기간 안에 생성된 사건입니다. 수집한 이벤트 건수와 구분합니다."),
    ("움직인 사건", "신규 사건과 이전 사건의 후속 조치를 합한 수입니다."),
    ("ERP 계정 자동 잠금", "기간 안에 자동 잠금 탐지 창이 끝난 기록입니다. 현재 잠금 상태와 구분합니다."),
    ("IP 차단 요청", "기간 안에 게이트웨이 차단을 요청한 횟수입니다."),
    ("IP 차단 적용", "요청 중 적용이 확인된 건입니다. 이후 해제·만료된 건도 포함합니다."),
    ("IP 차단 거부", "요청 중 게이트웨이가 거부한 건입니다."),
    ("재발", "같은 IP 또는 같은 계정의 ERP 로그인 실패가 이 기간 안에서 서로 다른 2일 이상에 나타난 수입니다(KST 날짜). 사람이나 공격자 수가 아닙니다."),
    ("문서 열람 거부", "401은 로그인되지 않은 요청, 403은 권한 없는 문서 요청, 404는 없는 문서 요청입니다. 403과 404는 의미가 달라 나눠 셉니다."),
    ("지난 기간 대비", "양쪽이 모두 확정본이고 어느 쪽에도 수집 공백 의심이 없을 때만 비교합니다. 조건이 안 맞으면 숫자를 만들지 않고 이유를 적습니다."),
    ("차단으로 막은 접속 시도", "차단 유효 시간의 게이트웨이 기록으로 집계한 접속 시도입니다. 같은 연결의 재전송은 한 번으로 세며, 공격자 수나 피해 규모가 아닙니다."),
)
# 후속 조치 상태. '대기'는 우리 손을 떠난 일(외부 회신 등)이라 기한 초과로 세지 않는다.
FOLLOWUP_STATES = (("open", "열림"), ("doing", "진행"), ("waiting", "대기(우리 손을 떠남)"),
                   ("done", "완료"), ("dropped", "미채택"))
FOLLOWUP_LABELS = dict(FOLLOWUP_STATES)
FOLLOWUP_ACTIVE = ("open", "doing", "waiting")
FOLLOWUP_NEEDS_NOTE = {"done": "완료 근거", "dropped": "미채택 사유"}
FOLLOWUP_CARRY_FLAG = 3  # 이 횟수 이상 이월되면 글자로 표시한다. 담당자별 집계·순위는 만들지 않는다.
BLOCK_DONE = frozenset({"applied", "released", "expired"})
BLOCK_SETTLED = BLOCK_DONE | {"rejected"}
# 미결 경과일 버킷: (라벨, 하한, 상한). 마지막 버킷은 상한이 없다. 고정 축이라 0건 행도 그대로 둔다.
AGING_BUCKETS = (("0~1일", 0, 1), ("2~3일", 2, 3), ("4~7일", 4, 7), ("8일 이상", 8, None))
ACTION_LABELS = {"applied": "적용", "released": "적용 후 해제", "expired": "적용 후 만료",
                 "pending": "확인 대기", "unknown": "적용 확인 필요", "rejected": "거부",
                 "apply_failed": "적용 실패"}


def _fmt(value):
    return f"{value:,}"


def ratio_text(part, whole):
    """분모가 작을 때 비율을 쓰지 않는다. 비율을 쓸 때는 분수를 병기한다."""
    if not whole:
        return "산출 대상 없음"
    if whole < 5:
        return f"{_fmt(part)}건 / {_fmt(whole)}건"
    return f"{100 * part / whole:.1f}% ({_fmt(part)}/{_fmt(whole)})"


def calculated_draft(snapshot):
    """사람이 써야 하는 핵심 판단은 만들지 않는다. 확인 후보만 제안한다."""
    metrics = snapshot["metrics"]
    rejected = metrics.get("IP 차단 거부", 0)
    pending = sum(snapshot.get("unsettled", {}).values())
    parts = []
    if rejected:
        parts.append(f"거부 {_fmt(rejected)}건의 사건과 조치 결과를 확인한다.")
    if pending:
        parts.append(f"미확정 차단 {_fmt(pending)}건의 게이트웨이 적용 상태를 확인한다.")
    if snapshot.get("replay_alerts"):
        parts.append(f"집계에 포함된 재생·합성 근거 경보 {_fmt(snapshot['replay_alerts'])}건의 범위를 확인한다.")
    if not parts:
        parts.append("집계에서 미확정 조치가 확인되지 않았다. 사건별 근거와 수집 상태를 검토한다.")
    parts.append("담당자와 목표일은 운영자가 지정한다.")
    return {"followup": " ".join(parts)}


def machine_facts(snapshot):
    """기간 집계 사실. 사람이 고칠 수 없고 재집계 때마다 다시 만들어진다."""
    metrics = snapshot["metrics"]
    requests = metrics.get("IP 차단 요청", 0)
    applied = metrics.get("IP 차단 적용", 0)
    rejected = metrics.get("IP 차단 거부", 0)
    unsettled = sum(snapshot.get("unsettled", {}).values())
    lines = [
        f'신규 사건 {_fmt(metrics.get("신규 사건", 0))}건, 이 기간에 움직인 사건 {_fmt(len(snapshot.get("cases", [])))}건, '
        f'ERP 계정 자동 잠금 {_fmt(metrics.get("ERP 계정 자동 잠금", 0))}건을 집계했다.',
        f'IP 차단 요청 {_fmt(requests)}건 중 {_fmt(applied)}건 적용, {_fmt(rejected)}건 거부, {_fmt(unsettled)}건 미확정이다. '
        f'적용 비율은 {ratio_text(applied, requests)}이며 산식은 적용 건수 / 요청 건수다.',
        "사건 건수와 로그 건수는 서로 다른 단위이며, 이 수치만으로 침해 성공이나 피해를 확정할 수 없다.",
    ]
    return lines


def aging_index(days):
    """경과일(0 이상 정수)이 속한 버킷의 순번."""
    for index, (_, _, high) in enumerate(AGING_BUCKETS):
        if high is None or days <= high:
            return index


def week_start(value: str = "") -> date:
    day = date.fromisoformat(value) if value else datetime.now(KST).date()
    if not 2000 <= day.year <= 2100:
        raise ValueError("2000~2100년 사이의 날짜를 선택하세요.")
    return day - timedelta(days=day.weekday())


def report_period(value="", kind="weekly"):
    if kind == "weekly":
        return week_start(value)
    if kind != "monthly":
        raise ValueError("보고서 유형을 확인하세요.")
    if len(value) == 7:
        value += "-01"
    day = date.fromisoformat(value) if value else datetime.now(KST).date()
    if not 2000 <= day.year <= 2100:
        raise ValueError("보고서 날짜를 확인하세요.")
    return day.replace(day=1)


def period_end(day, kind):
    return (day.replace(day=28) + timedelta(days=4)).replace(day=1) if kind == "monthly" else day + timedelta(days=7)


def report_key(day, kind):
    return f"monthly:{day}" if kind == "monthly" else str(day)


class ReportRepository(SocRepository):
    def __init__(self, storage):
        super().__init__(storage)
        def create():
            cur = self._conn.cursor()
            try:
                cur.execute("""CREATE TABLE IF NOT EXISTS weekly_reports (
                    week TEXT PRIMARY KEY, author TEXT NOT NULL, saved_at TEXT NOT NULL,
                    finalized INTEGER NOT NULL, payload TEXT NOT NULL
                )""")
                cur.execute("""CREATE TABLE IF NOT EXISTS report_followups (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, period_key TEXT NOT NULL,
                    text TEXT NOT NULL, owner TEXT NOT NULL, due TEXT NOT NULL,
                    status TEXT NOT NULL, closing_note TEXT NOT NULL,
                    created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL, updated_at TEXT NOT NULL
                )""")
            finally:
                cur.close()
        self._run_db(create)

    # --- 후속 조치 장부: 확정본과 달리 상태가 계속 바뀌므로 보고서 행과 따로 저장한다. ---
    _FU_COLUMNS = ("id, kind, period_key, text, owner, due, status, closing_note, created_by, created_at, "
                   "updated_by, updated_at")

    @staticmethod
    def _fu_row(row):
        keys = ("id", "kind", "period_key", "text", "owner", "due", "status", "closing_note",
                "created_by", "created_at", "updated_by", "updated_at")
        return dict(zip(keys, row))

    def _write(self, query, params):
        """한 문장 쓰기. 바뀐 행이 있으면 True. SQLite·PostgreSQL 모두 같은 모양으로 쓴다."""
        if self._is_pg:
            return bool(self._fetchall(query + " RETURNING id", params))

        def run():
            with self._conn:
                cur = self._conn.cursor()
                try:
                    cur.execute(query, params)
                    return cur.rowcount > 0
                finally:
                    cur.close()
        return run()

    def add_followup(self, kind, period_key, text, owner, due, author):
        stamp = datetime.now(KST).isoformat(timespec="seconds")
        new_id = uuid.uuid4().hex[:12]
        ok = self._write(
            f"INSERT INTO report_followups ({self._FU_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (new_id, kind, period_key, text, owner, due, "open", "", author, stamp, author, stamp))
        return new_id if ok else None

    def update_followup(self, followup_id, status, note, author):
        return self._write(
            "UPDATE report_followups SET status=?, closing_note=?, updated_by=?, updated_at=? WHERE id=?",
            (status, note, author, datetime.now(KST).isoformat(timespec="seconds"), followup_id))

    def visible_followups(self, kind, period_key):
        """이 기간 보고서에 보여 줄 항목: 이 기간에 만든 것 + 이전 기간에서 아직 안 끝난 것 전부.
        매번 질의한다(복사하면 확정 시 동결되어 이월이 멈춘다)."""
        active = tuple(FOLLOWUP_ACTIVE)
        marks = ",".join("?" for _ in active)
        rows = self._fetchall(
            f"SELECT {self._FU_COLUMNS} FROM report_followups WHERE kind = ? AND "
            f"(period_key = ? OR (period_key < ? AND status IN ({marks}))) ORDER BY period_key, created_at",
            (kind, period_key, period_key) + active)
        return [self._fu_row(row) for row in rows]

    def followups_by_ids(self, ids):
        ids = list(ids)
        if not ids:
            return []
        marks = ",".join("?" for _ in ids)
        rows = self._fetchall(f"SELECT {self._FU_COLUMNS} FROM report_followups WHERE id IN ({marks})", tuple(ids))
        return [self._fu_row(row) for row in rows]

    def get_followup(self, followup_id):
        rows = self.followups_by_ids([followup_id])
        return rows[0] if rows else None

    def get(self, week):
        rows = self._fetchall("SELECT author, saved_at, finalized, payload FROM weekly_reports WHERE week = ?", (str(week),))
        if not rows:
            return None
        author, saved_at, finalized, payload = rows[0]
        return dict(json.loads(payload), author=author, saved_at=saved_at, finalized=bool(finalized))

    def list(self):
        return self._fetchall("SELECT week, finalized, author FROM weekly_reports ORDER BY week DESC")

    def save(self, week, author, finalized, payload):
        def write():
            with self._conn:
                cur = self._conn.cursor()
                try:
                    self._execute(cur, """
                        INSERT INTO weekly_reports (week, author, saved_at, finalized, payload)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT (week) DO UPDATE SET author=excluded.author,
                            saved_at=excluded.saved_at, finalized=excluded.finalized, payload=excluded.payload
                        WHERE weekly_reports.finalized = 0
                    """, (str(week), author, datetime.now(KST).isoformat(timespec="seconds"),
                          int(finalized), json.dumps(payload, ensure_ascii=False)))
                    return cur.rowcount == 1
                finally:
                    cur.close()
        # A psycopg connection context closes the connection. Use its transaction context instead.
        if self._is_pg:
            return self._run_db(lambda: self._save_pg(week, author, finalized, payload))
        return write()

    def _save_pg(self, week, author, finalized, payload):
        return bool(self._fetchall("""
            INSERT INTO weekly_reports (week, author, saved_at, finalized, payload)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (week) DO UPDATE SET author=excluded.author,
                saved_at=excluded.saved_at, finalized=excluded.finalized, payload=excluded.payload
            WHERE weekly_reports.finalized = 0 RETURNING week
        """, (str(week), author, datetime.now(KST).isoformat(timespec="seconds"),
              int(finalized), json.dumps(payload, ensure_ascii=False))))


def weekly_snapshot(incidents, week, parse_time, auto_rule, effects_for=None, *, kind="weekly", now=None):
    start = datetime.combine(week, time.min, KST)
    end = datetime.combine(period_end(week, kind), time.min, KST)

    def in_week(value):
        stamp = parse_time(value)
        return stamp is not None and start <= stamp < end

    cases = []
    blocks = []
    block_log = []
    aging = [{"action": 0, "review": 0} for _ in AGING_BUCKETS]
    daily = [{"date": str(week + timedelta(days=i)), "cases": 0, "locks": 0, "requests": 0}
             for i in range((end.date() - week).days)]

    def increment(value, key):
        stamp = parse_time(value)
        if stamp is not None and start <= stamp < end:
            daily[(stamp.astimezone(KST).date() - week).days][key] += 1

    locks = requests = applied = rejected = 0
    unsettled = {"pending": 0, "unknown": 0, "apply_failed": 0}
    open_action = open_review = 0
    oldest_open = None
    replay_alerts = 0
    now = now or datetime.now(KST)
    for inc in incidents:
        new = in_week(inc.created_at_utc)
        increment(inc.created_at_utc, "cases")
        lock_ids = {a.alert_id: a for a in inc.alerts if a.rule_id == auto_rule and in_week(a.window_end_utc)}
        for alert in lock_ids.values():
            increment(alert.window_end_utc, "locks")
        locks += len(lock_ids)
        actions = [a for a in inc.approvals if a.action_type == "block" and in_week(a.approved_at_utc)]
        for action in actions:
            increment(action.approved_at_utc, "requests")
            if action.status in unsettled:
                unsettled[action.status] += 1
            # 감사용 전체 근거: 승인 한 건마다 한 줄. 필드는 방어적으로 읽는다.
            block_log.append({"approval_id": getattr(action, "approval_id", ""), "incident_id": inc.incident_id,
                              "target_ip": getattr(action, "target_ip", ""), "status": action.status,
                              "approved_at_utc": action.approved_at_utc})
        blocks.extend(a for a in actions if a.status in BLOCK_DONE)
        requests += len(actions)
        applied += sum(a.status in BLOCK_DONE for a in actions)
        rejected += sum(a.status == "rejected" for a in actions)
        if new:
            # 조치 대기와 판단 대기를 나눈다. 조사용 사건은 종결 경로가 없어 계속 쌓인다.
            if getattr(inc, "status", "open") == "open":
                if getattr(inc, "block_rule_eligible", False):
                    open_action += 1
                else:
                    open_review += 1
                created = parse_time(inc.created_at_utc)
                if created is not None:
                    days = max(0, (now - created).days)
                    oldest_open = days if oldest_open is None else max(oldest_open, days)
                    aging[aging_index(days)]["action" if getattr(inc, "block_rule_eligible", False) else "review"] += 1
            for alert in inc.alerts:
                if in_week(alert.window_end_utc) and any(
                        mode != "live" for mode in getattr(alert, "ingest_modes", ()) or ()):
                    replay_alerts += 1
        if new or lock_ids or actions:
            cases.append({"id": inc.incident_id, "title": inc.title, "new": new,
                          "locks": len(lock_ids), "ip": [a.status for a in actions],
                          "severity": getattr(inc, "severity", ""),
                          "target_ip": getattr(inc, "target_ip", ""),
                          "username": getattr(inc, "username", ""),
                          "status": getattr(inc, "status", ""),
                          "created_at_utc": inc.created_at_utc})
    effects = effects_for(blocks) if effects_for and blocks else {}
    # 0건(대상 없음)과 집계 실패를 구분한다. 둘을 같은 "집계 불가"로 묶으면 독자가 고장으로 읽는다.
    if not blocks:
        effect = {"state": "none", "reason": "이 기간에 적용이 확인된 차단이 없습니다."}
    elif len(effects) == len(blocks):
        effect = {"state": "ok", "attempts": sum(item["attempts"] for item in effects.values()),
                  "success": sum(item["success"] for item in effects.values())}
    else:
        effect = {"state": "unknown",
                  "reason": f"차단 {len(blocks)}건 중 {len(blocks) - len(effects)}건의 게이트웨이 기록을 확인하지 못했습니다."}
    blocked = effect.get("attempts") if effect["state"] == "ok" else None
    return {"metrics": {"신규 사건": sum(case["new"] for case in cases), "ERP 계정 자동 잠금": locks,
                        "IP 차단 요청": requests, "IP 차단 적용": applied, "IP 차단 거부": rejected,
                        "차단으로 막은 접속 시도": blocked},
            "open": {"action": open_action, "review": open_review, "oldest_days": oldest_open, "aging": aging},
            "unsettled": unsettled, "effect": effect, "replay_alerts": replay_alerts,
            "generated_at": now.isoformat(timespec="seconds"),
            "cases": cases, "daily": daily, "approvals": block_log}


REPORT_STYLE = """<style>
.rp-view {--hatch:repeating-linear-gradient(135deg,rgb(var(--text-rgb)/0.58) 0 3px,rgb(var(--text-rgb)/0.10) 3px 6px);
  display:grid;gap:16px;min-width:0;word-break:keep-all;overflow-wrap:anywhere}
.rp-view section[id],.rp-view header[id] {scroll-margin-top:96px}
.rp-head {position:sticky;top:0;z-index:15;display:grid;gap:10px}
.rp-head-main {display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px}
.rp-head h1 {margin:0;font-size:20px;font-weight:600;letter-spacing:-0.02em;color:var(--text)}
.rp-head-meta {margin:4px 0 0;font-size:13px;color:var(--text-2);display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center}
.rp-period {display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.rp-period label {font-size:12px;color:var(--text-3)}
.rp-period input {font:inherit;font-size:13px;padding:6px 8px;min-height:36px;color:var(--text);
  background:var(--bg);border:1px solid var(--line);border-radius:var(--radius-sm)}
.rp-chip {display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:var(--text);
  background:rgb(var(--text-rgb)/0.08);border-radius:999px;padding:3px 10px}
.rp-chip::before {content:"";width:6px;height:6px;border-radius:50%;background:var(--text-3)}
.rp-chip.is-draft::before {background:var(--warn)}
.rp-chip.is-final::before {background:var(--ok)}
.rp-jump {display:none;gap:4px 10px;overflow-x:auto;padding-bottom:2px}
.rp-jump .range-chip {flex:none;white-space:nowrap}
.rp-workspace {display:grid;grid-template-columns:minmax(0,1fr) 264px;gap:16px;align-items:start}
.rp-main,.rp-rail {display:grid;gap:16px;min-width:0}
.rp-rail {position:sticky;top:96px}
.rp-view .panel {margin:0}
.rp-toc {display:grid}
.rp-toc a {display:flex;justify-content:space-between;gap:8px;align-items:center;min-height:36px;
  font-size:13px;color:var(--text-2);border-top:1px solid var(--line-soft);padding:2px 0}
.rp-toc a:first-child {border-top:0}
.rp-toc a:hover {color:var(--text)}
.rp-toc span {font-size:12px;color:var(--text-3);font-weight:600}
.rp-verdict {font-size:16px;line-height:1.7;color:var(--text-2);margin:0 0 14px;max-width:620px}
.rp-verdict b {color:var(--text);font-weight:600}
.rp-verdict.is-missing {color:var(--text-3)}
.rp-strip {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));
  border:1px solid var(--line);border-radius:var(--radius-sm);overflow:hidden;background:var(--surface)}
.rp-cell {display:grid;align-content:start;gap:0;padding:14px 16px 12px;min-height:112px;
  border-left:1px solid var(--line);color:inherit;text-decoration:none;
  transition:background-color 150ms var(--ease)}
.rp-cell:first-child {border-left:0}
@media (hover:hover) {.rp-cell:hover {background:var(--raised);text-decoration:none}}
.rp-cell:focus-visible {outline:2px solid var(--accent);outline-offset:-3px}
.rp-cell-label {font-size:12px;color:var(--text-3);font-weight:500}
.rp-cell-val {font-size:28px;font-weight:600;letter-spacing:-0.03em;line-height:1.1;margin-top:6px;color:var(--text)}
.rp-cell-val small {font-size:14px;font-weight:500;color:var(--text-2);margin-left:2px}
.rp-cell-val.rp-soft {font-size:20px;letter-spacing:-0.02em;line-height:1.25;color:var(--text-2)}
.rp-cell-sub {font-size:12px;color:var(--text-2);margin-top:6px;line-height:1.5}
.rp-cell-link {font-size:12px;color:var(--accent);margin-top:8px;min-height:20px}
.rp-cell[data-state="unknown"] {box-shadow:inset 3px 0 0 var(--warn)}
.rp-cell[data-state="unknown"] .rp-cell-sub {color:var(--text)}
.rp-cell[data-impact="hit"] {background:rgb(var(--danger-rgb)/0.07);box-shadow:inset 3px 0 0 var(--danger)}
.rp-cell[data-impact="hit"] .rp-cell-val {color:var(--danger)}
.rp-alert {display:block;margin-top:10px;padding:12px 14px;color:inherit;text-decoration:none;
  background:rgb(var(--warn-rgb)/0.10);border:1px solid rgb(var(--warn-rgb)/0.38);
  border-left:3px solid var(--warn);border-radius:0 var(--radius-sm) var(--radius-sm) 0}
@media (hover:hover) {.rp-alert:hover {background:rgb(var(--warn-rgb)/0.16);text-decoration:none}}
.rp-alert:focus-visible {outline:2px solid var(--accent);outline-offset:2px}
.rp-alert-head {display:block;font-size:13px;font-weight:600;color:var(--text)}
.rp-alert-head b {font-size:20px;font-weight:600;letter-spacing:-0.02em;margin-left:6px}
.rp-alert-sub {display:block;font-size:12px;color:var(--text-2);margin-top:4px;line-height:1.5}
.rp-trust {display:flex;flex-wrap:wrap;gap:4px 16px;font-size:13px;color:var(--text-2);line-height:1.6;
  margin-top:14px;padding-top:12px;border-top:1px solid var(--line-soft)}
.rp-trust b {color:var(--text);font-weight:600}
.rp-fn {font-size:11px;line-height:1;vertical-align:super;margin-left:1px;font-weight:600}
.rp-fn::before {content:"※"}
.rp-metrics {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,124px),1fr));gap:8px 14px;margin:0}
.rp-metrics div {border-top:1px solid var(--line-soft);padding-top:6px}
.rp-metrics dt {font-size:12px;color:var(--text-3)}
.rp-metrics dd {margin:2px 0 0;font-size:20px;font-weight:600;letter-spacing:-0.02em;color:var(--text)}
.rp-metrics dd small {font-size:13px;font-weight:500;color:var(--text-2);margin-left:2px}
.rp-metrics dd .rp-soft {font-size:13px;font-weight:500;color:var(--text-2);letter-spacing:0}
.rp-cell-val .rp-soft {font-size:20px;color:var(--text-2)}
.rp-sub {margin-top:16px;padding-top:14px;border-top:1px solid var(--line-soft)}
.rp-view h2 {margin:0 0 4px}
.rp-view h3 {margin:0 0 8px;font-size:13px;font-weight:600;color:var(--text)}
.rp-view .panel > p {font-size:13px;line-height:1.7;color:var(--text-2)}
.rp-list {list-style:none;padding:0;margin:8px 0 0}
.rp-list li {border-top:1px solid var(--line-soft);padding:8px 0}
.rp-list li:first-child {border-top:0}
.rp-list-meta {margin:3px 0 0;font-size:12px;color:var(--text-3)}
.rp-machine {background:var(--sunken);border:1px solid var(--line-soft);border-left:3px solid var(--text-3);
  border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:12px 14px;margin:0 0 18px;max-width:620px}
.rp-machine-note {display:flex;align-items:center;gap:6px;margin:0 0 8px;font-size:12px;color:var(--text-3)}
.rp-machine p {margin:0 0 6px;font-size:13px;line-height:1.7;color:var(--text-2)}
.rp-machine p:last-child {margin-bottom:0}
.rp-prose {max-width:620px}
.rp-prose label {display:block;font-size:12px;font-weight:600;color:var(--text-2);margin-bottom:6px}
.rp-prose textarea {width:100%;font:inherit;font-size:13px;line-height:1.7;padding:10px;resize:vertical;
  min-height:88px;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:var(--radius-sm)}
.rp-prose p {margin:0 0 14px}
.rp-note {margin:0 0 14px;font-size:13px;line-height:1.7;color:var(--text-2);white-space:pre-wrap}
.rp-required {color:var(--danger);margin-left:2px}
.rp-actions {display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin-top:4px}
.rp-empty {font-size:13px;color:var(--text-2);margin:8px 0 0}
.rp-defs {list-style:none;padding:0;margin:0}
.rp-defs li {border-top:1px solid var(--line-soft);padding:8px 0;font-size:13px;line-height:1.6;color:var(--text-2)}
.rp-defs li:first-child {border-top:0}
.rp-defs b {color:var(--text);font-weight:600}
.rp-defs dt {margin-top:10px;font-size:12px;color:var(--text-3)}
.rp-defs dd {margin:4px 0 0;font-size:13px;line-height:1.7;color:var(--text-2);white-space:pre-wrap}
.rp-chart {font-variant-numeric:tabular-nums;--plot-height:144px}
.rp-chart-key {display:flex;flex-wrap:wrap;gap:4px 14px;align-items:center;margin:0 0 10px;font-size:12px;color:var(--text-2)}
.rp-chart-key i {display:inline-block;width:10px;height:10px;margin-right:6px;vertical-align:-1px}
.rp-s0 {background:rgb(var(--text-rgb)/0.72)}
.rp-s1 {background:var(--hatch)}
.rp-s2 {background:transparent;border:1px solid rgb(var(--text-rgb)/0.72)}
.rp-readout {display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;min-height:34px;margin-bottom:8px;
  padding:7px 10px;font-size:12px;color:var(--text-2);background:var(--sunken);
  border:1px solid var(--line-soft);border-radius:var(--radius-sm)}
.rp-readout a[hidden] {display:none}
.rp-plot-wrap {display:grid;grid-template-columns:minmax(40px,auto) minmax(0,1fr)}
.rp-scale {display:flex;flex-direction:column;justify-content:space-between;height:var(--plot-height);
  padding-right:8px;text-align:right;font-size:12px;color:var(--text-3)}
.rp-plot-scroll {overflow-x:auto}
.rp-plot {display:grid;grid-template-columns:repeat(var(--columns),minmax(0,1fr));
  min-width:max(100%,calc(var(--columns) * 22px));
  background:linear-gradient(var(--line-soft),var(--line-soft)) 0 calc(var(--plot-height) / 2)/100% 1px no-repeat}
.rp-view .rp-point {margin:0;padding:0;display:block;background:transparent;color:var(--text);border:0;
  font:inherit;min-width:0;cursor:pointer}
@media (hover:hover) {.rp-point:hover {background:var(--raised)}}
.rp-point[aria-pressed=true] {background:var(--raised)}
.rp-point[aria-pressed=true] .rp-point-label {text-decoration:underline;text-underline-offset:.2em}
.rp-point:focus-visible {outline:2px solid var(--accent);outline-offset:-2px}
.rp-bars {display:flex;justify-content:center;align-items:flex-end;gap:clamp(1px,.45vw,4px);
  height:var(--plot-height);border-bottom:1px solid var(--line)}
.rp-bars span {width:min(16%,8px);height:var(--value);box-sizing:border-box;print-color-adjust:exact}
.rp-bars span[data-zero] {border:0}
.rp-point-label {display:grid;align-content:center;min-height:28px;font-size:12px;line-height:1.1;color:var(--text-3)}
.rp-table {overflow-x:auto;margin-top:10px}
.rp-table th,.rp-table td {padding:7px 10px;text-align:right;font-variant-numeric:tabular-nums;font-size:13px}
.rp-table th:first-child,.rp-table td:first-child {text-align:left}
.rp-view details {margin-top:10px}
.rp-view summary {cursor:pointer;min-height:36px;align-content:center;font-size:13px;color:var(--text-2)}
.rp-view summary:focus-visible {outline:2px solid var(--accent);outline-offset:2px}
.rp-aging {font-variant-numeric:tabular-nums}
.rp-age-list {list-style:none;padding:0;margin:0;border-top:1px solid var(--line-soft)}
.rp-age-list li {border-bottom:1px solid var(--line-soft)}
.rp-age-row {display:grid;grid-template-columns:72px minmax(0,1fr) minmax(104px,auto) 16px;gap:12px;
  align-items:center;min-height:44px;padding:4px 10px;color:var(--text);text-decoration:none;
  transition:background-color 150ms var(--ease)}
@media (hover:hover) {.rp-age-row:hover {background:var(--raised);text-decoration:none}}
.rp-age-row:focus-visible {outline:2px solid var(--accent);outline-offset:-3px}
.rp-age-label {font-size:13px;color:var(--text)}
.rp-age-track {display:flex;height:10px;overflow:hidden;background:var(--line-soft);border-radius:var(--radius-sm)}
.rp-age-track span {flex:none;width:var(--w);height:100%;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.rp-age-val {display:grid;justify-items:end;text-align:right;line-height:1.35}
.rp-age-val b {font-size:14px;font-weight:600;color:var(--text)}
.rp-age-val small {font-size:12px;color:var(--text-2)}
.rp-age-go {font-size:12px;color:var(--text-3);text-align:right}
.rp-age-row[data-old] .rp-age-label {font-weight:700}
.rp-age-row[data-old]:not([data-zero]) {box-shadow:inset 3px 0 0 var(--danger)}
.rp-age-row[data-zero] .rp-age-label, .rp-age-row[data-zero] .rp-age-val b,
.rp-age-row[data-zero] .rp-age-val small {color:var(--text-3)}
.rp-age-note {margin:10px 0 0;font-size:12px;line-height:1.6;color:var(--text-3)}
.rp-ing-list {list-style:none;padding:0;margin:0;border-top:1px solid var(--line-soft)}
.rp-ing-row {display:grid;grid-template-columns:96px minmax(0,1fr);gap:4px 12px;align-items:center;
  padding:10px;border-bottom:1px solid var(--line-soft)}
.rp-ing-row[data-bad] {box-shadow:inset 3px 0 0 var(--danger)}
.rp-ing-name {font-size:13px;color:var(--text);font-weight:600;display:grid}
.rp-ing-name small {font-size:12px;font-weight:400;color:var(--text-2)}
.rp-ing-band {display:grid;grid-template-columns:repeat(var(--n),minmax(1px,1fr));gap:1px;height:16px}
.rp-ing-band span {display:block;height:100%;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.rp-g-hit {background:rgb(var(--text-rgb)/0.72)}
.rp-g-zero {background:var(--hatch)}
.rp-g-na {border:1px dashed var(--line)}
i.rp-g-na {display:inline-block;width:10px;height:10px;margin-right:6px;box-sizing:border-box}
.rp-ing-line {grid-column:2;margin:4px 0 0;font-size:13px;line-height:1.6;color:var(--text-2)}
.rp-ing-line b {color:var(--text);margin-right:8px}
.rp-fu-list {list-style:none;padding:0;margin:0;border-top:1px solid var(--line-soft)}
.rp-fu {display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 16px;padding:12px 10px;border-bottom:1px solid var(--line-soft)}
.rp-fu-text {margin:0;font-size:14px;line-height:1.6;color:var(--text)}
.rp-fu-main .rp-list-meta {margin:2px 0 0}
.rp-fu-flag {display:inline-block;margin:6px 8px 0 0;padding:2px 8px;font-size:12px;font-weight:600;color:var(--text);
  border:1px solid var(--text-3);border-radius:999px}
.rp-fu-flag[data-hard] {border-width:2px;border-color:var(--danger)}
.rp-fu-note {margin:6px 0 0;font-size:13px;line-height:1.6;color:var(--text-2)}
.rp-fu-states {display:flex;align-items:center;gap:8px}
.rp-fu-col {display:grid;gap:2px}
.rp-fu-col small {font-size:12px;color:var(--text-3)}
.rp-fu-arrow {color:var(--text-3)}
.rp-fu-state {font-size:13px;font-weight:600;color:var(--text)}
.rp-fu-state[data-s="done"] {font-weight:500;color:var(--text-2)}
.rp-fu-state[data-s="dropped"] {font-weight:500;color:var(--text-2);text-decoration:line-through}
.rp-fu-form,.rp-fu-add {grid-column:1 / -1;display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px}
.rp-fu-add {margin-top:14px;padding-top:12px;border-top:1px solid var(--line-soft)}
.rp-fu-form label,.rp-fu-add label {font-size:12px;color:var(--text-3)}
.rp-fu-form select,.rp-fu-form input:not([type=hidden]),.rp-fu-add input:not([type=hidden]) {font:inherit;font-size:13px;
  min-height:36px;padding:6px 8px;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:var(--radius-sm)}
.rp-fu-form input[name=note] {flex:1 1 220px;min-width:0}
.rp-fu-add input[name=text] {flex:1 1 260px;min-width:0}
.rp-xgrid {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));gap:16px}
.rp-xm h3 {margin:0 0 6px}
.rp-kv {list-style:none;padding:0;margin:0}
.rp-kv li {display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-top:1px solid var(--line-soft);
  font-size:13px;color:var(--text-2)}
.rp-kv li:first-child {border-top:0}
.rp-kv b {color:var(--text);font-variant-numeric:tabular-nums}
.rp-trend svg {display:block;margin:4px 0;color:var(--text)}
.rp-raw summary {min-height:44px;font-weight:600;color:var(--text)}
.rp-raw .rp-table th, .rp-raw .rp-table td {text-align:left;white-space:nowrap}
.rp-raw .rp-table td a {display:inline-flex;align-items:center;min-height:44px}
.rp-raw .rp-na {color:var(--text-3)}
@media (max-width:1100px) {
  .rp-workspace {grid-template-columns:minmax(0,1fr)}
  .rp-rail {position:static;order:99}
  .rp-rail .rp-toc-panel {display:none}
  .rp-jump {display:flex}
}
@media (max-width:700px) {
  .rp-age-row {grid-template-columns:56px minmax(0,1fr) minmax(88px,auto) 12px;gap:8px;padding:4px 8px}
  .rp-head h1 {font-size:17px}
  .rp-strip {grid-template-columns:repeat(2,minmax(0,1fr))}
  .rp-cell {min-height:96px;padding:12px 12px 10px}
  .rp-cell-val {font-size:24px}
  .rp-prose textarea {font-size:16px}
}
@media print {
  @page {margin:14mm 12mm 16mm}
  body:has(.rp-view) aside.sidebar, body:has(.rp-view) .topbar, body:has(.rp-view) .foot,
  .rp-jump, .rp-rail, .rp-period, .rp-print, .rp-actions, .rp-cell-link, .rp-readout,
  .rp-view form button, .rp-fu-form, .rp-fu-add {display:none !important}
  /* 원인: 기본 테마가 다크라 --text-2/--text-3 가 밝은 회색이다. 인쇄 배경만 흰색으로 바꾸면 밝은 회색 글자가 흰 종이에 얹힌다.
     그래서 인쇄 때는 .rp-view 안의 전역 토큰 자체를 라이트 값으로 되돌린다(새 토큰 없음). 흑백 인쇄에서도 4.5:1 이상. */
  .rp-view {
    --surface:#fff; --sunken:#f4f4f4; --raised:#fff; --line:#bbb; --line-soft:#d6d6d6;
    --text-rgb:17 17 17; --text:#111; --text-2:#2b2b2b; --text-3:#4a4a4a;
    --ok:#1f5a24; --danger:#8f1d31; --warn:#6b4700; --accent:#222; --on-accent:#fff;
    color-scheme:light}
  .rp-view, .rp-view .panel {background:#fff !important;color:#111 !important;
    border-color:#bbb !important;box-shadow:none !important}
  .rp-cell-sub, .rp-trust, .rp-list-meta, .rp-metrics dt {color:#444 !important}
  .rp-machine {background:#f4f4f4 !important;border-left-color:#666 !important}
  .rp-workspace {display:block !important}
  .rp-head {position:static !important}
  details:not([open]) > :not(summary) {display:block !important}
  /* 최신 크로미움은 접힌 details 안쪽을 ::details-content 로 숨긴다. 위 규칙만으로는 인쇄에 안 나온다. 선택자가 달라 별도 규칙으로 둔다. */
  details:not([open])::details-content {content-visibility:visible !important;display:block !important}
  .rp-plot-scroll {overflow:visible !important}
  .rp-plot {min-width:0 !important}
  .rp-bars span, .rp-strip, .rp-cell {print-color-adjust:exact;-webkit-print-color-adjust:exact}
  .rp-cell[data-state="unknown"], .rp-cell[data-impact="hit"], .rp-age-row[data-old]:not([data-zero])
    {box-shadow:none !important;border-left:3px solid #000 !important}
  .rp-age-row {min-height:0 !important}
  .panel, .rp-strip, .rp-cell, .rp-machine, .rp-chart, .rp-age-row, .rp-ing-row, thead, tr, .rp-fu, .rp-xm, .rp-trend {break-inside:avoid}
  #rp-raw.panel {break-inside:auto}
  .rp-raw .rp-table {overflow:visible !important}
  .rp-raw .rp-table th, .rp-raw .rp-table td {white-space:normal !important}
  h2, h3 {break-after:avoid}
  .rp-main {display:flex;flex-direction:column}
  #rp-now {order:1} #rp-writing {order:2} #rp-followups {order:3} #rp-aging {order:4} #rp-ingest {order:5}
  #rp-detect {order:6} #rp-extra {order:7} #rp-evidence {order:8} #rp-raw {order:9} #rp-footnotes {order:10}
  .rp-end {order:11}
  .rp-print-stamp {display:block !important;position:fixed;top:0;left:0;right:0;
    font-size:9pt;color:#444;border-bottom:1px solid #bbb;padding-bottom:3px}
  .rp-end {display:block !important;margin-top:16px;font-size:10pt;color:#444;text-align:center}
}
.rp-print-stamp, .rp-end {display:none}
</style>"""


def render_daily(daily, kind="weekly"):
    if not daily:
        return '<p class="rp-empty">이 확정본에는 일별 집계가 저장되어 있지 않습니다.</p>'
    series = (("cases", "신규 사건"), ("locks", "계정 자동 잠금"), ("requests", "IP 차단 요청"))
    maximum = max((row[key] for row in daily for key, _ in series), default=0)
    if not maximum:
        return (f'<p class="rp-empty">관측 기간 {len(daily)}일 전체에서 신규 사건·계정 자동 잠금·'
                'IP 차단 요청이 모두 0건입니다.</p>')
    axis_max = max(2, maximum + maximum % 2)
    points = []
    for i, row in enumerate(daily):
        day = date.fromisoformat(row["date"])
        values = [row[key] for key, _ in series]
        label = "월화수목금토일"[i] if len(daily) <= 7 else (f"{day.day}" if day.day in {1, 5, 10, 15, 20, 25, 30} else "")
        query = urlencode({"from": f"{day}T00:00:00+09:00", "to": f"{day + timedelta(days=1)}T00:00:00+09:00"})
        detail = " · ".join(f"{name} {value:,}건" for (_, name), value in zip(series, values))
        bars = "".join(f'<span class="rp-s{j}" style="--value:{100 * value / axis_max:.3f}%"'
                       + (' data-zero' if not value else '') + '></span>' for j, value in enumerate(values))
        points.append(f'<button type="button" class="rp-point" aria-pressed="false" '
                      f'aria-label="{day:%m/%d} KST, {detail}" data-report-detail="{day:%m/%d} KST · {detail}" '
                      f'data-event-query="{html.escape(query, quote=True)}">'
                      f'<span class="rp-bars" aria-hidden="true">{bars}</span>'
                      f'<span class="rp-point-label">{label}</span></button>')
    legend = "".join(f'<span><i class="rp-s{i}" aria-hidden="true"></i>{name}</span>'
                     for i, (_, name) in enumerate(series))
    headers = "".join(f'<th scope="col">{label}</th>' for _, label in series)
    rows = "".join(
        f'<tr><th scope="row">{html.escape(row["date"])}</th>'
        + "".join(f'<td>{row[key]:,}</td>' for key, _ in series) + '</tr>' for row in daily
    )
    return (f'<div class="rp-chart"><div class="rp-chart-key">{legend}</div>'
            '<div class="rp-readout"><span data-report-readout>날짜에 마우스를 올리거나 선택해 수치를 확인하세요.</span>'
            '<a data-report-events hidden>선택한 날짜의 로그 열기 →</a></div>'
            f'<div class="rp-plot-wrap"><div class="rp-scale" aria-hidden="true">'
            f'<span>{axis_max:,}건</span><span>{axis_max // 2:,}</span><span>0</span></div>'
            f'<div class="rp-plot-scroll"><div class="rp-plot" style="--columns:{len(daily)}">'
            f'{"".join(points)}</div></div></div>'
            '<script>(()=>{const chart=document.querySelector(".rp-chart");if(!chart)return;'
            'const readout=chart.querySelector("[data-report-readout]"),link=chart.querySelector("[data-report-events]");'
            'const show=(point)=>{readout.textContent=point.dataset.reportDetail;'
            'link.href="/events?"+point.dataset.eventQuery;link.hidden=false;};'
            'chart.querySelectorAll(".rp-point").forEach(point=>{'
            'point.addEventListener("pointerenter",()=>show(point));point.addEventListener("focus",()=>show(point));'
            'point.addEventListener("click",()=>{chart.querySelector("[aria-pressed=true]")?.setAttribute("aria-pressed","false");'
            'point.setAttribute("aria-pressed","true");show(point);});});})();</script>'
            f'<details><summary>일별 수치 표 보기</summary><div class="rp-table"><table>'
            f'<thead><tr><th scope="col">날짜</th>{headers}</tr></thead><tbody>{rows}</tbody></table></div></details>'
            '</div>')


def _aging_headline(counts):
    """차트 제목은 결론 문장이다. 가장 오래된, 비어 있지 않은 버킷을 말한다."""
    for index in range(len(counts) - 1, -1, -1):
        action, review = counts[index]
        total = action + review
        if not total:
            continue
        label = AGING_BUCKETS[index][0]
        if index == len(counts) - 1:
            who = "조치 대기 사건" if not review else "조사용 사건" if not action else "사건"
            return f"8일 넘은 {who} {_fmt(total)}건이 가장 오래 남아 있습니다"
        if index == 0:
            return f"미결 사건은 모두 2일 안에 생성됐습니다 ({_fmt(total)}건)"
        return f"가장 오래된 미결 사건은 {label} 경과, {_fmt(total)}건입니다"
    return ""


def render_aging(open_counts, generated=""):
    """미결 노후화 수평 누적 막대. (html, 미결 합계, 제목 문장)을 돌려준다.
    값이 0인 버킷도 행을 남긴다. 옛 확정본에는 aging 키가 없어 합계를 None 으로 돌려준다."""
    aging = open_counts.get("aging")
    if not isinstance(aging, list) or len(aging) != len(AGING_BUCKETS):
        return ('<p class="rp-empty">이 확정본에는 경과일별 미결 집계가 저장되어 있지 않아 표시하지 못합니다. '
                '열린 사건은 사건 목록에서 직접 확인하세요. <a href="/incidents">사건 목록 열기 →</a></p>'), None, ""
    counts = [(int(item.get("action") or 0), int(item.get("review") or 0)) for item in aging]
    total = sum(action + review for action, review in counts)
    if not total:
        return ('<p class="rp-empty">이 기간에 생성된 사건 중 열려 있는 사건을 확인했고, 미결은 0건입니다. '
                '<a href="/incidents">사건 목록 열기 →</a></p>'), 0, ""
    peak = max(action + review for action, review in counts)
    rows = []
    for index, ((label, _, _), (action, review)) in enumerate(zip(AGING_BUCKETS, counts)):
        count = action + review
        attrs = (" data-zero" if not count else "") + (" data-old" if index == len(AGING_BUCKETS) - 1 else "")
        segments = "".join(f'<span class="rp-s{series}" style="--w:{100 * value / peak:.3f}%"></span>'
                           for series, value in enumerate((action, review)) if value)
        rows.append(
            f'<li><a class="rp-age-row" href="/incidents"{attrs}>'
            f'<span class="rp-age-label">{label}</span>'
            f'<span class="rp-age-track" aria-hidden="true">{segments}</span>'
            f'<span class="rp-age-val"><b>{_fmt(count)}건</b>'
            f'<small>조치 {_fmt(action)} · 판단 {_fmt(review)}</small></span>'
            '<span class="rp-age-go" aria-hidden="true">→</span></a></li>')
    base = (f"스냅샷 생성 시각({html.escape(generated[:16].replace('T', ' '))} KST)" if generated
            else "스냅샷 생성 시각")
    body = (
        '<div class="rp-aging">'
        '<div class="rp-chart-key"><span><i class="rp-s0" aria-hidden="true"></i>조치 대기</span>'
        '<span><i class="rp-s1" aria-hidden="true"></i>판단 대기</span></div>'
        f'<ul class="rp-age-list">{"".join(rows)}</ul>'
        f'<p class="rp-age-note">막대 길이는 네 줄 중 가장 많은 줄({_fmt(peak)}건)을 100%로 맞춘 같은 눈금입니다. '
        f'경과일은 사건 생성 시각부터 {base}까지입니다. 줄을 누르면 사건 목록으로 갑니다.</p></div>')
    return body, total, _aging_headline(counts)


def _ts_short(value):
    return html.escape(str(value or "")[:16].replace("T", " "))


def _ingest_line(source, bucket_hours, observed_to):
    """출처 한 줄의 결론 문장. 색이 아니라 글자가 1차 구분이다."""
    state, hours = source.get("state"), source.get("max_gap_hours")
    if state == "no_data":
        return ("<b>구분 불가</b>이 기간에 기록이 한 건도 없습니다. 트래픽이 없었던 것인지 수집이 끊긴 것인지 이 데이터로는 구분할 수 없습니다.")
    if state == "gap":
        tail = " 집계 시점까지 이어지고 있습니다." if source.get("gap_ongoing") else ""
        return (f'<b>공백 의심</b>{_fmt(hours)}시간 연속 0건 ({_ts_short(source.get("gap_start_kst"))} ~ '
                f'{_ts_short(source.get("gap_end_kst"))}).{tail}')
    if state == "sparse":
        return (f'<b>활동 적음</b>평가한 {_fmt(source.get("evaluated_hours"))}시간 중 기록이 있던 시간은 '
                f'{_fmt(source.get("active_hours"))}시간입니다. 수집 문제인지 실제 한산함인지 구분할 수 없습니다.')
    return f'<b>이상 없음</b>연속 0건이 {_fmt(source.get("min_gap_hours") or 0)}시간을 넘지 않았습니다.'


def ingest_summary(ingest):
    """신뢰 띠용 한 문구. 저장 안 됨/공백 의심/구분 불가/없음을 모두 글자로 구분한다."""
    sources = (ingest or {}).get("sources") if isinstance(ingest, dict) else None
    if not isinstance(sources, list) or not sources:
        return "수집 공백 집계 저장 안 됨"
    gaps = [s for s in sources if s.get("state") == "gap"]
    unsure = [s for s in sources if s.get("state") in ("no_data", "sparse")]
    if gaps:
        return f'수집 공백 의심 <b>{len(gaps)}개 출처</b> ({html.escape(", ".join(str(s.get("label")) for s in gaps))})'
    if unsure:
        return f'수집 상태 구분 불가 <b>{len(unsure)}개 출처</b>'
    return "수집 공백 의심 없음"


def render_ingest(ingest, event_link):
    """출처별 시간대 띠. 0건은 사선, None(평가 안 함)은 빈 점선 칸이다. None을 공백으로 칠하지 않는다."""
    sources = ingest.get("sources") if isinstance(ingest, dict) else None
    if not isinstance(sources, list) or not sources:
        return ('<p class="rp-empty">이 확정본에는 수집 공백 집계가 저장되어 있지 않아 표시하지 못합니다. '
                f'이 기간의 로그는 <a href="{event_link}">이벤트 목록</a>에서 직접 확인하세요.</p>')
    hours = int(ingest.get("bucket_hours") or 1)
    rows = []
    for source in sources:
        cells = "".join(
            '<span class="rp-g-na"></span>' if value is None
            else '<span class="rp-g-zero"></span>' if not value else '<span class="rp-g-hit"></span>'
            for value in source.get("buckets", []))
        attr = ' data-bad' if source.get("state") == "gap" else ''
        rows.append(
            f'<li class="rp-ing-row"{attr}><span class="rp-ing-name">{html.escape(str(source.get("label")))}'
            f'<small>{_fmt(source.get("total") or 0)}건</small></span>'
            f'<span class="rp-ing-band" aria-hidden="true" style="--n:{max(1, len(source.get("buckets", [])))}">{cells}</span>'
            f'<p class="rp-ing-line">{_ingest_line(source, hours, ingest.get("observed_to_kst"))}</p></li>')
    open_note = (f' 기간이 아직 끝나지 않아 {_ts_short(ingest.get("observed_to_kst"))} KST까지만 평가했습니다.'
                 if ingest.get("period_open") else "")
    return (
        '<div class="rp-ingest">'
        '<div class="rp-chart-key"><span><i class="rp-s0" aria-hidden="true"></i>기록 있음</span>'
        '<span><i class="rp-s1" aria-hidden="true"></i>0건</span>'
        '<span><i class="rp-g-na" aria-hidden="true"></i>평가 안 함</span></div>'
        f'<ul class="rp-ing-list">{"".join(rows)}</ul>'
        f'<p class="rp-age-note">한 칸은 {hours}시간입니다. 0건 구간이 {_fmt(ingest.get("min_gap_hours") or 0)}시간 이상 이어지면 '
        '수집 공백 의심으로 봅니다. 수집 시작 전·미래·덜 찬 칸은 "평가 안 함"이라 공백으로 세지 않습니다.'
        f'{open_note} <a href="{event_link}">이 기간의 이벤트 열기 →</a></p></div>')


def _period_date(key):
    return date.fromisoformat(str(key).removeprefix("monthly:"))


def carry_count(created_key, current_key, kind):
    """만든 기간부터 이 보고서 기간까지 몇 번 이월됐나. 만든 기간 자체는 0."""
    created, current = _period_date(created_key), _period_date(current_key)
    if kind == "monthly":
        return max(0, (current.year - created.year) * 12 + current.month - created.month)
    return max(0, (current - created).days // 7)


def is_overdue(row, today):
    return row["status"] in ("open", "doing") and bool(row["due"]) and row["due"] < str(today)


def validate_followup_new(text, owner, due):
    """등록 입력 검사. 문제가 있으면 사용자에게 보일 사유를 돌려준다."""
    if not text.strip():
        return "후속 조치 내용을 입력하세요."
    if len(text) > 500 or len(owner) > 40:
        return "내용은 500자, 담당은 40자까지 입력할 수 있습니다."
    if due:
        try:
            date.fromisoformat(due)
        except ValueError:
            return "기한 날짜를 확인하세요."
    return None


def validate_followup_change(status, note):
    if status not in FOLLOWUP_LABELS:
        return "상태를 확인하세요."
    if len(note) > 500:
        return "메모는 500자까지 입력할 수 있습니다."
    if status in FOLLOWUP_NEEDS_NOTE and not note.strip():
        return f"{FOLLOWUP_LABELS[status]} 처리에는 {FOLLOWUP_NEEDS_NOTE[status]}를 적어야 합니다."
    return None


def followup_freeze(rows):
    """확정 당시 모습. 상태는 이후 바뀌어도 이 값은 그대로 남는다."""
    return [{"id": r["id"], "text": r["text"], "owner": r["owner"], "due": r["due"], "status": r["status"],
             "period_key": r["period_key"]} for r in rows]


def followup_summary(rows, today):
    """신뢰 띠 문구. rows 는 None(저장 안 됨)과 빈 목록(관측했고 없음)을 구분한다."""
    if rows is None:
        return "후속 조치 장부 저장 안 됨"
    active = [r for r in rows if r["status"] in FOLLOWUP_ACTIVE]
    if not active:
        return "미결 후속 조치 0건"
    overdue = sum(1 for r in active if is_overdue(r, today))
    return f'미결 후속 조치 <b>{_fmt(len(active))}건</b>' + (f' (기한 초과 <b>{_fmt(overdue)}건</b>)' if overdue else "")


def _fu_status(row_state):
    return f'<span class="rp-fu-state" data-s="{row_state}">{html.escape(FOLLOWUP_LABELS.get(row_state, "상태 미확인"))}</span>'


def render_followups(rows, *, frozen, kind, key, week, csrf, editable, finalized, today, legacy_text="", hint=""):
    """후속 조치 장부. 확정본에서는 [확정 당시] → [현재]를 나란히 둔다. 상태 변경 폼만 살아 있다."""
    esc = html.escape
    if finalized and frozen is None:
        body = ('<p class="rp-empty">이 확정본에는 구조화된 후속 조치 장부가 저장되어 있지 않습니다. '
                '확정 당시 자유 서술만 남아 있습니다.</p>')
        if legacy_text:
            body += f'<h3>후속 확인 (이전 형식)</h3><p class="rp-note">{esc(legacy_text)}</p>'
        return body
    frozen_by_id = {item["id"]: item for item in (frozen or [])}
    items = []
    for row in rows:
        carried = carry_count(row["period_key"], key, kind)
        past = frozen_by_id.get(row["id"]) if finalized else None
        flags = []
        if carried >= FOLLOWUP_CARRY_FLAG:
            flags.append(f'<span class="rp-fu-flag">{carried}기간 연속 이월</span>')
        elif carried:
            flags.append(f'<span class="rp-fu-flag">{carried}기간 이월</span>')
        if is_overdue(row, today):
            flags.append('<span class="rp-fu-flag" data-hard>기한 초과</span>')
        meta = " · ".join(filter(None, [
            f'담당 {esc(row["owner"])}' if row["owner"] else "담당 미지정",
            f'기한 {esc(row["due"])}' if row["due"] else "기한 없음",
            f'등록 {esc(row["created_by"])}']))
        if finalized:
            states = (f'<span class="rp-fu-col"><small>확정 당시</small>{_fu_status(past["status"]) if past else "—"}</span>'
                      f'<span class="rp-fu-arrow" aria-hidden="true">→</span>'
                      f'<span class="rp-fu-col"><small>현재</small>{_fu_status(row["status"])}</span>')
        else:
            states = f'<span class="rp-fu-col"><small>현재</small>{_fu_status(row["status"])}</span>'
        note = (f'<p class="rp-fu-note">{esc(FOLLOWUP_NEEDS_NOTE.get(row["status"], "메모"))}: {esc(row["closing_note"])}</p>'
                if row["closing_note"] else "")
        form = ""
        if editable:
            options = "".join(f'<option value="{value}"{" selected" if value == row["status"] else ""}>{label}</option>'
                              for value, label in FOLLOWUP_STATES)
            fid = esc(row["id"], quote=True)
            form = (
                f'<form class="rp-fu-form" method="post" action="/reports/followups">'
                f'<input type="hidden" name="csrf_token" value="{esc(csrf or "", quote=True)}">'
                f'<input type="hidden" name="kind" value="{kind}"><input type="hidden" name="week" value="{week}">'
                f'<input type="hidden" name="followup_id" value="{fid}">'
                f'<label for="fu-s-{fid}">상태</label><select id="fu-s-{fid}" name="status">{options}</select>'
                f'<label for="fu-n-{fid}">메모</label>'
                f'<input id="fu-n-{fid}" name="note" maxlength="500" placeholder="완료는 근거, 미채택은 사유 필수" '
                f'value="{esc(row["closing_note"], quote=True)}">'
                '<button class="btn-ghost">상태 변경</button></form>')
        items.append(f'<li class="rp-fu"><div class="rp-fu-main"><p class="rp-fu-text">{esc(row["text"])}</p>'
                     f'<p class="rp-list-meta">{meta}</p>{"".join(flags)}{note}</div>'
                     f'<div class="rp-fu-states">{states}</div>{form}</li>')
    listing = (f'<ul class="rp-fu-list">{"".join(items)}</ul>' if items
               else '<p class="rp-empty">등록된 후속 조치가 없고, 이월된 미결 항목도 없습니다.</p>')
    add = ""
    if editable and not finalized:
        add = (
            '<form class="rp-fu-add" method="post" action="/reports/followups">'
            f'<input type="hidden" name="csrf_token" value="{esc(csrf or "", quote=True)}">'
            f'<input type="hidden" name="kind" value="{kind}"><input type="hidden" name="week" value="{week}">'
            '<input type="hidden" name="intent" value="add">'
            '<label for="fu-text">후속 조치 내용</label>'
            '<input id="fu-text" name="text" maxlength="500" required>'
            '<label for="fu-owner">담당</label><input id="fu-owner" name="owner" maxlength="40">'
            '<label for="fu-due">기한</label><input id="fu-due" name="due" type="date">'
            '<button class="btn-ghost">후속 조치 등록</button></form>')
    hint_html = f'<p class="rp-list-meta">{esc(hint)}</p>' if hint and editable and not finalized else ""
    rule = ('<p class="rp-age-note">이전 기간에서 끝나지 않은 항목은 사람이 아무것도 하지 않아도 매번 자동으로 이월됩니다. '
            '기한 초과는 저장하지 않고 열림·진행 상태에서만 날짜로 계산합니다. 담당자별 집계는 만들지 않습니다.'
            + (' 확정본은 확정 당시 상태를 고정해 두고, 현재 상태는 여기서 계속 바꿀 수 있습니다.' if finalized else '') + '</p>')
    return f'{hint_html}{listing}{add}{rule}'


def _kv(items):
    rows = "".join(f"<li><span>{html.escape(label)}</span><b>{_fmt(value)}</b></li>" for label, value in items)
    return f'<ul class="rp-kv">{rows}</ul>'


def render_extra(extra, event_link):
    """2순위 지표 세 묶음. 못 센 항목은 0이 아니라 '집계 불가'로 적는다. 옛 확정본에는 키가 없다."""
    if not isinstance(extra, dict):
        return ('<p class="rp-empty">이 확정본에는 추가 지표가 저장되어 있지 않아 표시하지 못합니다. '
                f'원본은 <a href="{event_link}">이벤트 목록</a>에서 확인하세요.</p>')
    cut = ('<p class="rp-empty"><b>집계 불가</b> 조회 상한에 닿아 일부가 잘렸을 수 있어 수치를 적지 않습니다. '
           f'<a href="{event_link}">이벤트 목록</a>에서 직접 확인하세요.</p>')
    blocks = []
    waf = extra.get("waf") or {}
    if waf.get("state") != "ok":
        body = cut
    elif not waf.get("total"):
        body = '<p class="rp-empty">관측했고 WAF 판정은 0건입니다.</p>'
    else:
        body = (_kv([("감지", waf["detected"]), ("차단", waf["blocked"])])
                + '<p class="rp-list-meta">규칙 유형별</p>'
                + _kv(sorted(waf["families"].items(), key=lambda item: -item[1])))
    blocks.append(f'<div class="rp-xm"><h3>WAF 판정 유형별 · {_fmt(waf.get("total", 0))}건</h3>{body}</div>')
    doc = extra.get("doc_read") or {}
    if doc.get("state") != "ok":
        body = cut
    elif not doc.get("total"):
        body = '<p class="rp-empty">관측했고 문서 열람 기록은 0건입니다.</p>'
    else:
        body = _kv([("열람 성공(200)", doc["ok"]), ("로그인 안 됨(401)", doc["unauth"]),
                    ("권한 없음 거부(403)", doc["forbidden"]), ("없는 문서(404)", doc["missing"]),
                    ("그 밖", doc["other"])])
    blocks.append(f'<div class="rp-xm"><h3>ERP 문서 열람 결과 · {_fmt(doc.get("total", 0))}건</h3>{body}</div>')
    recur = extra.get("recur") or {}
    if recur.get("state") != "ok":
        body = cut
    else:
        body = (_kv([("재발 IP", recur["ips"]), ("재발 계정", recur["accounts"])])
                + f'<p class="rp-list-meta">로그인 실패 {_fmt(recur["failed_total"])}건 기준 · 서로 다른 2일 이상 나타난 수</p>')
    blocks.append(f'<div class="rp-xm"><h3>재발</h3>{body}</div>')
    return f'<div class="rp-xgrid">{"".join(blocks)}</div>'


COMPARE_METRICS = ("신규 사건", "IP 차단 요청", "ERP 계정 자동 잠금")


def compare_periods(current, previous, current_final):
    """(행 목록, None) 또는 (None, 비교하지 않는 이유). 조건이 안 맞으면 숫자를 만들지 않는다."""
    if not current_final:
        return None, "확정본끼리만 비교합니다. 이 보고서를 확정하면 지난 확정본과 비교할 수 있습니다."
    if previous is None:
        return None, "직전 기간의 확정본이 없어 비교하지 않습니다."
    for name, snap in (("이번", current), ("지난", previous)):
        ingest = snap.get("ingest")
        if not isinstance(ingest, dict) or not ingest.get("sources"):
            return None, f"{name} 기간 확정본에 수집 공백 집계가 저장되어 있지 않아 비교하지 않습니다."
        bad = [str(src.get("label")) for src in ingest["sources"] if src.get("state") == "gap"]
        if bad:
            return None, f"{name} 기간에 수집 공백 의심({', '.join(bad)})이 있어 건수가 사실과 다를 수 있어 비교하지 않습니다."
    rows = []
    for label in COMPARE_METRICS:
        now_value, before = current.get("metrics", {}).get(label), previous.get("metrics", {}).get(label)
        if now_value is None or before is None:
            continue
        rows.append((label, before, now_value))
    return rows, None


def render_compare(rows, reason, kind):
    if reason:
        return f'<p class="rp-empty"><b>비교하지 않음</b> — {html.escape(reason)}</p>'
    if not rows:
        return '<p class="rp-empty">비교할 공통 지표가 없습니다.</p>'

    def change(before, now_value):
        diff = now_value - before
        return "변화 없음" if not diff else f"{'+' if diff > 0 else '−'}{_fmt(abs(diff))}"
    body = "".join(f'<tr><th scope="row">{html.escape(label)}</th><td>{_fmt(before)}</td><td>{_fmt(now_value)}</td>'
                   f'<td><b>{change(before, now_value)}</b></td></tr>' for label, before, now_value in rows)
    note = " 월마다 일수가 달라 같은 길이의 기간 비교가 아닙니다." if kind == "monthly" else ""
    return ('<div class="rp-table"><table><thead><tr><th scope="col">지표</th><th scope="col">지난 기간</th>'
            f'<th scope="col">이번 기간</th><th scope="col">변화</th></tr></thead><tbody>{body}</tbody></table></div>'
            f'<p class="rp-list-meta">양쪽 모두 확정본이고 수집 공백 의심이 없는 경우의 비교입니다.{note}</p>')


def render_trend(points):
    """신규 사건 추이 스파크라인. 확정본이 3개 미만이면 그리지 않고 이유를 적는다. 숫자는 글자로도 항상 적는다."""
    if len(points) < 3:
        return f'<p class="rp-empty">추이 · 확정본이 3개 이상 쌓이면 표시합니다 (현재 {len(points)}개).</p>'
    values = [value for _, value in points]
    top = max(values) or 1
    width, height, pad = 240, 40, 4
    step = (width - 2 * pad) / (len(values) - 1)
    coords = [(pad + i * step, height - pad - (height - 2 * pad) * v / top) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5"/>' for x, y in coords)
    labels = " · ".join(f"{html.escape(str(key).removeprefix('monthly:'))} {_fmt(value)}건" for key, value in points)
    return ('<div class="rp-trend"><h3>신규 사건 추이 (확정본 기준)</h3>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" aria-hidden="true" '
            f'fill="currentColor" stroke="currentColor"><polyline points="{line}" fill="none" stroke-width="1.5"/>{dots}</svg>'
            f'<p class="rp-list-meta">{labels}</p></div>')


def _kst_text(value):
    """UTC 문자열을 KST 문자열로 바꾼다. 읽지 못하면 원문을 그대로 보인다."""
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S")


def _raw_value(row, key, formatter=None):
    """키 자체가 없으면 저장되지 않은 것이고, 값이 비었으면 원래 없는 것이다. 둘을 구분해 적는다."""
    if key not in row:
        return '<span class="rp-na">저장 안 됨</span>'
    value = row[key]
    if value in ("", None):
        return '<span class="rp-na">없음</span>'
    return html.escape(formatter(value) if formatter else str(value))


def _raw_table(headers, rows):
    head = "".join(f'<th scope="col">{label}</th>' for label in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="rp-table"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_raw(snapshot):
    """감사용 전체 근거. 스냅샷에 저장된 값만 보이고, 저장되지 않은 값은 없다고 적는다."""
    esc = html.escape
    cases = snapshot.get("cases", [])

    def link(cid):
        return f'<a href="/incidents/{quote(cid, safe="")}">{esc(cid)}</a>'

    case_rows = [[link(case["id"]), _raw_value(case, "severity"), _raw_value(case, "target_ip"),
                  _raw_value(case, "username"), _raw_value(case, "created_at_utc", _kst_text),
                  _raw_value(case, "status")] for case in cases]
    cases_html = (_raw_table(("사건 ID", "심각도", "대상 IP", "계정", "생성 시각 (KST)", "상태"), case_rows)
                  if case_rows else '<p class="rp-empty">이 기간에 신규 사건이나 관련 조치가 있는 사건이 없습니다.</p>')
    if "approvals" in snapshot:
        approvals = snapshot["approvals"]
        approval_rows = [[_raw_value(item, "approval_id"), link(item["incident_id"]),
                          esc(ACTION_LABELS.get(item.get("status"), "상태 미확인")), _raw_value(item, "target_ip"),
                          _raw_value(item, "approved_at_utc", _kst_text)] for item in approvals]
        approvals_html = (_raw_table(("승인 ID", "사건 ID", "상태", "대상 IP", "승인 시각 (KST)"), approval_rows)
                          if approval_rows else
                          '<p class="rp-empty">이 기간에 IP 차단 승인 기록을 확인했고, 0건입니다.</p>')
        approval_count = len(approvals)
    else:
        # 옛 확정본: 승인 ID와 승인 시각은 저장되지 않았다. 사건별 상태 문자열로 할 수 있는 만큼만 보인다.
        legacy = [[link(case["id"]), esc(ACTION_LABELS.get(status, "상태 미확인")), _raw_value(case, "target_ip")]
                  for case in cases for status in case.get("ip", [])]
        approval_count = len(legacy)
        approvals_html = (
            '<p class="rp-empty">이 확정본에는 승인 ID와 승인 시각이 저장되어 있지 않습니다. '
            '사건별 상태만 보이며, 대상 IP는 승인 기록이 아니라 사건의 대상 IP입니다. '
            '승인 ID는 사건 상세의 승인 기록에서 확인하세요.</p>'
            + (_raw_table(("사건 ID", "상태", "사건 대상 IP"), legacy) if legacy else ""))
    return (
        '<details><summary>'
        f'감사용 전체 근거 열기 — 사건 {_fmt(len(cases))}건 · 차단 승인 {_fmt(approval_count)}건</summary>'
        f'<div class="rp-sub"><h3>사건 전체 목록</h3>{cases_html}</div>'
        f'<div class="rp-sub"><h3>기간 내 차단 승인 기록</h3>{approvals_html}</div>'
        '<p class="rp-list-meta">일별 수치는 위 추이 차트의 표에 있어 여기서는 반복하지 않습니다. '
        '인쇄하면 이 묶음이 펼쳐진 채 나옵니다.</p></details>')


def _cell(label, href, value_html, sub, link_text, *, state="ok", impact=None, footnote=0):
    esc = html.escape
    mark = f'<sup class="rp-fn">{footnote}</sup>' if footnote else ""
    attrs = f' data-state="{state}"' + (f' data-impact="{impact}"' if impact else "")
    return (f'<a class="rp-cell" href="{href}"{attrs}>'
            f'<span class="rp-cell-label">{esc(label)}{mark}</span>'
            f'{value_html}<span class="rp-cell-sub">{esc(sub)}</span>'
            f'<span class="rp-cell-link">{esc(link_text)} →</span></a>')


def _count_value(count):
    return f'<span class="rp-cell-val">{_fmt(count)}<small>건</small></span>'


def _soft_value(text):
    return f'<span class="rp-cell-val rp-soft">{html.escape(text)}</span>'


def report_body(week, report, snapshot, history, csrf, editable, message="", *, kind="weekly",
                followups=None, today=None, previous=None, trend=None):
    esc = html.escape
    today = today or datetime.now(KST).date()
    key = report_key(week, kind)
    notes = report.get("notes", {}) if report else {}
    finalized = bool(report and report["finalized"])
    status = "확정본" if finalized else "작성 중" if report else "새 보고서"
    chip_class = "is-final" if finalized else "is-draft" if report else ""
    title = "월간" if kind == "monthly" else "주간"
    last_day = period_end(week, kind) - timedelta(days=1)
    span = f"{week} ~ {last_day} (KST)"
    metrics = snapshot.get("metrics", {})
    open_counts = snapshot.get("open", {})
    unsettled = snapshot.get("unsettled", {})
    effect = snapshot.get("effect", {"state": "unknown", "reason": "이 확정본에는 차단 효과 집계가 저장되어 있지 않습니다."})
    unsettled_total = sum(unsettled.values())
    event_range = f"/events?from={week}T00%3A00%3A00%2B09%3A00&amp;to={period_end(week, kind)}T00%3A00%3A00%2B09%3A00"

    # --- S0 Band B : 1등급 지표. 후속 조치 추적은 아직 없어 칸을 만들지 않는다. ---
    oldest = open_counts.get("oldest_days")
    aging = f"가장 오래된 건 {oldest}일 경과" if oldest else "경과일 집계 없음"
    cells = [
        _cell("조치 대기", "/incidents", _count_value(open_counts.get("action", 0)),
              f"IP 차단 승인 경로가 있는 사건 · {aging}", "사건 목록 열기"),
        _cell("판단 대기", "/incidents", _count_value(open_counts.get("review", 0)),
              "조사용 경보만 붙어 종결 경로가 없는 사건", "사건 목록 열기"),
    ]
    if effect["state"] == "ok":
        success = effect["success"]
        cells.append(_cell(
            "차단 시간 중 로그인 성공", event_range, _count_value(success),
            "관측했고 발생하지 않음" if not success else "차단이 유효한 시간에 같은 IP에서 로그인이 성공했습니다",
            "게이트웨이 기록 열기", impact="hit" if success else "0"))
    elif effect["state"] == "none":
        cells.append(_cell("차단 시간 중 로그인 성공", event_range, _soft_value("산출 대상 없음"),
                           effect["reason"], "게이트웨이 기록 열기", state="none"))
    else:
        cells.append(_cell("차단 시간 중 로그인 성공", event_range, _soft_value("집계 불가"),
                           effect["reason"], "게이트웨이 기록 열기", state="unknown"))
    alert_row = ""
    if unsettled_total:
        detail = " · ".join(f"{ACTION_LABELS[key]} {_fmt(value)}" for key, value in unsettled.items() if value)
        alert_row = (f'<a class="rp-alert" href="/incidents">'
                     f'<span class="rp-alert-head">차단 요청 미확정<b>{_fmt(unsettled_total)}건</b></span>'
                     f'<span class="rp-alert-sub">{esc(detail)} · 한 건이라도 있으면 차단했다고 보고할 수 없습니다. '
                     '사건의 승인 기록에서 게이트웨이 적용 상태를 확인하세요. →</span></a>')

    frozen_followups = snapshot.get("followups")  # 확정 당시 목록. 옛 확정본에는 키가 없다.
    # --- S0 Band C : 신뢰 띠. "없음"을 적극적으로 쓴다. 침묵은 확인 안 함으로 읽힌다. ---
    unknown_count = 1 if effect["state"] == "unknown" else 0
    generated = snapshot.get("generated_at", "")
    trust = [
        f'집계 불가 <b>{unknown_count}개</b>' if unknown_count else "집계 불가 없음",
        f'미확정 차단 <b>{_fmt(unsettled_total)}건</b>' if unsettled_total else "미확정 차단 0건",
        f'재생·합성 근거 경보 <b>{_fmt(snapshot["replay_alerts"])}건</b>' if snapshot.get("replay_alerts")
        else "재생·합성 근거 경보 0건",
        ingest_summary(snapshot.get("ingest")),
        followup_summary(frozen_followups if finalized else followups, today),
    ]
    if generated:
        trust.append(f'스냅샷 {esc(generated[:16].replace("T", " "))} KST')
    verdict_text = notes.get("summary", "").strip()
    if verdict_text:
        verdict = f'<p class="rp-verdict">{esc(verdict_text)}</p>'
    else:
        verdict = ('<p class="rp-verdict is-missing">핵심 판단이 아직 작성되지 않았습니다. '
                   f'아래 집계 기준으로는 조치 대기 {_fmt(open_counts.get("action", 0))}건, '
                   f'판단 대기 {_fmt(open_counts.get("review", 0))}건입니다.</p>')

    # --- S1 탐지 내용 : 2등급 지표. IP 차단 상태값은 한 칸으로 합친다. ---
    requests = metrics.get("IP 차단 요청", 0)
    blocked = metrics.get("차단으로 막은 접속 시도")
    if effect["state"] == "ok":
        blocked_html = f'{_fmt(effect["attempts"])}<small>건</small>'
    elif effect["state"] == "none":
        blocked_html = '<span class="rp-soft">산출 대상 없음</span>'
    elif blocked is not None:
        blocked_html = f'{_fmt(blocked)}<small>건</small>'
    else:
        blocked_html = '<span class="rp-soft">집계 불가</span>'
    detect_rows = [
        ("신규 사건", f'{_fmt(metrics.get("신규 사건", 0))}<small>건</small>'),
        ("움직인 사건", f'{_fmt(len(snapshot.get("cases", [])))}<small>건</small>'),
        ("ERP 계정 자동 잠금", f'{_fmt(metrics.get("ERP 계정 자동 잠금", 0))}<small>건</small>'),
        ("IP 차단 요청", f'{_fmt(requests)}<small>건</small>'),
        ("IP 차단 적용 비율", f'<span class="rp-soft">{esc(ratio_text(metrics.get("IP 차단 적용", 0), requests))}</span>'),
        ("차단으로 막은 접속 시도", blocked_html),
    ]
    detect_html = "".join(f'<div><dt>{esc(label)}</dt><dd>{value}</dd></div>'
                          for label, value in detect_rows)

    # --- S2 사건과 대응 근거 ---
    cases_html = "".join(
        f'<li><a href="/incidents/{quote(case["id"], safe="")}">{esc(case["title"])}</a>'
        f'<p class="rp-list-meta">{"신규 사건" if case["new"] else "이전 사건의 후속 조치"}'
        + (f' · 계정 자동 잠금 {_fmt(case["locks"])}건' if case["locks"] else "")
        + (" · IP 차단 " + ", ".join(ACTION_LABELS.get(s, "상태 미확인") for s in case["ip"]) if case["ip"] else "")
        + (f' · 대상 {esc(case["target_ip"])}' if case.get("target_ip") else "")
        + "</p></li>" for case in snapshot.get("cases", []))
    source_rows = "".join(f'<div><dt>{esc(label)}</dt><dd>{_fmt(count)}<small>건</small></dd></div>'
                          for label, count in snapshot.get("sources", {}).items())
    sources = (f'<dl class="rp-metrics">{source_rows}</dl>' if source_rows
               else '<p class="rp-empty">이 보고서에 저장된 로그 출처 집계가 없습니다.</p>')

    # --- S3 판단과 서술 : 기계 문장과 사람 입력을 영역으로 가른다. ---
    facts = "".join(f"<p>{esc(line)}</p>" for line in machine_facts(snapshot))
    machine_block = (
        '<div class="rp-machine"><p class="rp-machine-note">'
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        'aria-hidden="true"><path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/></svg>'
        '기간 집계 사실 — 재집계할 때마다 자동으로 다시 만들어집니다. 편집할 수 없습니다.</p>'
        f'{facts}</div>')
    writing = machine_block
    if editable and not finalized:
        parts = []
        for name, label in FIELDS:
            if name == "summary":
                hint = ("이 보고서의 결론 1~3문장. 이 글이 보고서 첫 줄로 올라갑니다. "
                        "비우면 확정할 수 없습니다.")
            elif name == "assessment":
                hint = "위 집계를 왜 이렇게 봤는지, 침해 가능성과 오탐 판단을 쓰세요."
            elif name == "followup":
                hint = "확인할 일과 담당·목표일을 쓰세요."
            else:
                hint = ""
            required = '<span class="rp-required" aria-hidden="true">*</span>' if name == "summary" else ""
            parts.append(
                f'<p><label for="report-{name}">{esc(label)}{required}</label>'
                f'<textarea id="report-{name}" name="{name}" rows="4" maxlength="2000" '
                f'placeholder="{esc(hint, quote=True)}"{" required" if name == "summary" else ""}>'
                f'{esc(notes.get(name, ""))}</textarea></p>')
        writing += (
            f'<form class="rp-prose" method="post" action="/reports">'
            f'<input type="hidden" name="week" value="{week}">'
            f'<input type="hidden" name="kind" value="{kind}">'
            f'<input type="hidden" name="csrf_token" value="{esc(csrf or "", quote=True)}">'
            + "".join(parts)
            + '<div class="rp-actions">'
            '<button class="btn-ghost" name="intent" value="collect">수치 새로 집계</button>'
            '<button class="btn-ghost" name="intent" value="draft">초안 저장</button></div>'
            '<details><summary>확정 전 미리보기와 확정</summary>'
            '<p>확정하면 집계와 서술이 영구히 고정됩니다. <b>확정은 취소할 수 없습니다.</b> '
            '수정이 필요하면 확정 전에 고쳐 주세요.</p>'
            f'<p class="rp-list-meta">{span} · 관련 사건 {_fmt(len(snapshot.get("cases", [])))}건 · '
            f'집계 불가 {unknown_count}개 · 미확정 차단 {_fmt(unsettled_total)}건 — '
            '이 항목들은 확정을 막지 않고 확정본에 그대로 기록됩니다.</p>'
            '<dl class="rp-defs">'
            + "".join(f'<dt><b>{esc(label)}</b></dt><dd data-report-preview="{name}">—</dd>'
                      for name, label in FIELDS)
            + '</dl><div class="rp-actions">'
            '<button class="btn-ghost" name="intent" value="final">보고서 확정</button></div>'
            '</details></form>'
            '<script>(()=>{const review=document.querySelector(".rp-prose details");'
            'if(!review)return;const form=review.closest("form");'
            'const sync=()=>{if(!review.open)return;review.querySelectorAll("[data-report-preview]").forEach(el=>{'
            'el.textContent=form.elements[el.dataset.reportPreview].value.trim()||"작성된 내용이 없습니다.";});};'
            'review.addEventListener("toggle",sync);form.addEventListener("input",sync);})();</script>')
    else:
        if not editable and not finalized:
            writing += '<p class="rp-empty">조회 전용 보고서입니다.</p>'
        for name, label in FIELDS:
            writing += (f'<h3>{esc(label)}</h3>'
                        f'<p class="rp-note">{esc(notes.get(name, "")) or "작성된 내용이 없습니다."}</p>')

    # --- S4 각주와 집계 기준 ---
    footnotes = "".join(f'<li><b>{esc(label)}</b> · {esc(text)}</li>' for label, text in DEFINITIONS)
    stamp_bits = [f"{title} 관제 보고서", span, status]
    if report:
        stamp_bits += [esc(report["author"]), f'저장 {esc(report["saved_at"][:16].replace("T", " "))} KST']
    stamp = " · ".join(stamp_bits)

    # --- 헤더와 레일 ---
    this_period = report_period("", kind)
    prev_period = (this_period - timedelta(days=1)).replace(day=1) if kind == "monthly" else this_period - timedelta(days=7)
    quick = "".join(
        f'<a class="range-chip{" active" if value == week else ""}" href="/reports?kind={kind}&amp;week={value}">{label}</a>'
        for value, label in ((this_period, "이번 달" if kind == "monthly" else "이번 주"),
                             (prev_period, "지난달" if kind == "monthly" else "지난주")))
    kinds = "".join(
        f'<a class="range-chip" {"aria-current=true" if value == kind else ""} '
        f'href="/reports?kind={value}&amp;week={week}">{label}</a>'
        for value, label in (("weekly", "주간"), ("monthly", "월간")))
    aging_html, aging_total, aging_headline = render_aging(open_counts, generated)
    compare_rows, compare_reason = compare_periods(
        snapshot, previous["snapshot"] if previous else None, finalized)
    compare_html = render_compare(compare_rows, compare_reason, kind)
    fu_rows = followups if followups is not None else []
    fu_html = render_followups(
        fu_rows, frozen=frozen_followups if finalized else None, kind=kind, key=key, week=week, csrf=csrf,
        editable=editable, finalized=finalized, today=today, legacy_text=notes.get("followup", ""),
        hint=("확인 후보: " + calculated_draft(snapshot)["followup"]) if not finalized else "")
    open_fu = [r for r in (frozen_followups if finalized else followups) or [] if r["status"] in FOLLOWUP_ACTIVE]
    followup_toc = f"{_fmt(len(open_fu))}건 미결" if open_fu else ""
    sections = (("rp-now", "지금 상태", ""),
                ("rp-aging", "미결 사건 경과일", "" if aging_total is None else f"{_fmt(aging_total)}건"),
                ("rp-ingest", "로그 수집 상태", ""),
                ("rp-detect", "탐지 내용", ""),
                ("rp-extra", "추가 지표", ""),
                ("rp-followups", "후속 조치 장부", followup_toc),
                ("rp-evidence", "사건과 대응 근거", f'{_fmt(len(snapshot.get("cases", [])))}건'),
                ("rp-raw", "감사용 전체 근거", ""),
                ("rp-writing", "판단과 서술", ""), ("rp-footnotes", "각주와 집계 기준", ""))
    toc = "".join(f'<a href="#{sid}">{esc(label)}<span>{extra}</span></a>' for sid, label, extra in sections)
    jump = "".join(f'<a class="range-chip" href="#{sid}">{esc(label)}</a>' for sid, label, _ in sections)
    history_sections = []
    for label, is_final in (("작성 중", False), ("확정본", True)):
        links = []
        for key, flag, author in history:
            month = key.startswith("monthly:")
            if bool(flag) != is_final or month != (kind == "monthly"):
                continue
            day = key.removeprefix("monthly:")
            links.append(f'<li><a href="/reports?kind={kind}&amp;week={quote(day)}">{esc(day)}</a>'
                         f'<p class="rp-list-meta">{esc(author)}</p></li>')
        history_sections.append(f'<h3>{label}</h3><ul class="rp-list">'
                                + ("".join(links) or "<li>저장된 보고서가 없습니다.</li>") + "</ul>")
    print_button = ('<button type="button" class="btn-ghost rp-print" onclick="window.print()">인쇄 / PDF 저장</button>'
                    '<p class="rp-list-meta rp-print">페이지 번호는 인쇄 설정의 \'머리말 및 꼬리말\'을 켜면 나옵니다.</p>'
                    if finalized else "")
    return f"""
    {REPORT_STYLE}
    <div class="rp-view">
    <p class="rp-print-stamp">{stamp}</p>
    <header class="panel rp-head">
      <nav class="chart-periods" aria-label="보고서 유형">{kinds}</nav>
      <div class="rp-head-main">
        <div><h1>{title} 관제 보고서</h1>
        <p class="rp-head-meta"><span class="rp-chip {chip_class}">{status}</span><span>{span}</span>
        {f'<span>{esc(report["author"])} · {esc(report["saved_at"][:16].replace("T", " "))} KST</span>' if report else ''}</p></div>
        <form class="rp-period" method="get" action="/reports">
          {quick}
          <input type="hidden" name="kind" value="{kind}">
          <label for="report-week">{'조회 월' if kind == 'monthly' else '기준 날짜'}</label>
          <input type="{'month' if kind == 'monthly' else 'date'}" id="report-week" name="week"
                 value="{str(week)[:7] if kind == 'monthly' else week}" required>
          <button class="btn-ghost">기간 열기</button>
        </form>
        {print_button}
      </div>
      <nav class="rp-jump" aria-label="보고서 내 이동">{jump}</nav>
      {f'<p role="status">{esc(message)}</p>' if message else ''}
    </header>
    <div class="rp-workspace">
    <div class="rp-main">
      <section class="panel" id="rp-now">
        <h2>지금 상태</h2>
        {verdict}
        <div class="rp-strip">{"".join(cells)}</div>
        {alert_row}
        <p class="rp-trust">{"".join(f"<span>{piece}</span>" for piece in trust)}</p>
      </section>
      <section class="panel" id="rp-aging">
        <h2>미결 사건 경과일</h2>
        {f'<h3>경과일별 미결 사건 — {esc(aging_headline)}</h3>' if aging_headline else ''}
        {aging_html}
      </section>
      <section class="panel" id="rp-ingest">
        <h2>로그 수집 상태</h2>
        {render_ingest(snapshot.get("ingest"), event_range)}
      </section>
      <section class="panel" id="rp-detect">
        <h2>탐지 내용</h2>
        <dl class="rp-metrics">{detect_html}</dl>
        <div class="rp-sub"><h3>{'월간 구간별' if kind == 'monthly' else '일별'} 관제 추이</h3>
        {render_daily(snapshot.get("daily"), kind)}</div>
      </section>
      <section class="panel" id="rp-extra">
        <h2>추가 지표</h2>
        {render_extra(snapshot.get("extra"), event_range)}
        <div class="rp-sub"><h3>지난 기간 대비</h3>{compare_html}</div>
        <div class="rp-sub">{render_trend(trend or [])}</div>
      </section>
      <section class="panel" id="rp-followups">
        <h2>후속 조치 장부</h2>
        {fu_html}
      </section>
      <section class="panel" id="rp-evidence">
        <h2>사건과 대응 근거</h2>
        <ul class="rp-list">{cases_html or "<li>선택한 기간에 신규 사건이나 관련 조치 기록이 없습니다.</li>"}</ul>
        <div class="rp-sub"><h3>로그 출처별 이벤트</h3>{sources}
        <p><a href="{event_range}">이 기간의 이벤트 열기 →</a></p></div>
      </section>
      <section class="panel rp-raw" id="rp-raw">
        <h2>감사용 전체 근거</h2>
        {render_raw(snapshot)}
      </section>
      <section class="panel" id="rp-writing">
        <h2>판단과 서술</h2>
        {writing}
      </section>
      <section class="panel" id="rp-footnotes">
        <h2>각주와 집계 기준</h2>
        <ul class="rp-defs">{footnotes}</ul>
        <p class="rp-list-meta">모든 시각은 KST입니다. 수집 공백과 후속 조치 추적은 이 보고서에서 아직 집계하지 않습니다.</p>
      </section>
      <p class="rp-end">— 보고서 끝 —</p>
    </div>
    <aside class="rp-rail">
      <section class="panel rp-toc-panel"><h2>보고서 목차</h2>
      <nav class="rp-toc" aria-label="보고서 내 이동">{toc}</nav></section>
      <section class="panel" id="rp-archive"><h2>지난 보고서</h2>{"".join(history_sections)}</section>
    </aside></div>
    </div>
    """
