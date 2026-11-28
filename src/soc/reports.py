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
FIELDS = (("summary", "핵심 판단"), ("assessment", "판단 근거"), ("opinion", "필요한 결정·요청"))
HUMAN_ONLY_FIELDS = frozenset({"summary", "assessment", "opinion"})

# 지표 정의는 한 곳에서만 쓴다. title 속성(호버 전용)으로는 내보내지 않고 각주 절에 싣는다.
DEFINITIONS = (
    ("조치 대기", "이 기간에 생성되어 아직 열려 있는 사건 중 IP 차단 승인 경로가 있는 사건입니다."),
    ("판단 대기", "이 기간에 생성되어 아직 열려 있는 사건 중 조사용 경보만 붙어 종결 경로가 없는 사건입니다."),
    ("차단 시간 중 로그인 성공", "차단이 유효한 시간에 그 IP에서 ERP 로그인이 성공한 기록 수입니다. 조회한 로그 안에서 센 값이며, 차단 우회를 확정하는 수치는 아닙니다."),
    ("차단 요청 미확정", "승인했으나 게이트웨이 적용이 확인되지 않은 건입니다. 한 건이라도 있으면 차단했다고 보고할 수 없습니다."),
    ("ERP 계정 자동 잠금", "기간 안에 자동 잠금 탐지 창이 끝난 기록입니다. 현재 잠금 상태와 구분합니다."),
    ("IP 차단 적용", "요청 중 적용이 확인된 건입니다. 이후 해제·만료된 건도 포함합니다."),
    ("재발", "같은 IP 또는 같은 계정의 ERP 로그인 실패가 이 기간 안에서 서로 다른 2일 이상에 나타난 수입니다(KST 날짜). 사람이나 공격자 수가 아닙니다."),
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
# 사건 목록과 같은 표기. 영어 원문(high 등)을 화면에 그대로 내지 않는다.
SEVERITY_LABELS = {"critical": "긴급", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보"}


def severity_label(value):
    return SEVERITY_LABELS.get(str(value or "").lower(), "미지정")


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
OPEN_CASES_STORED = 10  # 그룹별로 오래된 순 몇 건까지 스냅샷에 남기나
QUEUE_SHOWN = 5          # 화면에 보이는 건수
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
    open_items = {"action": [], "review": []}
    now = now or datetime.now(KST)
    excluded_incidents = 0
    for inc in incidents:
        # 실제 운영(live) 근거가 하나도 없는 사건(재생·합성 데이터뿐)은 보고서 수치에 넣지 않는다. 몇 건 뺐는지는 남긴다.
        modes = [m for alert in inc.alerts for m in (getattr(alert, "ingest_modes", ()) or ())]
        if modes and "live" not in modes:
            excluded_incidents += 1
            continue
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
                    group = "action" if getattr(inc, "block_rule_eligible", False) else "review"
                    aging[aging_index(days)][group] += 1
                    open_items[group].append({
                        "id": inc.incident_id, "title": inc.title, "severity": getattr(inc, "severity", ""),
                        "target_ip": getattr(inc, "target_ip", ""),
                        "age_hours": max(0, int((now - created).total_seconds() // 3600))})
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
            "open_cases": {group: sorted(items, key=lambda item: (-SEVERITY_RANK.get(str(item.get("severity")).lower(), 0),
                                                                  -item["age_hours"]))[:OPEN_CASES_STORED]
                           for group, items in open_items.items()},
            "excluded": {"incidents": excluded_incidents},
            "unsettled": unsettled, "effect": effect, "replay_alerts": replay_alerts,
            "generated_at": now.isoformat(timespec="seconds"),
            "cases": cases, "daily": daily, "approvals": block_log}


REPORT_STYLE = """<style>
.rp-view {--hatch:repeating-linear-gradient(135deg,rgb(var(--text-rgb)/0.58) 0 3px,rgb(var(--text-rgb)/0.10) 3px 6px);
  display:grid;gap:16px;min-width:0;word-break:keep-all;overflow-wrap:anywhere}
.rp-view section[id],.rp-view header[id] {scroll-margin-top:calc(var(--rp-head-h,96px) + 16px)}
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
.rp-rail {position:sticky;top:calc(var(--rp-head-h,96px) + 16px);max-height:calc(100vh - var(--rp-head-h,96px) - 32px);overflow-y:auto;align-content:start}
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
  align-items:center;min-height:34px;padding:2px 10px;color:var(--text);text-decoration:none;
  transition:background-color 150ms var(--ease)}
@media (hover:hover) {.rp-age-row:hover {background:var(--raised);text-decoration:none}}
.rp-age-row:focus-visible {outline:2px solid var(--accent);outline-offset:-3px}
.rp-age-label {font-size:13px;color:var(--text)}
.rp-age-track {display:flex;height:10px;overflow:hidden;background:var(--line-soft);border-radius:var(--radius-sm)}
.rp-age-track span {flex:none;width:var(--w);height:100%;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.rp-age-val {display:flex;align-items:baseline;justify-content:flex-end;gap:8px;text-align:right;line-height:1.35}
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
.rp-ing-row {--c:var(--text-3)}
.rp-ing-band {display:flex;align-items:flex-end;gap:1px;height:44px;border-bottom:1px solid var(--line);cursor:crosshair;touch-action:pan-y}
.rp-ing-band span {flex:1 1 0;min-width:1px;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.rp-ing-band .h {background:var(--c);border-radius:1px 1px 0 0}
.rp-ing-band .z {height:2px;background:repeating-linear-gradient(90deg,color-mix(in srgb,var(--c) 70%,transparent) 0 2px,transparent 2px 4px)}
.rp-ing-band .n {height:0;align-self:flex-end;border-bottom:1px dotted var(--text-3);margin-bottom:-1px}
.rp-lg-bar {background:var(--text-2);height:10px;width:6px !important;display:inline-block;margin-right:6px}
.rp-lg-zero {background:repeating-linear-gradient(90deg,var(--text-2) 0 2px,transparent 2px 4px);height:3px !important;vertical-align:middle !important}
i.rp-g-na {display:inline-block;width:10px;height:0 !important;border:0;border-bottom:1px dotted var(--text-3);margin-right:6px;vertical-align:middle !important}
.rp-strip-readout {margin:10px 0 0}
.rp-ing-axis {display:grid;grid-template-columns:repeat(var(--n),minmax(1px,1fr));gap:1px;margin:4px 0 0 108px;font-size:12px;color:var(--text-3)}
.rp-ing-axis span {border-left:1px solid var(--line);padding-left:4px;overflow:hidden;white-space:nowrap}
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
.rp-xgrid {margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));gap:12px;align-items:stretch}
.rp-xm {display:flex;flex-direction:column;padding:12px 14px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface);min-width:0}
.rp-xm h3 {margin:0;font-size:13px;font-weight:600;color:var(--text-2)}
.rp-xm-num {margin:4px 0 8px;font-size:13px;color:var(--text-2)}
.rp-xm-num b {font-size:26px;font-weight:600;letter-spacing:-0.02em;color:var(--text);margin-right:2px;font-variant-numeric:tabular-nums}
.rp-xm-num b.rp-xm-na {font-size:18px}
.rp-xm-rows {flex:1;border-top:1px solid var(--line-soft)}
.rp-xm-note {margin:8px 0 0;font-size:12px;line-height:1.5;color:var(--text-3)}
.rp-xm-rows .rp-xm-note {margin:10px 0 0;color:var(--text-2)}
.rp-kv {list-style:none;padding:0;margin:0}
.rp-kv li {display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-top:1px solid var(--line-soft);
  font-size:13px;color:var(--text-2)}
.rp-kv li:first-child {border-top:0}
.rp-kv b {color:var(--text);font-variant-numeric:tabular-nums}
.rp-trend svg {display:block;margin:4px 0;color:var(--text)}
.rp-c0 {color:var(--source-erp)}
.rp-c1 {color:var(--source-caddy)}
.rp-c2 {color:var(--source-gateway)}
.rp-cross b.rp-c0 {border-color:var(--source-erp)}
.rp-cross b.rp-c1 {border-color:var(--source-caddy)}
.rp-cross b.rp-c2 {border-color:var(--source-gateway)}
.rp-tip i {display:inline-block;width:8px;height:8px;margin-right:6px;border-radius:50%;background:currentColor}
.rp-ing-table {width:100%;border-collapse:collapse}
.rp-ing-table th,.rp-ing-table td {padding:8px 10px;font-size:13px;text-align:left;border-bottom:1px solid var(--line-soft);
  font-variant-numeric:tabular-nums;color:var(--text-2)}
.rp-ing-table thead th {font-size:12px;font-weight:600;color:var(--text-3)}
.rp-ing-table tbody th {color:var(--text);font-weight:600}
.rp-ing-table td b {color:var(--text)}
.rp-ing-table tr[data-bad] th {box-shadow:inset 3px 0 0 var(--danger)}
.rp-ing-note {margin:10px 0 0;font-size:13px;line-height:1.6;color:var(--text-2)}
.rp-chart-note {font-size:12px;color:var(--text-3)}
.rp-queue {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:12px}
.rp-q {padding:14px 16px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface);min-width:0}
.rp-q h3 {margin:0;font-size:15px;font-weight:600;color:var(--text)}
.rp-q h4 {margin:12px 0 4px;font-size:12px;font-weight:600;color:var(--text-3)}
.rp-q-num {margin:4px 0 0;font-size:13px;color:var(--text-2)}
.rp-q-num b {font-size:32px;font-weight:600;letter-spacing:-0.03em;color:var(--text);margin-right:2px}
.rp-q-head {margin:0 0 10px;font-size:14px;font-weight:600;color:var(--text)}
.rp-q-verdict {margin:10px 0 6px;font-size:13px;color:var(--text-2)}
.rp-q-verdict b {color:var(--text)}
.rp-q-bar {display:flex;gap:2px;height:6px;border-radius:3px;overflow:hidden}
.rp-q-seg {flex-basis:0;min-width:4px;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.rp-q-seg[data-t="0"],.rp-q-legend i[data-t="0"] {background:rgb(var(--text-rgb)/0.22)}
.rp-q-seg[data-t="1"],.rp-q-legend i[data-t="1"] {background:rgb(var(--text-rgb)/0.42)}
.rp-q-seg[data-t="2"],.rp-q-legend i[data-t="2"] {background:rgb(var(--text-rgb)/0.66)}
.rp-q-seg[data-t="3"],.rp-q-legend i[data-t="3"] {background:rgb(var(--text-rgb)/0.92)}
.rp-q-legend {display:flex;flex-wrap:wrap;gap:2px 14px;list-style:none;padding:0;margin:8px 0 0;font-size:12px;color:var(--text-2)}
.rp-q-legend i {display:inline-block;width:9px;height:9px;margin-right:5px;border-radius:2px}
.rp-q-legend b {color:var(--text);font-variant-numeric:tabular-nums}
.rp-q-legend li[data-zero] {color:var(--text-3)}
.rp-q-legend li[data-zero] b {color:var(--text-3);font-weight:500}
.rp-q-list {list-style:none;padding:0;margin:0}
.rp-q-list li {display:grid;grid-template-columns:minmax(0,1fr) 48px 64px minmax(0,92px);gap:8px;align-items:center;
  padding:5px 0;border-top:1px solid var(--line-soft);font-size:13px;color:var(--text-2)}
.rp-q-list li:first-child {border-top:0}
.rp-q-list a {display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.4}
.rp-q-list b {color:var(--text);text-align:right;font-variant-numeric:tabular-nums}
.rp-q-list .sev::before {display:none}  /* 글자 하나로만 표시. 동그라미는 글자와 같은 정보라 겹쳐 보이지 않게 뺀다 */
.rp-q-list span {overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px}
.rp-appx-head {margin:8px 0 -4px;padding:0 4px}
.rp-appx-head h2 {margin:0;font-size:16px;color:var(--text)}
.rp-appx-head p {margin:2px 0 0;font-size:13px;color:var(--text-3)}
.rp-ai {margin:-6px 0 14px}
.rp-ai-row {display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px}
.rp-view .rp-ai-btn {display:inline-flex;align-items:center;gap:6px;min-height:34px;padding:0 12px;margin:0;font:inherit;font-size:13px;
  color:var(--text);background:var(--surface);border:1px solid var(--line);border-radius:var(--radius-sm);cursor:pointer}
.rp-view .rp-ai-btn:disabled {opacity:.6;cursor:progress}
.rp-view .rp-ai-btn.is-quiet {background:transparent;border-color:transparent;color:var(--text-2)}
@media (hover:hover) {.rp-view .rp-ai-btn:hover:not(:disabled) {background:var(--raised)}}
.rp-view .rp-ai-btn:focus-visible {outline:2px solid var(--accent);outline-offset:2px}
.rp-ai-hint {font-size:12px;color:var(--text-3)}
.rp-ai-pre {margin:8px 0 0;padding:10px 12px;max-height:260px;overflow:auto;font-size:12px;line-height:1.5;color:var(--text-2);
  background:var(--sunken);border:1px solid var(--line-soft);border-radius:var(--radius-sm);white-space:pre-wrap}
.rp-ai-pre[hidden] {display:none}
.rp-ai-note {margin:6px 0 0;min-height:0;font-size:13px;color:var(--text-2)}
.rp-ai-note:empty {display:none}
.rp-ai-card {margin-top:8px;padding:12px 14px;background:var(--sunken);border:1px solid var(--line-soft);border-left:3px solid var(--accent);
  border-radius:0 var(--radius-sm) var(--radius-sm) 0}
.rp-ai-card[hidden] {display:none}
.rp-ai-cap {margin:0 0 6px;font-size:12px;font-weight:600;color:var(--text-2)}
.rp-ai-text {margin:0 0 10px;font-size:14px;line-height:1.7;color:var(--text);white-space:pre-wrap}
.rp-ai-acts {display:flex;flex-wrap:wrap;gap:6px 8px}
.rp-todo-sum {margin:0 0 8px;font-size:13px;color:var(--text-2)}
.rp-todo-sum b {color:var(--text)}
.rp-todo-list {list-style:none;padding:0;margin:0}
.rp-todo-list li {display:grid;grid-template-columns:96px minmax(0,1fr) minmax(0,auto);gap:4px 12px;align-items:baseline;
  padding:8px 0;border-top:1px solid var(--line-soft);font-size:13px;color:var(--text-2)}
.rp-todo-list li:first-child {border-top:0}
.rp-todo-tag {font-weight:600;color:var(--text);font-size:12px}
.rp-todo-text a {color:var(--text)}
.rp-todo-meta {font-size:12px;text-align:right;color:var(--text-3)}
.rp-two {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:0 16px}
.rp-prose {max-width:none}
.rp-prose .rp-actions .rp-list-meta {margin:0}
.rp-toc-group {margin:10px 0 2px;font-size:12px;font-weight:600;color:var(--text-3)}
.rp-toc-group:first-child {margin-top:0}
.rp-head-tools {display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px}
.rp-scope {display:inline-flex;align-items:center;gap:4px 14px;flex-wrap:wrap;font-size:12px;color:var(--text-2)}
.rp-scope > span {color:var(--text-3)}
.rp-scope label {display:inline-flex;align-items:center;gap:4px;min-height:28px}
.rp-tools-note {flex-basis:100%;margin:0}
.rp-save {margin:0}
.rp-view .rp-tools {display:inline-flex;border:1px solid var(--line);border-radius:var(--radius-sm);overflow:hidden;background:var(--surface)}
.rp-view .rp-tool {display:inline-flex;align-items:center;gap:6px;min-height:36px;padding:0 14px;margin:0;border:0;border-left:1px solid var(--line);
  border-radius:0;background:transparent;color:var(--text);font:inherit;font-size:13px;cursor:pointer;text-decoration:none;white-space:nowrap}
.rp-view .rp-tool:first-child {border-left:0}
@media (hover:hover) {.rp-view .rp-tool:hover {background:var(--raised);text-decoration:none}}
.rp-view .rp-tool:focus-visible {outline:2px solid var(--accent);outline-offset:-2px}
.rp-fold .rp-defs li {font-size:12px;line-height:1.5;padding:6px 0}
.rp-fold > summary {font-size:12px}
.rp-fold {margin-top:6px}
.rp-fold > summary {font-weight:600;color:var(--text);min-height:36px}
.rp-stats {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,160px),1fr));gap:10px;margin:0 0 14px}
.rp-stat {display:grid;gap:2px;padding:10px 12px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-2)}
.rp-stat-val {font-size:22px;font-weight:600;letter-spacing:-0.02em;color:var(--text);font-variant-numeric:tabular-nums}
.rp-stat-val small {font-size:13px;font-weight:500;color:var(--text-2);margin-left:2px}
.rp-stat svg {width:100%;height:28px;margin-top:4px;overflow:visible}
.rp-chart-key svg {margin-right:6px;vertical-align:middle}
.rp-plot2 {display:grid;grid-template-columns:36px minmax(0,1fr);gap:0 8px}
.rp-plot2:focus-visible {outline:2px solid var(--accent);outline-offset:2px}
.rp-yscale {display:flex;flex-direction:column;justify-content:space-between;height:180px;text-align:right;font-size:12px;color:var(--text-3)}
.rp-canvas {position:relative;height:180px;color:var(--text);cursor:crosshair;touch-action:pan-y}
.rp-canvas svg {display:block;width:100%;height:100%}
.rp-cross {position:absolute;inset:0;pointer-events:none}
.rp-cross[hidden],.rp-tip[hidden] {display:none}
.rp-cross i {position:absolute;top:0;bottom:0;left:inherit;border-left:1px dashed var(--text-3)}
.rp-cross b {position:absolute;left:inherit;width:9px;height:9px;margin:-4.5px 0 0 -4.5px;border-radius:50%;background:var(--surface);border:2px solid var(--text)}
.rp-tip {position:absolute;top:6px;z-index:2;min-width:150px;padding:8px 10px;pointer-events:none;font-size:12px;line-height:1.6;
  color:var(--text);background:var(--raised);border:1px solid var(--line);border-radius:var(--radius-sm);box-shadow:var(--shadow)}
.rp-tip[data-side="right"] {transform:translateX(12px)}
.rp-tip[data-side="left"] {transform:translateX(calc(-100% - 12px))}
.rp-tip strong {display:block;font-size:12px;margin-bottom:2px}
.rp-tip span {display:flex;justify-content:space-between;gap:14px}
.rp-tip em {font-style:normal;color:var(--text-2)}
.rp-tip b {font-variant-numeric:tabular-nums}
.rp-xlabels {display:flex;justify-content:space-between;margin:4px 0 0 44px;font-size:12px;color:var(--text-3)}
.rp-xlabels span {min-width:1ch;text-align:center}
.rp-ev-sum {margin:0 0 8px;font-size:13px;color:var(--text-2)}
.rp-ev-sum b {color:var(--text)}
.rp-ev table {width:100%}
.rp-ev th,.rp-ev td {padding:6px 10px;font-size:13px;text-align:left}
.rp-ev th[scope=row] {font-weight:500;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rp-raw summary {min-height:44px;font-weight:600;color:var(--text)}
.rp-raw .rp-table th, .rp-raw .rp-table td {text-align:left;white-space:nowrap}
.rp-raw .rp-table th,.rp-raw .rp-table td {padding:3px 10px;font-size:12px;line-height:1.4}
.rp-raw .rp-table td a {display:inline-block;padding:2px 0}
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
  .rp-view form button, .rp-fu-form, .rp-fu-add, .rp-tip, .rp-cross, .rp-ai {display:none !important}
  /* 원인: 기본 테마가 다크라 --text-2/--text-3 가 밝은 회색이다. 인쇄 배경만 흰색으로 바꾸면 밝은 회색 글자가 흰 종이에 얹힌다.
     그래서 인쇄 때는 .rp-view 안의 전역 토큰 자체를 라이트 값으로 되돌린다(새 토큰 없음). 흑백 인쇄에서도 4.5:1 이상. */
  .rp-view {
    --surface:#fff; --sunken:#f4f4f4; --raised:#fff; --line:#bbb; --line-soft:#d6d6d6;
    --text-rgb:17 17 17; --text:#111; --text-2:#2b2b2b; --text-3:#4a4a4a;
    --ok:#1f5a24; --danger:#8f1d31; --warn:#6b4700; --accent:#222; --on-accent:#fff;
    --source-erp:#1d5aa8; --source-caddy:#6b46b5; --source-gateway:#0f7a55; --source-waf:#96396e;
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
  .panel, .rp-strip, .rp-cell, .rp-machine, .rp-chart, .rp-age-row, .rp-ing-row, thead, tr, .rp-fu, .rp-xm, .rp-trend, .rp-stat, .rp-q {break-inside:avoid}
  #rp-raw.panel {break-inside:auto}
  .rp-raw .rp-table {overflow:visible !important}
  .rp-raw .rp-table th, .rp-raw .rp-table td {white-space:normal !important}
  h2, h3 {break-after:avoid}
  .rp-main {display:flex;flex-direction:column}
  #rp-now {order:1} #rp-writing {order:2} #rp-todo {order:3} #rp-followups {order:4} .rp-appx-head {order:5}
  #rp-aging {order:6} #rp-evidence {order:7} #rp-detect {order:8} #rp-extra {order:9} #rp-ingest {order:10}
  #rp-facts {order:11} #rp-raw {order:12} #rp-footnotes {order:13}
  .rp-end {order:14}
  .rp-view[data-scope="summary"] .rp-appx-area, .rp-view[data-scope="summary"] .rp-appx-head {display:none !important}
  .rp-scope {display:none !important}
  .rp-print-stamp {display:block !important;position:fixed;top:0;left:0;right:0;
    font-size:9pt;color:#444;border-bottom:1px solid #bbb;padding-bottom:3px}
  .rp-end {display:block !important;margin-top:16px;font-size:10pt;color:#444;text-align:center}
  .rp-draft-note {display:block !important;margin:0 0 8px;padding:6px 10px;border:2px solid #000;font-weight:700;text-align:center}
}
.rp-print-stamp, .rp-end, .rp-draft-note {display:none}
</style>"""


EVIDENCE_SHOWN = 5


def render_evidence(cases):
    """사건과 대응 근거. 한 줄 요약 + 표 상위 몇 건만 보이고, 전체는 접는다(전체 근거는 감사용 절에 따로 있다)."""
    if not cases:
        return '<p class="rp-empty">선택한 기간에 신규 사건이나 관련 조치 기록이 없습니다.</p>'
    esc = html.escape
    new = sum(1 for case in cases if case["new"])
    locked = sum(1 for case in cases if case["locks"])
    blocked = sum(1 for case in cases if case["ip"])
    summary = (f'<p class="rp-ev-sum"><b>{_fmt(len(cases))}건</b> 움직임 · 신규 {_fmt(new)} · 이전 사건 후속 {_fmt(len(cases) - new)}'
               f' · 계정 자동 잠금 {_fmt(locked)} · IP 차단 요청 {_fmt(blocked)}</p>')

    def row(case):
        response = " · ".join(filter(None, [
            f'잠금 {_fmt(case["locks"])}' if case["locks"] else "",
            ", ".join(ACTION_LABELS.get(state, "상태 미확인") for state in case["ip"]) if case["ip"] else ""])) or "—"
        return (f'<tr><th scope="row"><a href="/incidents/{quote(case["id"], safe="")}">{esc(case["title"])}</a></th>'
                f'<td>{"신규" if case["new"] else "후속"}</td><td>{esc(case.get("target_ip") or "—")}</td>'
                f'<td>{esc(response)}</td></tr>')
    head = ('<thead><tr><th scope="col">사건</th><th scope="col">구분</th><th scope="col">대상 IP</th>'
            '<th scope="col">대응</th></tr></thead>')
    table = f'<div class="rp-table rp-ev"><table>{head}<tbody>{"".join(row(c) for c in cases[:EVIDENCE_SHOWN])}</tbody></table></div>'
    rest = cases[EVIDENCE_SHOWN:]
    more = (f'<details><summary>나머지 {_fmt(len(rest))}건 보기</summary><div class="rp-table rp-ev"><table>{head}'
            f'<tbody>{"".join(row(c) for c in rest)}</tbody></table></div></details>' if rest else "")
    return summary + table + more


def _line_points(values, axis_max, width=640, height=180):
    count = len(values)
    coords = []
    for i, value in enumerate(values):
        x = width * i / (count - 1) if count > 1 else width / 2
        y = 4 + (height - 8) * (1 - value / axis_max)
        coords.append((x, y))
    return coords


def render_daily(daily, kind="weekly"):
    if not daily:
        return '<p class="rp-empty">이 확정본에는 일별 집계가 저장되어 있지 않습니다.</p>'
    series = (("cases", "신규 사건", ""), ("locks", "계정 자동 잠금", "6 4"), ("requests", "IP 차단 요청", "1.5 3.5"))
    maximum = max((row[key] for row in daily for key, _, _ in series), default=0)
    if not maximum:
        return (f'<p class="rp-empty">관측 기간 {len(daily)}일 전체에서 신규 사건·계정 자동 잠금·'
                'IP 차단 요청이 모두 0건입니다.</p>')
    axis_max = max(2, maximum + maximum % 2)
    width, height = 640, 180
    count = len(daily)
    dash_attr = lambda dash: f' stroke-dasharray="{dash}"' if dash else ""
    # 요약 카드: 합계가 1차(글자)이고 작은 추이선은 보조다.
    cards = []
    for index, (key, name, dash) in enumerate(series):
        values = [row[key] for row in daily]
        peak = max(values) or 1
        line = " ".join(f"{x * 100 / width:.1f},{y * 28 / height:.1f}" for x, y in _line_points(values, peak, width, height))
        cards.append(f'<div class="rp-stat"><span class="rp-cell-label">{name}</span>'
                     f'<b class="rp-stat-val">{_fmt(sum(values))}<small>건</small></b>'
                     f'<svg class="rp-c{index}" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">'
                     f'<polyline points="{line}" fill="none" stroke="currentColor" stroke-width="1.5" '
                     f'vector-effect="non-scaling-stroke"{dash_attr(dash)}/></svg></div>')
    grid = "".join(f'<line x1="0" x2="{width}" y1="{4 + (height - 8) * f:.1f}" y2="{4 + (height - 8) * f:.1f}"/>'
                   for f in (0, 0.5, 1))
    per_series = {key: _line_points([row[key] for row in daily], axis_max, width, height) for key, _, _ in series}
    area_pts = per_series["cases"]
    area = (f'M{area_pts[0][0]:.1f},{height} ' + " ".join(f"L{x:.1f},{y:.1f}" for x, y in area_pts)
            + f' L{area_pts[-1][0]:.1f},{height} Z')
    lines = "".join(
        '<polyline class="rp-c%d" points="' % index + " ".join(f"{x:.1f},{y:.1f}" for x, y in per_series[key])
        + f'" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" '
        f'stroke-linejoin="round"{dash_attr(dash)}/>' for index, (key, _, dash) in enumerate(series[:1]))
    details = []
    for i, row in enumerate(daily):
        day = date.fromisoformat(row["date"])
        query = urlencode({"from": f"{day}T00:00:00+09:00", "to": f"{day + timedelta(days=1)}T00:00:00+09:00"})
        details.append({
            "day": f"{day:%m/%d} {'월화수목금토일'[day.weekday()]}",
            "values": [row[key] for key, _, _ in series],
            "y": [round(100 * per_series[key][i][1] / height, 2) for key, _, _ in series],
            "x": round(100 * i / (count - 1), 3) if count > 1 else 50,
            "q": query})
    names = [name for _, name, _ in series]
    legend = "".join(
        f'<span><svg class="rp-c{index}" width="22" height="8" aria-hidden="true"><line x1="0" x2="22" y1="4" y2="4" stroke="currentColor" '
        f'stroke-width="2"{dash_attr(dash)}/></svg>{name}</span>' for index, (_, name, dash) in enumerate(series[:1]))
    step = 1 if count <= 7 else 5

    def xlabel(i, row):
        day = date.fromisoformat(row["date"])
        if not (i % step == 0 or i == count - 1):
            return "<span></span>"
        return f'<span>{"월화수목금토일"[day.weekday()] if count <= 7 else day.day}</span>'
    xlabels = "".join(xlabel(i, row) for i, row in enumerate(daily))
    headers = "".join(f'<th scope="col">{label}</th>' for _, label, _ in series)
    rows = "".join(
        f'<tr><th scope="row">{html.escape(row["date"])}</th>'
        + "".join(f'<td>{row[key]:,}</td>' for key, _, _ in series) + '</tr>' for row in daily)
    payload = html.escape(json.dumps({"names": names, "days": details}, ensure_ascii=False), quote=True)
    script = (
        '<script>(()=>{const chart=document.querySelector(".rp-chart");if(!chart)return;'
        'const data=JSON.parse(chart.dataset.chart),days=data.days,plot=chart.querySelector(".rp-plot2"),'
        'canvas=chart.querySelector(".rp-canvas"),cross=canvas.querySelector(".rp-cross"),tip=canvas.querySelector(".rp-tip"),'
        'dots=cross.querySelectorAll("b"),out=chart.querySelector("[data-report-readout]"),link=chart.querySelector("[data-report-events]");'
        'let at=-1;const text=d=>d.day+" · "+data.names.map((n,i)=>n+" "+d.values[i].toLocaleString()+"건").join(" · ");'
        'const show=i=>{i=Math.max(0,Math.min(days.length-1,i));at=i;const d=days[i];cross.hidden=false;tip.hidden=false;'
        'cross.style.left=d.x+"%";dots.forEach((dot,k)=>dot.style.top=d.y[k]+"%");'
        'tip.replaceChildren();const head=document.createElement("strong");head.textContent=d.day;tip.append(head);'
        'data.names.forEach((n,k)=>{const row=document.createElement("span"),a=document.createElement("em"),b=document.createElement("b");'
        'const sw=document.createElement("i");sw.className="rp-c"+k;a.textContent=n;a.prepend(sw);b.textContent=d.values[k].toLocaleString()+"건";row.append(a,b);tip.append(row);});'
        'tip.style.left=d.x+"%";tip.dataset.side=d.x>60?"left":"right";out.textContent=text(d);'
        'link.href="/events?"+d.q;link.hidden=false;};'
        'canvas.addEventListener("pointermove",e=>{const r=canvas.getBoundingClientRect();'
        'show(days.length>1?Math.round((e.clientX-r.left)/r.width*(days.length-1)):0);});'
        'canvas.addEventListener("pointerleave",()=>{cross.hidden=true;tip.hidden=true;});'
        'plot.addEventListener("keydown",e=>{if(e.key==="ArrowLeft"){show(at<0?0:at-1);e.preventDefault();}'
        'else if(e.key==="ArrowRight"){show(at+1);e.preventDefault();}});})();</script>')
    return (
        f'<div class="rp-chart" data-chart="{payload}"><div class="rp-stats">{"".join(cards)}</div>'
        f'<div class="rp-chart-key">{legend}<span class="rp-chart-note">계정 자동 잠금·IP 차단 요청은 수가 작아 위 카드와 마우스 툴팁에서 봅니다.</span></div>'
        '<div class="rp-plot2" tabindex="0" role="group" aria-label="일별 관제 추이. 좌우 방향키로 날짜를 옮기면 수치가 아래에 표시됩니다.">'
        f'<div class="rp-yscale" aria-hidden="true"><span>{axis_max:,}</span><span>{axis_max // 2:,}</span><span>0</span></div>'
        f'<div class="rp-canvas"><svg viewBox="0 0 {width} {height}" preserveAspectRatio="none" aria-hidden="true">'
        '<defs><linearGradient class="rp-c0" id="rp-fill" x1="0" x2="0" y1="0" y2="1">'
        '<stop offset="0" stop-color="currentColor" stop-opacity=".26"/><stop offset="1" stop-color="currentColor" stop-opacity="0"/>'
        f'</linearGradient></defs><g stroke="currentColor" stroke-opacity=".18" vector-effect="non-scaling-stroke">{grid}</g>'
        f'<path d="{area}" fill="url(#rp-fill)"/>{lines}</svg>'
        '<div class="rp-cross" hidden><i></i><b class="rp-c0"></b></div>'
        '<div class="rp-tip" hidden></div></div></div>'
        f'<div class="rp-xlabels" aria-hidden="true">{xlabels}</div>'
        '<div class="rp-readout"><span data-report-readout>그래프에 마우스를 올리거나 방향키로 날짜를 고르면 수치가 보입니다.</span>'
        '<a data-report-events hidden>선택한 날짜의 로그 열기 →</a></div>'
        f'{script}'
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


def _age_text(hours):
    return f"{hours // 24}일" if hours >= 24 else f"{hours}시간"


def render_queue(open_counts, open_cases, generated=""):
    """미결 사건 현황. 막대 네 줄 대신 '처리 대기열' 두 칸: 건수 · 경과 분포 한 줄 · 오래된 순 목록.
    (html, 미결 합계, 제목 문장)을 돌려준다. 옛 확정본(오래된 목록이 없음)과 미결 0건은 기존 표시로 돌아간다."""
    aging = open_counts.get("aging")
    if not isinstance(aging, list) or len(aging) != len(AGING_BUCKETS) or not isinstance(open_cases, dict):
        return render_aging(open_counts, generated)
    counts = [(int(item.get("action") or 0), int(item.get("review") or 0)) for item in aging]
    if not sum(a + r for a, r in counts):
        return render_aging(open_counts, generated)
    esc = html.escape
    cards = []
    for group, title, meaning, index in (("action", "조치 대기", "IP 차단 승인 경로가 있는 사건", 0),
                                         ("review", "판단 대기", "조사용 경보만 붙어 종결 경로가 없는 사건", 1)):
        per_bucket = [pair[index] for pair in counts]
        total = sum(per_bucket)
        if not total:
            cards.append(f'<div class="rp-q"><h3>{title} · 0건</h3>'
                         f'<p class="rp-list-meta">{meaning}</p><p class="rp-empty">관측했고 미결은 없습니다.</p></div>')
            continue
        segments = "".join(f'<span class="rp-q-seg" data-t="{i}" style="flex-grow:{value}"></span>'
                           for i, value in enumerate(per_bucket) if value)
        legend = "".join(
            f'<li{" data-zero" if not value else ""}><i data-t="{i}" aria-hidden="true"></i>{AGING_BUCKETS[i][0]} <b>{_fmt(value)}</b></li>'
            for i, value in enumerate(per_bucket))
        old = sum(per_bucket[2:])
        verdict = (f'4일 넘은 건 <b>{_fmt(old)}건</b>' if old else '4일 넘은 건 없음')
        items = (open_cases.get(group) or [])[:QUEUE_SHOWN]
        rows = "".join(
            f'<li><a href="/incidents/{quote(item["id"], safe="")}">{esc(item["title"])}</a>'
            f'<b>{_age_text(int(item["age_hours"]))}</b>'
            f'<span class="sev sev-{esc(str(item.get("severity") or "info").lower(), quote=True)}">{severity_label(item.get("severity"))}</span>'
            f'<span>{esc(item.get("target_ip") or "—")}</span></li>' for item in items)
        shown = len(items)
        more = (f'<p class="rp-list-meta">우선순위 순 {shown}건만 표시합니다. 전체 {_fmt(total)}건은 '
                '<a href="/incidents">사건 목록</a>에서 확인하세요.</p>' if total > shown else "")
        cards.append(
            f'<div class="rp-q"><h3>{title} · {_fmt(total)}건</h3>'
            f'<p class="rp-list-meta">{meaning}</p>'
            f'<p class="rp-q-verdict">{verdict}</p><div class="rp-q-bar" aria-hidden="true">{segments}</div>'
            f'<ul class="rp-q-legend">{legend}</ul>'
            f'<h4>높음 먼저 · 오래된 순</h4><ul class="rp-q-list">{rows}</ul>{more}</div>')
    base = (f"스냅샷 생성 시각({esc(generated[:16].replace('T', ' '))} KST)" if generated else "스냅샷 생성 시각")
    total_all = sum(a + r for a, r in counts)
    return (f'<div class="rp-queue">{"".join(cards)}</div>'
            f'<p class="rp-age-note">경과일은 사건 생성 시각부터 {base}까지입니다. 이 기간에 생성된 사건만 셉니다.</p>',
            total_all, _aging_headline(counts))


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


def ingest_summary(ingest):
    """신뢰 띠용 한 문구. 저장 안 됨/공백 의심/구분 불가/없음을 모두 글자로 구분한다.
    '활동 적음'(원래 뜸한 출처)은 경고가 아니다. 이전엔 받던 출처가 이번 기간 0건이면 '구분 불가'로 올린다."""
    sources = (ingest or {}).get("sources") if isinstance(ingest, dict) else None
    if not isinstance(sources, list) or not sources:
        return "수집 공백 집계 저장 안 됨"
    gaps = [s for s in sources if s.get("state") == "gap"]
    unsure = [s for s in sources if s.get("state") == "no_data" and s.get("had_prior_data")]
    if gaps:
        return f'수집 공백 의심 <b>{len(gaps)}개 출처</b> ({html.escape(", ".join(str(s.get("label")) for s in gaps))})'
    if unsure:
        return f'수집 상태 구분 불가 <b>{len(unsure)}개 출처</b> (이전엔 받던 출처가 0건)'
    return "수집 공백 의심 없음"


_SVG = ('<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">')
ICON_PRINT = _SVG + '<path d="M7 9V3h10v6M7 17H5a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2"/><rect x="7" y="14" width="10" height="7"/></svg>'
ICON_FILE = _SVG + '<path d="M12 4v11m0 0-4-4m4 4 4-4M5 20h14"/></svg>'
ICON_MAIL = _SVG + '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>'
INGEST_COLORS = {"erp": "var(--source-erp)", "gateway": "var(--source-gateway)",
                 "caddy": "var(--source-caddy)", "waf": "var(--source-waf)"}


def _ingest_axis(ingest, hours):
    """띠 아래 날짜 눈금. 자정(KST)이 시작되는 칸마다 그 날짜(주간은 요일)를 적는다."""
    try:
        start = datetime.fromisoformat(str(ingest.get("period_start_kst")))
    except ValueError:
        return ""
    count = max((len(src.get("buckets", [])) for src in ingest.get("sources", [])), default=0)
    if not count:
        return ""
    weekly = hours == 1
    ticks = []
    for index in range(count):
        at = start + timedelta(hours=index * hours)
        if at.hour != 0:
            continue
        span = max(1, 24 // hours)
        label = "월화수목금토일"[at.weekday()] if weekly else f"{at.day}일"
        ticks.append(f'<span style="grid-column:{index + 1} / span {span}">{label}</span>')
    return f'<div class="rp-ing-axis" aria-hidden="true" style="--n:{count}">{"".join(ticks)}</div>' if ticks else ""


INGEST_STATE_TEXT = {"ok": "이상 없음", "gap": "공백 의심", "sparse": "활동 적음", "no_data": "구분 불가"}


def render_ingest(ingest, event_link):
    """출처별 수집 상태 표. 실무자가 먼저 묻는 '마지막 수신'과 '끝에서 연속 무수신'을 앞에 둔다.
    시간대별 띠는 접어 둔다. 띠에서 0건은 사선, None(평가 안 함)은 빈 점선 칸이다. None을 공백으로 칠하지 않는다."""
    sources = ingest.get("sources") if isinstance(ingest, dict) else None
    if not isinstance(sources, list) or not sources:
        return ('<p class="rp-empty">이 확정본에는 수집 공백 집계가 저장되어 있지 않아 표시하지 못합니다. '
                f'이 기간의 로그는 <a href="{event_link}">이벤트 목록</a>에서 직접 확인하세요.</p>')
    hours = int(ingest.get("bucket_hours") or 1)
    stored = "<span class=\"rp-na\">저장 안 됨</span>"
    rows, bands, series = [], [], []
    for source in sources:
        state = source.get("state")
        label = html.escape(str(source.get("label")))
        if "last_active_kst" in source:
            last = source.get("last_active_kst")
            last_text = (f'{_ts_short(last)[5:13]}시대' if last else "기록 없음")
            tail = source.get("tail_silent_hours")
            tail_text = "—" if tail is None else ("없음" if not tail else f"{_fmt(tail)}시간")
        else:
            last_text = tail_text = stored
        longest = source.get("max_gap_hours")
        longest_text = "—" if longest is None else f'{_fmt(longest)}시간'
        attr = " data-bad" if state == "gap" else ""
        rows.append(
            f'<tr{attr}><th scope="row">{label}</th><td>{_fmt(source.get("total") or 0)}건</td><td>{last_text}</td>'
            f'<td>{tail_text}</td><td>{longest_text}</td><td><b>{INGEST_STATE_TEXT.get(state, "상태 미확인")}</b></td></tr>')
        values = source.get("buckets", [])
        peak = max((v for v in values if v), default=1)
        bars = "".join(
            '<span class="n"></span>' if value is None
            else '<span class="z"></span>' if not value
            else f'<span class="h" style="height:{max(14.0, 100 * (value / peak) ** 0.5):.0f}%"></span>'
            for value in values)
        color = INGEST_COLORS.get(source.get("key"), "var(--text-3)")
        bands.append(f'<li class="rp-ing-row"{attr} style="--c:{color}"><span class="rp-ing-name">{label}</span>'
                     f'<span class="rp-ing-band" data-label="{label}" style="--n:{max(1, len(values))}">{bars}</span></li>')
        series.append({"label": str(source.get("label")), "values": values})
    head = ('<thead><tr><th scope="col">출처</th><th scope="col">기간 건수</th><th scope="col">마지막 수신</th>'
            '<th scope="col">끝에서 연속 무수신</th><th scope="col">최장 무수신</th><th scope="col">판정</th></tr></thead>')
    states = {source.get("state") for source in sources}
    notes = []
    if "sparse" in states:
        notes.append("활동 적음: 기록이 있던 시간이 평가 구간의 25% 미만입니다. 수집이 끊긴 것인지 원래 한산한 것인지 이 데이터만으로는 구분할 수 없습니다.")
    if "no_data" in states:
        notes.append("구분 불가: 이 기간에 기록이 한 건도 없습니다. 트래픽이 없었는지 수집이 끊겼는지 구분할 수 없습니다.")
    if "gap" in states:
        notes.append(f'공백 의심: 0건이 {_fmt(ingest.get("min_gap_hours") or 0)}시간 이상 이어졌습니다.')
    try:
        start = datetime.fromisoformat(str(ingest.get("period_start_kst")))
    except ValueError:
        start = None
    payload = html.escape(json.dumps({"hours": hours, "start": start.isoformat() if start else "", "rows": series},
                                     ensure_ascii=False), quote=True)
    script = (
        '<script>(()=>{const box=document.querySelector(".rp-ingest [data-strip]");if(!box)return;'
        'const d=JSON.parse(box.dataset.strip),out=box.querySelector("[data-strip-readout]"),W=["일","월","화","수","목","금","토"];'
        'const fmt=i=>{if(!d.start)return"";const t=new Date(new Date(d.start).getTime()+i*d.hours*3600000),'
        'k=new Date(t.getTime()+9*3600000);return(k.getUTCMonth()+1)+"/"+k.getUTCDate()+" ("+W[k.getUTCDay()]+") "+k.getUTCHours()+"시"+(d.hours>1?"부터 "+d.hours+"시간":"")};'
        'box.querySelectorAll(".rp-ing-band").forEach((band,r)=>{band.addEventListener("pointermove",e=>{'
        'const rect=band.getBoundingClientRect(),v=d.rows[r].values,i=Math.max(0,Math.min(v.length-1,Math.floor((e.clientX-rect.left)/rect.width*v.length)));'
        'out.textContent=d.rows[r].label+" · "+fmt(i)+" · "+(v[i]===null?"평가 안 함":v[i].toLocaleString()+"건");});'
        'band.addEventListener("pointerleave",()=>{out.textContent="막대에 마우스를 올리면 그 시간의 건수가 보입니다.";});});})();</script>')
    return (
        '<div class="rp-ingest">'
        f'<div class="rp-table"><table class="rp-ing-table">{head}<tbody>{"".join(rows)}</tbody></table></div>'
        + (f'<p class="rp-ing-note">{" ".join(html.escape(n) for n in notes)}</p>' if notes else "")
        + '<details><summary>시간별 수신 그래프 보기</summary>'
        f'<div data-strip="{payload}">'
        '<div class="rp-chart-key"><span><i class="rp-lg-bar" aria-hidden="true"></i>기록 있음 (막대가 높을수록 많음 · 색은 출처)</span>'
        '<span><i class="rp-lg-zero" aria-hidden="true"></i>0건</span>'
        '<span><i class="rp-g-na" aria-hidden="true"></i>평가 안 함</span></div>'
        f'<ul class="rp-ing-list">{"".join(bands)}</ul>{_ingest_axis(ingest, hours)}'
        '<p class="rp-readout rp-strip-readout" data-strip-readout>막대에 마우스를 올리면 그 시간의 건수가 보입니다.</p>'
        f'<p class="rp-age-note">막대 한 칸은 {hours}시간이고, 막대 높이는 출처마다 자기 최대치를 기준으로 그립니다(작은 값도 보이도록 제곱근 눈금). '
        '수집 시작 전·미래·덜 찬 칸은 "평가 안 함"이라 공백으로 세지 않습니다.</p></div></details>'
        f'<p class="rp-age-note"><a href="{event_link}">이 기간의 이벤트 열기 →</a></p>{script}</div>')


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


TODO_SHOWN = 5


def render_todo(snapshot, followups, today):
    """1층의 '지금 해야 할 일'. 읽는 사람이 이 보고서에서 바로 움직일 항목 세 종류만 모은다."""
    esc = html.escape
    items = []
    open_cases = snapshot.get("open_cases")
    action_total = int((snapshot.get("open") or {}).get("action") or 0)
    shown_actions = []
    if isinstance(open_cases, dict):
        shown_actions = (open_cases.get("action") or [])[:TODO_SHOWN]
    for case in shown_actions:
        key = esc(str(case.get("severity") or "info").lower(), quote=True)
        meta = (f'<span class="sev sev-{key}">{severity_label(case.get("severity"))}</span> · '
                f'{_age_text(int(case["age_hours"]))} · {esc(case.get("target_ip") or "대상 IP 없음")}')
        items.append(("차단 승인 대기", f'<a href="/incidents/{quote(case["id"], safe="")}">{esc(case["title"])}</a>', meta))
    if action_total > len(shown_actions):
        items.append(("차단 승인 대기", f'<a href="/incidents">외 {_fmt(action_total - len(shown_actions))}건 — 사건 목록에서 확인</a>', ""))
    unsettled = sum((snapshot.get("unsettled") or {}).values())
    if unsettled:
        items.append(("미확정 차단", f'<a href="/incidents">승인했지만 게이트웨이 적용이 확인되지 않은 차단 {_fmt(unsettled)}건</a>',
                      "한 건이라도 있으면 차단했다고 보고할 수 없습니다"))
    overdue = sorted((r for r in (followups or []) if is_overdue(r, today)), key=lambda r: r["due"])
    for row in overdue[:TODO_SHOWN]:
        items.append(("기한 초과", f'<a href="#rp-followups">{esc(row["text"])}</a>',
                      f'기한 {esc(row["due"])} · {("담당 " + esc(row["owner"])) if row["owner"] else "담당 미지정"}'))
    if len(overdue) > TODO_SHOWN:
        items.append(("기한 초과", f'<a href="#rp-followups">외 {_fmt(len(overdue) - TODO_SHOWN)}건</a>', ""))
    summary = (f'<p class="rp-todo-sum">차단 승인 대기 <b>{_fmt(action_total)}건</b> · 미확정 차단 <b>{_fmt(unsettled)}건</b>'
               f' · 기한 초과 후속 조치 <b>{_fmt(len(overdue))}건</b></p>')
    if not items:
        return summary + '<p class="rp-empty">지금 이 보고서에서 바로 처리할 항목이 없습니다.</p>'
    rows = "".join(f'<li><span class="rp-todo-tag">{tag}</span><span class="rp-todo-text">{text}</span>'
                   f'<span class="rp-todo-meta">{meta}</span></li>' for tag, text, meta in items)
    return f'{summary}<ul class="rp-todo-list">{rows}</ul>'


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
    """추가 지표 세 칸. 칸마다 같은 뼈대(이름 · 큰 합계 · 항목 줄 · 주석)라 위아래 줄이 맞는다.
    못 센 항목은 0이 아니라 '집계 불가'로 적는다. 옛 확정본에는 키가 없다."""
    if not isinstance(extra, dict):
        return ('<p class="rp-empty">이 확정본에는 추가 지표가 저장되어 있지 않아 표시하지 못합니다. '
                f'원본은 <a href="{event_link}">이벤트 목록</a>에서 확인하세요.</p>')

    def card(name, total, rows, note, state="ok"):
        if state != "ok":
            head = '<p class="rp-xm-num"><b class="rp-xm-na">집계 불가</b></p>'
            body = '<p class="rp-xm-note">조회 상한에 닿아 일부가 잘렸을 수 있어 수치를 적지 않습니다.</p>'
        else:
            head = f'<p class="rp-xm-num"><b>{_fmt(total)}</b>건</p>'
            body = (_kv(rows) if rows else '<p class="rp-xm-note">관측했고 해당 기록은 없습니다.</p>')
        return (f'<div class="rp-xm"><h3>{name}</h3>{head}<div class="rp-xm-rows">{body}</div>'
                f'<p class="rp-xm-note">{note}</p></div>')

    waf = extra.get("waf") or {}
    waf_rows = []
    if waf.get("total"):
        waf_rows = ([("감지", waf["detected"]), ("차단", waf["blocked"])]
                    + sorted(waf["families"].items(), key=lambda item: -item[1]))
    doc = extra.get("doc_read") or {}
    doc_rows = ([("열람 성공(200)", doc["ok"]), ("로그인 안 됨(401)", doc["unauth"]),
                 ("권한 없음 거부(403)", doc["forbidden"]), ("없는 문서(404)", doc["missing"]),
                 ("그 밖", doc["other"])] if doc.get("total") else [])
    recur = extra.get("recur") or {}
    recur_rows = ([("재발 IP", recur["ips"]), ("재발 계정", recur["accounts"])] if recur.get("state") == "ok" else [])
    cards = [
        card("WAF 판정", waf.get("total", 0), waf_rows, "감지와 차단, 규칙 유형별", waf.get("state", "ok")),
        card("ERP 문서 열람", doc.get("total", 0), doc_rows, "403은 권한 없음, 404는 없는 문서", doc.get("state", "ok")),
        card("로그인 실패 · 재발", recur.get("failed_total", 0), recur_rows,
             "같은 IP·계정이 서로 다른 2일 이상 실패한 수", recur.get("state", "ok")),
    ]
    return (f'<div class="rp-xgrid">{"".join(cards)}</div>'
            f'<p class="rp-list-meta"><a href="{event_link}">이 기간의 이벤트 열기 →</a></p>')


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

    case_rows = [[link(case["id"]), _raw_value(case, "severity", severity_label), _raw_value(case, "target_ip"),
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


# AI 초안은 입력칸을 바로 덮어쓰지 않는다. 입력칸 바로 아래에 '제안 카드'로 보여 주고, 사람이 바꾸기·덧붙이기·버리기를 고른다.
AI_BLOCK = (
    '<div class="rp-ai" data-ai-box>'
    '<div class="rp-ai-row"><button type="button" class="rp-ai-btn" data-ai="summary"><span aria-hidden="true">✦</span> AI로 초안 만들기</button>'
    '<span class="rp-ai-hint">숫자와 고정 용어만 보냅니다. 사건 제목·IP·계정명·로그 문장은 보내지 않습니다.</span>'
    '<button type="button" class="rp-ai-btn is-quiet" data-ai-preview>보내는 내용 미리 보기</button></div>'
    '<pre class="rp-ai-pre" hidden></pre>'
    '<p class="rp-ai-note" role="status" aria-live="polite"></p>'
    '<div class="rp-ai-card" hidden>'
    '<p class="rp-ai-cap"></p><p class="rp-ai-text"></p>'
    '<div class="rp-ai-acts"><button type="button" class="rp-ai-btn" data-ai-act="replace">이 내용으로 바꾸기</button>'
    '<button type="button" class="rp-ai-btn" data-ai-act="append">아래에 덧붙이기</button>'
    '<button type="button" class="rp-ai-btn is-quiet" data-ai-act="discard">버리기</button></div></div></div>')
AI_SCRIPT = (
    '<script>(()=>{const form=document.getElementById("report-form"),box=form&&form.querySelector("[data-ai-box]");'
    'if(!box)return;const area=form.elements.summary,flag=form.elements.ai_summary,make=box.querySelector("[data-ai]"),'
    'note=box.querySelector(".rp-ai-note"),card=box.querySelector(".rp-ai-card"),cap=box.querySelector(".rp-ai-cap"),'
    'text=box.querySelector(".rp-ai-text"),pre=box.querySelector(".rp-ai-pre"),peek=box.querySelector("[data-ai-preview]");let draft="";'
    'const post=(extra)=>{const body=new URLSearchParams(Object.assign({csrf_token:form.elements.csrf_token.value,week:form.elements.week.value,'
    'kind:form.elements.kind.value,field:"summary"},extra||{}));return fetch("/reports/ai-draft",{method:"POST",body}).then(r=>r.json());};'
    'peek.addEventListener("click",async()=>{if(!pre.hidden){pre.hidden=true;peek.textContent="보내는 내용 미리 보기";return;}'
    'try{const data=await post({preview:"1"});pre.textContent=data.ok?data.facts:(data.error||"미리 볼 수 없습니다.");pre.hidden=false;'
    'peek.textContent="미리 보기 닫기";}catch(e){note.textContent="미리 볼 수 없습니다.";}});'
    'const apply=(append)=>{area.value=append&&area.value.trim()?area.value.trimEnd()+"\\n\\n"+draft:draft;flag.value="1";'
    'area.dispatchEvent(new Event("input",{bubbles:true}));card.hidden=true;area.focus();'
    'note.textContent="입력칸에 넣었습니다. 읽고 고친 뒤 \'초안 저장\'을 눌러야 저장됩니다.";};'
    'box.querySelectorAll("[data-ai-act]").forEach(b=>b.addEventListener("click",()=>{const act=b.dataset.aiAct;'
    'if(act==="discard"){card.hidden=true;note.textContent="";}else apply(act==="append");}));'
    'make.addEventListener("click",async()=>{make.disabled=true;card.hidden=true;note.textContent="AI가 초안을 쓰는 중입니다…";'
    'try{const data=await post();'
    'if(data.ok){draft=data.text;text.textContent=draft;'
    'cap.textContent="AI 초안"+(data.checked?" · 글 속 숫자 "+data.checked+"개를 집계와 대조해 모두 일치":"")+" · 읽고 고쳐서 쓰세요"'
    '+(area.value.trim()?" · 입력칸에 이미 글이 있어 바꾸거나 덧붙일 수 있습니다":"");'
    'note.textContent="";card.hidden=false;card.querySelector("[data-ai-act=replace]").focus();}'
    'else{note.textContent=data.error||"AI 초안을 만들지 못했습니다.";}}'
    'catch(e){note.textContent="AI 서비스에 연결하지 못했습니다. 직접 쓰셔도 됩니다.";}'
    'make.disabled=false;});})();</script>')


def report_body(week, report, snapshot, history, csrf, editable, message="", *, kind="weekly",
                followups=None, today=None, previous=None, trend=None, ai_enabled=False):
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
    open_cases = snapshot.get("open_cases")

    def oldest_text(group):
        """그룹별로 가장 오래된 미결 사건. 옛 확정본은 두 그룹 합산값만 있어 그렇다고 적는다."""
        if isinstance(open_cases, dict):
            items = open_cases.get(group) or []
            return f"가장 오래된 건 {_age_text(int(items[0]['age_hours']))} 경과" if items else "미결 없음"
        oldest = open_counts.get("oldest_days")
        return f"조치·판단 합산 가장 오래된 건 {oldest}일 경과" if oldest else "경과일 집계 없음"
    cells = [
        _cell("조치 대기", "/incidents", _count_value(open_counts.get("action", 0)),
              f"IP 차단 승인 경로가 있는 사건 · {oldest_text('action')}", "사건 목록 열기"),
        _cell("판단 대기", "/incidents", _count_value(open_counts.get("review", 0)),
              f"조사용 경보만 붙어 종결 경로가 없는 사건 · {oldest_text('review')}" if isinstance(open_cases, dict)
              else "조사용 경보만 붙어 종결 경로가 없는 사건", "사건 목록 열기"),
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
    excluded_n = (snapshot.get("excluded") or {}).get("incidents", 0)
    trust = [
        f'집계 불가 <b>{unknown_count}개</b>' if unknown_count else "집계 불가 없음",
        f'미확정 차단 <b>{_fmt(unsettled_total)}건</b>' if unsettled_total else "미확정 차단 0건",
        (f'재생·합성 근거 사건 <b>{_fmt(excluded_n)}건</b> 제외' if excluded_n else None),
        f'재생·합성 근거 경보 <b>{_fmt(snapshot["replay_alerts"])}건</b> 포함' if snapshot.get("replay_alerts")
        else ("재생·합성 근거 경보 0건" if not excluded_n else None),
        ingest_summary(snapshot.get("ingest")),
        followup_summary(frozen_followups if finalized else followups, today),
    ]
    trust = [piece for piece in trust if piece]
    if generated:
        trust.append(f'스냅샷 {esc(generated[:16].replace("T", " "))} KST')
    verdict_text = notes.get("summary", "").strip()
    if verdict_text:
        verdict = (f'<p class="rp-verdict">{esc(verdict_text)}</p>'
                   + ('<p class="rp-list-meta">핵심 판단은 AI 초안을 바탕으로 사람이 고쳐 썼습니다.</p>'
                      if ((report or {}).get("ai") or {}).get("summary") else ""))
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
    daily_rows = snapshot.get("daily") or []
    cards_shown = any(row.get(key) for row in daily_rows for key in ("cases", "locks", "requests"))  # 아래 요약 카드와 같은 조건
    detect_rows = [] if cards_shown else [
        ("신규 사건", f'{_fmt(metrics.get("신규 사건", 0))}<small>건</small>'),
        ("ERP 계정 자동 잠금", f'{_fmt(metrics.get("ERP 계정 자동 잠금", 0))}<small>건</small>'),
        ("IP 차단 요청", f'{_fmt(requests)}<small>건</small>'),
    ]
    detect_rows += [
        ("움직인 사건", f'{_fmt(len(snapshot.get("cases", [])))}<small>건</small>'),
        ("IP 차단 적용 비율", f'<span class="rp-soft">{esc(ratio_text(metrics.get("IP 차단 적용", 0), requests))}</span>'),
        ("차단으로 막은 접속 시도", blocked_html),
    ]
    detect_html = "".join(f'<div><dt>{esc(label)}</dt><dd>{value}</dd></div>'
                          for label, value in detect_rows)

    # --- S2 사건과 대응 근거 ---
    evidence_html = render_evidence(snapshot.get("cases", []))
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
    writing = ""
    write_section = ""
    if editable and not finalized:
        parts = {}
        for name, label in FIELDS:
            hint = {"summary": "이 보고서의 결론 1~3문장. 이 글이 보고서 첫 줄로 올라갑니다. 비우면 확정할 수 없습니다.",
                    "assessment": "위 집계를 왜 이렇게 봤는지, 침해 가능성과 오탐 판단을 쓰세요.",
                    "opinion": "다른 팀이나 윗선에 요청하거나 결정받아야 할 일을 쓰세요."}.get(name, "")
            required = '<span class="rp-required" aria-hidden="true">*</span>' if name == "summary" else ""
            # required 속성은 쓰지 않는다. 브라우저가 '초안 저장'까지 막아서, 핵심 판단이 비면 초안도 못 저장했다. 확정만 서버가 막는다.
            aria_required = ' aria-required="true"' if name == "summary" else ""
            rows = 3
            ai_block = AI_BLOCK if (ai_enabled and name == "summary") else ""
            parts[name] = (
                f'<p><label for="report-{name}">{esc(label)}{required}</label>'
                f'<textarea id="report-{name}" name="{name}" rows="{rows}" maxlength="2000" '
                f'placeholder="{esc(hint, quote=True)}"{aria_required}>'
                f'{esc(notes.get(name, ""))}</textarea></p>{ai_block}')
        writing = (
            f'<form id="report-form" class="rp-prose" method="post" action="/reports">'
            f'<input type="hidden" name="week" value="{week}">'
            f'<input type="hidden" name="kind" value="{kind}">'
            f'<input type="hidden" name="csrf_token" value="{esc(csrf or "", quote=True)}">'
            f'<input type="hidden" name="ai_summary" value="{1 if ((report or {}).get("ai") or {}).get("summary") else 0}">'
            + parts["summary"]
            + '<div class="rp-two">' + parts["assessment"] + parts["opinion"] + '</div>'
            + '<div class="rp-actions">'
            '<button class="btn-ghost" name="intent" value="draft">초안 저장</button>'
            '<button class="btn-ghost" name="intent" value="collect">수치 다시 불러오기</button>'
            '<span class="rp-list-meta">다시 불러와도 쓴 글은 지워지지 않고, 비어 있던 칸만 채워집니다.</span></div>'
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
            'review.addEventListener("toggle",sync);form.addEventListener("input",sync);})();</script>'
            + (AI_SCRIPT if ai_enabled else ""))
    else:
        # 읽는 사람 화면: 핵심 판단은 '지금 상태' 첫 줄에 이미 있으므로 되풀이하지 않는다. 비어 있는 칸은 감춘다.
        for name, label in FIELDS:
            if name != "summary" and notes.get(name, "").strip():
                writing += f'<h3>{esc(label)}</h3><p class="rp-note">{esc(notes[name])}</p>'
        if not editable and not finalized and not report:
            writing = '<p class="rp-empty">조회 전용 보고서입니다.</p>' + writing
    if writing:
        write_section = f'<section class="panel" id="rp-writing"><h2>판단과 서술</h2>{writing}</section>'
    facts = "".join(f"<p>{esc(line)}</p>" for line in machine_facts(snapshot))
    facts_html = (
        '<details class="rp-fold"><summary>기간 집계 사실 보기 — 자동 생성, 편집 불가</summary>'
        f'<div class="rp-machine">{facts}</div></details>')
    todo_html = render_todo(snapshot, followups, today)

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
    aging_html, aging_total, aging_headline = render_queue(open_counts, snapshot.get("open_cases"), generated)
    compare_rows, compare_reason = compare_periods(
        snapshot, previous["snapshot"] if previous else None, finalized)
    compare_html = render_compare(compare_rows, compare_reason, kind)
    if compare_reason and len(trend or []) < 3:
        compare_trend_html = ('<div class="rp-sub"><h3>지난 기간 대비 · 추이</h3>'
                              f'<p class="rp-empty"><b>표시하지 않음</b> — {html.escape(compare_reason)} '
                              f'추이는 확정본이 3개 이상 쌓이면 표시합니다 (현재 {len(trend or [])}개).</p></div>')
    else:
        compare_trend_html = (f'<div class="rp-sub"><h3>지난 기간 대비</h3>{compare_html}</div>'
                              f'<div class="rp-sub">{render_trend(trend or [])}</div>')
    fu_rows = followups if followups is not None else []
    fu_active = [r for r in (frozen_followups if finalized else followups) or [] if r["status"] in FOLLOWUP_ACTIVE]
    fu_summary = (f"미결 {_fmt(len(fu_active))}건 · 전체 {_fmt(len(fu_rows))}건" if fu_rows
                  else "등록된 후속 조치 없음" + (" — 열어서 등록" if editable and not finalized else ""))
    fu_html = render_followups(
        fu_rows, frozen=frozen_followups if finalized else None, kind=kind, key=key, week=week, csrf=csrf,
        editable=editable, finalized=finalized, today=today, legacy_text=notes.get("followup", ""),
        hint=("확인 후보: " + calculated_draft(snapshot)["followup"]) if not finalized else "")
    open_fu = [r for r in (frozen_followups if finalized else followups) or [] if r["status"] in FOLLOWUP_ACTIVE]
    followup_toc = f"{_fmt(len(open_fu))}건 미결" if open_fu else ""
    summary_sections = [("rp-now", "지금 상태")] + ([("rp-writing", "판단과 서술")] if write_section else []) + [
        ("rp-todo", "지금 해야 할 일"), ("rp-followups", "후속 조치 장부")]
    appendix_sections = [("rp-aging", "미결 사건 현황"), ("rp-evidence", "사건과 대응 근거"), ("rp-detect", "탐지 내용"),
                         ("rp-extra", "추가 지표"), ("rp-ingest", "로그 수집 상태"), ("rp-facts", "기간 집계 사실"),
                         ("rp-raw", "감사용 전체 근거"), ("rp-footnotes", "각주와 집계 기준")]
    sections = summary_sections + appendix_sections
    toc = ('<p class="rp-toc-group">요약</p>'
           + "".join(f'<a href="#{sid}">{esc(label)}</a>' for sid, label in summary_sections)
           + '<p class="rp-toc-group">부록</p>'
           + "".join(f'<a href="#{sid}">{esc(label)}</a>' for sid, label in appendix_sections))
    jump = "".join(f'<a class="range-chip" href="#{sid}">{esc(label)}</a>' for sid, label in sections)
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
    save_button = ('<button class="btn-ghost rp-save" form="report-form" name="intent" value="draft">초안 저장</button>'
                   if editable and not finalized else "")
    if report:
        mail_body = ((notes.get("summary", "").strip() or "(핵심 판단 미작성)")[:700]
                     + "\n\n※ 내려받은 보고서 파일(HTML)을 첨부해 주세요.")
        mail_href = html.escape("mailto:?" + urlencode(
            {"subject": f"{title} 관제 보고서 {span} ({status})", "body": mail_body}, quote_via=quote), quote=True)
        print_button = (
            '<div class="rp-tools rp-print" role="group" aria-label="보고서 출력과 전달">'
            f'<button type="button" class="rp-tool" onclick="window.print()">{ICON_PRINT}인쇄 / PDF</button>'
            f'<a class="rp-tool" href="/reports?kind={kind}&amp;week={week}&amp;export=1" download>{ICON_FILE}파일 저장</a>'
            f'<a class="rp-tool" href="{mail_href}">{ICON_MAIL}메일</a>'
            '</div>'
            '<div class="rp-scope rp-print" role="radiogroup" aria-label="출력 범위"><span>출력 범위</span>'
            '<label><input type="radio" name="rp-scope" value="summary" checked> 요약 (1~2쪽)</label>'
            '<label><input type="radio" name="rp-scope" value="full"> 전체 (부록 포함)</label></div>'
            '<p class="rp-list-meta rp-print rp-tools-note">메일은 제목과 핵심 판단만 채워서 열립니다. 내려받은 파일을 첨부하세요.</p>'
            '<script>(()=>{const view=document.querySelector(".rp-view"),file=view&&view.querySelector("a[download]");'
            'if(!view)return;const base=file&&file.getAttribute("href");'
            'view.querySelectorAll("input[name=rp-scope]").forEach(r=>r.addEventListener("change",()=>{'
            'view.dataset.scope=r.value;if(file)file.setAttribute("href",base+"&scope="+r.value);}));'
            'if(file)file.setAttribute("href",base+"&scope=summary");})();</script>')
    elif editable:
        print_button = '<p class="rp-list-meta rp-print">초안을 저장하면 인쇄·내려받기·메일 보내기가 열립니다.</p>'
    else:
        print_button = ""
    draft_note = ('<p class="rp-draft-note">초안 — 확정 전 보고서입니다. 수치와 서술이 바뀔 수 있습니다.</p>'
                  if report and not finalized else "")
    return f"""
    {REPORT_STYLE}
    <div class="rp-view" data-scope="summary">
    {draft_note}
    <p class="rp-print-stamp">{stamp}</p>
    <header class="panel rp-head">
      <nav class="chart-periods" aria-label="보고서 유형">{kinds}</nav>
      <div class="rp-head-main">
        <div><h1>{title} 관제 보고서</h1>
        <p class="rp-head-meta"><span class="rp-chip {chip_class}">{status}</span><span>{span}</span>
        {f'<span>{esc(report["author"])} · {esc(report["saved_at"][:16].replace("T", " "))} KST</span>' if report else ''}</p>
        </div>
        <form class="rp-period" method="get" action="/reports">
          {quick}
          <input type="hidden" name="kind" value="{kind}">
          <label for="report-week">{'조회 월' if kind == 'monthly' else '기준 날짜'}</label>
          <input type="{'month' if kind == 'monthly' else 'date'}" id="report-week" name="week"
                 value="{str(week)[:7] if kind == 'monthly' else week}" required>
          <button class="btn-ghost">기간 열기</button>
        </form>
      </div>
      <div class="rp-head-tools">{save_button}{print_button}</div>
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
      {write_section}
      <section class="panel" id="rp-todo">
        <h2>지금 해야 할 일</h2>
        {todo_html}
      </section>
      <section class="panel" id="rp-followups">
        <h2>후속 조치 장부</h2>
        <details class="rp-fold"{" open" if fu_rows or finalized else ""}><summary>{fu_summary}</summary>{fu_html}</details>
      </section>
      <div class="rp-appx-head"><h2>부록 — 근거와 상세</h2>
        <p>위까지가 요약입니다. 아래는 숫자의 근거를 확인할 때 보는 상세 자료입니다.</p></div>
      <section class="panel rp-appx-area" id="rp-aging">
        <h2>미결 사건 현황</h2>
        {f'<p class="rp-q-head">{esc(aging_headline)}</p>' if aging_headline else ''}
        {aging_html}
      </section>
      <section class="panel rp-appx-area" id="rp-evidence">
        <h2>사건과 대응 근거</h2>
        {evidence_html}
        <div class="rp-sub"><h3>로그 출처별 이벤트</h3>{sources}
        <p class="rp-list-meta"><a href="{event_range}">이 기간의 이벤트 열기 →</a></p></div>
      </section>
      <section class="panel rp-appx-area" id="rp-detect">
        <h2>탐지 내용</h2>
        <dl class="rp-metrics">{detect_html}</dl>
        <div class="rp-sub"><h3>{'월간 구간별' if kind == 'monthly' else '일별'} 관제 추이</h3>
        {render_daily(snapshot.get("daily"), kind)}</div>
      </section>
      <section class="panel rp-appx-area" id="rp-extra">
        <h2>추가 지표</h2>
        {render_extra(snapshot.get("extra"), event_range)}
        {compare_trend_html}
      </section>
      <section class="panel rp-appx-area" id="rp-ingest">
        <h2>로그 수집 상태</h2>
        {render_ingest(snapshot.get("ingest"), event_range)}
      </section>
      <section class="panel rp-appx-area" id="rp-facts">
        <h2>기간 집계 사실</h2>
        {facts_html}
      </section>
      <section class="panel rp-raw rp-appx-area" id="rp-raw">
        <h2>감사용 전체 근거</h2>
        {render_raw(snapshot)}
      </section>
      <section class="panel rp-appx-area" id="rp-footnotes">
        <h2>각주와 집계 기준</h2>
        <details class="rp-fold"><summary>숫자를 잘못 읽기 쉬운 {len(DEFINITIONS)}개 항목의 정의 보기</summary>
        <ul class="rp-defs">{footnotes}</ul></details>
      </section>
      <p class="rp-end">— 보고서 끝 —</p>
    </div>
    <aside class="rp-rail">
      <section class="panel rp-toc-panel"><h2>보고서 목차</h2>
      <nav class="rp-toc" aria-label="보고서 내 이동">{toc}</nav></section>
      <section class="panel" id="rp-archive"><h2>지난 보고서</h2>{"".join(history_sections)}</section>
    </aside></div>
    </div>
    <script>(()=>{{const view=document.querySelector(".rp-view"),head=view&&view.querySelector(".rp-head");if(!head)return;const sync=()=>view.style.setProperty("--rp-head-h",head.offsetHeight+"px");sync();if(window.ResizeObserver)new ResizeObserver(sync).observe(head);else addEventListener("resize",sync);}})();</script>
    """


EXPORT_CSS = """
:root{color-scheme:light;--bg:#fff;--sunken:#f4f4f2;--surface:#fff;--raised:#fff;--line:#bbb;--line-soft:#dedede;
--text:#111;--text-2:#2b2b2b;--text-3:#4a4a4a;--accent:#222;--on-accent:#fff;--ok:#1f5a24;--danger:#8f1d31;--warn:#6b4700;
--source-erp:#1d5aa8;--source-caddy:#6b46b5;--source-gateway:#0f7a55;--source-waf:#96396e;
--text-rgb:17 17 17;--accent-rgb:34 34 34;--ok-rgb:31 90 36;--danger-rgb:143 29 49;--warn-rgb:107 71 0;
--sev-critical:#8f1d31;--sev-high:#a63a14;--sev-medium:#6b4700;--sev-low:#4a4a4a;--sev-info:#4a4a4a;
--radius:6px;--radius-sm:4px;--shadow:none;--ease:ease}
body{margin:0;padding:24px;background:#fff;color:#111;font:14px/1.6 system-ui,"Malgun Gothic","Apple SD Gothic Neo",sans-serif}
.panel{background:#fff;border:1px solid #bbb;border-radius:6px;padding:16px 18px}
h1,h2,h3,h4{color:#111;margin:0 0 6px}h2{font-size:16px}
a{color:#0b4a9c}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #dedede}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.sev{display:inline-flex;align-items:center;gap:6px;font-weight:600;font-size:12px;white-space:nowrap}
.sev-critical,.sev-high{color:var(--sev-critical)}.sev-medium{color:var(--sev-medium)}
.btn-ghost,.range-chip{display:none}
.rp-scope,.rp-save{display:none!important}
.rp-view[data-scope="summary"] .rp-appx-area,.rp-view[data-scope="summary"] .rp-appx-head{display:none!important}
.rp-view{max-width:1000px;margin:0 auto}
.rp-period,.rp-jump,.rp-rail,.rp-print,.rp-actions,.rp-cell-link,.rp-fu-form,.rp-fu-add,.rp-readout,.rp-tip,.rp-cross{display:none!important}
.rp-workspace{display:block}.rp-head{position:static}.rp-draft-note{display:block!important;margin:0 0 12px;padding:8px 12px;border:2px solid #000;font-weight:700;text-align:center}
details:not([open])>:not(summary){display:block}
"""


def standalone_page(title, body, scope="summary"):
    """내려받는 독립 HTML 한 장. 대시보드 없이 열려도 모양이 유지되도록 필요한 색과 기본 스타일을 안에 담는다.
    scope 가 summary 면 부록을 감춘 요약본, full 이면 부록까지 모두 담는다."""
    body = body.replace("<details", "<details open")
    body = body.replace('data-scope="summary"', f'data-scope="{"full" if scope == "full" else "summary"}"', 1)
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)}</title><style>{EXPORT_CSS}</style></head><body>{body}</body></html>')
