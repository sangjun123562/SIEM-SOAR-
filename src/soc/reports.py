"""Weekly SOC reports with immutable finalized snapshots."""
import html
import json
from datetime import date, datetime, time, timedelta, timezone
from urllib.parse import quote, urlencode

from .repository import SocRepository

KST = timezone(timedelta(hours=9))
# summary 는 사람이 쓰는 결론이다. 기계가 만든 사실 문장은 notes 에 저장하지 않는다.
FIELDS = (("summary", "핵심 판단"), ("assessment", "판단 근거"),
          ("followup", "후속 확인"), ("opinion", "담당자 의견"))
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
    ("차단으로 막은 접속 시도", "차단 유효 시간의 게이트웨이 기록으로 집계한 접속 시도입니다. 같은 연결의 재전송은 한 번으로 세며, 공격자 수나 피해 규모가 아닙니다."),
)
BLOCK_DONE = frozenset({"applied", "released", "expired"})
BLOCK_SETTLED = BLOCK_DONE | {"rejected"}
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
            finally:
                cur.close()
        self._run_db(create)

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


def weekly_snapshot(incidents, week, parse_time, auto_rule, effects_for=None, *, kind="weekly"):
    start = datetime.combine(week, time.min, KST)
    end = datetime.combine(period_end(week, kind), time.min, KST)

    def in_week(value):
        stamp = parse_time(value)
        return stamp is not None and start <= stamp < end

    cases = []
    blocks = []
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
    now = datetime.now(KST)
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
            "open": {"action": open_action, "review": open_review, "oldest_days": oldest_open},
            "unsettled": unsettled, "effect": effect, "replay_alerts": replay_alerts,
            "generated_at": now.isoformat(timespec="seconds"),
            "cases": cases, "daily": daily}


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
@media (max-width:1100px) {
  .rp-workspace {grid-template-columns:minmax(0,1fr)}
  .rp-rail {position:static;order:99}
  .rp-rail .rp-toc-panel {display:none}
  .rp-jump {display:flex}
}
@media (max-width:700px) {
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
  .rp-view form button {display:none !important}
  .rp-view, .rp-view .panel {background:#fff !important;color:#111 !important;
    border-color:#bbb !important;box-shadow:none !important}
  .rp-cell-sub, .rp-trust, .rp-list-meta, .rp-metrics dt {color:#444 !important}
  .rp-machine {background:#f4f4f4 !important;border-left-color:#666 !important}
  .rp-workspace {display:block !important}
  .rp-head {position:static !important}
  details:not([open]) > :not(summary) {display:block !important}
  .rp-plot-scroll {overflow:visible !important}
  .rp-plot {min-width:0 !important}
  .rp-bars span, .rp-strip, .rp-cell {print-color-adjust:exact;-webkit-print-color-adjust:exact}
  .rp-cell[data-state="unknown"], .rp-cell[data-impact="hit"]
    {box-shadow:none !important;border-left:3px solid #000 !important}
  .panel, .rp-strip, .rp-cell, .rp-machine, .rp-chart, thead, tr {break-inside:avoid}
  h2, h3 {break-after:avoid}
  .rp-main {display:flex;flex-direction:column}
  #rp-now {order:1} #rp-writing {order:2} #rp-detect {order:3}
  #rp-evidence {order:4} #rp-footnotes {order:5}
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


def report_body(week, report, snapshot, history, csrf, editable, message="", *, kind="weekly"):
    esc = html.escape
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

    # --- S0 Band C : 신뢰 띠. "없음"을 적극적으로 쓴다. 침묵은 확인 안 함으로 읽힌다. ---
    unknown_count = 1 if effect["state"] == "unknown" else 0
    generated = snapshot.get("generated_at", "")
    trust = [
        f'집계 불가 <b>{unknown_count}개</b>' if unknown_count else "집계 불가 없음",
        f'미확정 차단 <b>{_fmt(unsettled_total)}건</b>' if unsettled_total else "미확정 차단 0건",
        f'재생·합성 근거 경보 <b>{_fmt(snapshot["replay_alerts"])}건</b>' if snapshot.get("replay_alerts")
        else "재생·합성 근거 경보 0건",
        "수집 공백 집계 미도입",
        "후속 조치 추적 미도입",
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
    sections = (("rp-now", "지금 상태", ""), ("rp-detect", "탐지 내용", ""),
                ("rp-evidence", "사건과 대응 근거", f'{_fmt(len(snapshot.get("cases", [])))}건'),
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
      <section class="panel" id="rp-detect">
        <h2>탐지 내용</h2>
        <dl class="rp-metrics">{detect_html}</dl>
        <div class="rp-sub"><h3>{'월간 구간별' if kind == 'monthly' else '일별'} 관제 추이</h3>
        {render_daily(snapshot.get("daily"), kind)}</div>
      </section>
      <section class="panel" id="rp-evidence">
        <h2>사건과 대응 근거</h2>
        <ul class="rp-list">{cases_html or "<li>선택한 기간에 신규 사건이나 관련 조치 기록이 없습니다.</li>"}</ul>
        <div class="rp-sub"><h3>로그 출처별 이벤트</h3>{sources}
        <p><a href="{event_range}">이 기간의 이벤트 열기 →</a></p></div>
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
