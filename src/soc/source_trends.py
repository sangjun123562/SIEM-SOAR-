"""Shared period and collection-mode scope for source metrics, charts and logs."""
import html
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode


def source_scope(store, kind, query=None, now=None):
    from .dashboard import _bk_json_attr, _parse_utc
    from .access_time import night_bands
    query = query or {}
    now = now or datetime.now(timezone.utc)
    period = query.get('range', '24h')
    if period not in {'1h', '24h', '7d'}:
        period = '24h'
    duration = {'1h': timedelta(hours=1), '24h': timedelta(hours=24), '7d': timedelta(days=7)}[period]
    start, end = now-duration, now
    selected = False
    if query.get('from') and query.get('to'):
        a, b = _parse_utc(query['from']), _parse_utc(query['to'])
        if a and b and a < b and b-a <= timedelta(days=7):
            start, end, selected = a, b, True
    mode = query.get('mode', 'all')
    if mode not in {'all', 'live', 'replay', 'synthetic'}:
        mode = 'all'
    source = 'caddy' if kind == 'waf' else kind
    types = {'erp': ('login_success','login_failed','login_source_denied','login_blocked','logout'),
             'gateway': ('fw_allow','fw_deny'), 'waf': ('waf_detected','waf_blocked')}.get(kind)
    events = []
    offset = 0
    while True:
        batch = store.list_recent_events(limit=1000, offset=offset, source=source, event_types=types,
                                         since_utc=start, until_utc=end)
        events.extend(e for e in batch if mode=='all' or e.get('ingest_mode')==mode)
        if len(batch) < 1000:
            break
        offset += len(batch)
    # WAF decisions are separate from HTTP access logs and must not inflate request counts.
    if kind == 'caddy':
        events = [e for e in events if e.get('event_type') not in {'waf_detected','waf_blocked'}]
    settings = {
        'erp': ('로그인 성공 · 실패 추이', [('success','로그인 성공','var(--text-3)'),('failure','로그인 실패','var(--danger)')]),
        'gateway': ('허용 · 차단 추이', [('allow','허용','var(--text-3)'),('deny','차단','var(--danger)')]),
        'caddy': ('웹 요청 · 응답 추이', [('requests','전체 요청','var(--text-3)'),('client_error','4xx 응답','var(--warn)'),('server_error','5xx 응답','var(--danger)')]),
        'waf': ('WAF 탐지 · 차단 추이', [('detected','탐지 후 통과','var(--warn)'),('blocked','차단','var(--danger)')]),
    }
    title, series = settings[kind]
    kst = timezone(timedelta(hours=9))
    count = 28 if period == '7d' and not selected else 24
    step = (end-start)/count
    rows=[]
    for i in range(count):
        a, b = start+step*i, start+step*(i+1)
        local=a.astimezone(kst)
        qs={'range':period,'mode':mode,'from':a.isoformat(),'to':b.isoformat()}
        rows.append({'t': local.strftime('%m-%d %H시' if period=='7d' else '%H:%M'),
                     'span': f'{local:%m-%d %H:%M} ~ {b.astimezone(kst):%H:%M} KST',
                     'start':a.timestamp(), 'end':b.timestamp(),
                     'href':f'/logs/{kind}?'+urlencode(qs), **{key:0 for key,_,_ in series}})
    for e in events:
        stamp=_parse_utc(e['event_ts_utc'])
        if not stamp or not start <= stamp < end:
            continue
        i=min(count-1,int((stamp-start)/step))
        et=e.get('event_type')
        keys=[]
        if kind=='erp':
            keys=['success'] if et=='login_success' else ['failure'] if et=='login_failed' else []
        elif kind=='gateway':
            keys=['allow'] if et=='fw_allow' else ['deny']
        elif kind=='waf':
            keys=['blocked'] if et=='waf_blocked' else ['detected']
        else:
            keys=['requests']
            code=int(e.get('status_code') or 0)
            if 400<=code<500: keys.append('client_error')
            elif code>=500: keys.append('server_error')
        for key in keys: rows[i][key]+=1
    modes={'all':'전체 기록','live':'실시간','replay':'조사용','synthetic':'합성 시험'}
    scope=f'{start.astimezone(kst):%m-%d %H:%M} ~ {end.astimezone(kst):%m-%d %H:%M} KST · {modes[mode]}'
    options=''.join(f'<option value="{v}"{" selected" if v==period else ""}>{label}</option>' for v,label in [('1h','최근 1시간'),('24h','최근 24시간'),('7d','최근 7일')])
    mode_options=''.join(f'<option value="{v}"{" selected" if v==mode else ""}>{label}</option>' for v,label in modes.items())
    controls=(f'<form method="get" action="/logs/{kind}" class="source-scope">'
              f'<label>조회 기간 <select name="range">{options}</select></label>'
              f'<label>수집 방식 <select name="mode">{mode_options}</select></label>'
              '<button class="btn-ghost" type="submit">적용</button>'
              + (f'<a class="btn-ghost" href="/logs/{kind}?{html.escape(urlencode({"range":period,"mode":mode}))}">시간 선택 해제</a>' if selected else '')
              + f'<span class="muted">{html.escape(scope)}</span></form>')
    totals=' · '.join(f'{label} {sum(r[key] for r in rows):,}건' for key,label,_ in series)
    chart=(f'<div class="bk-chart" id="bk-source-{kind}" data-chart="{_bk_json_attr({"rows":rows,"height":160,"nightBands":night_bands(start,start+step*(count-1)),"series":[{"key":k,"label":l,"color":c} for k,l,c in series]})}"></div>'
           if events else '<p class="empty">해당 기간 기록 없음</p>')
    note={'erp':'로그인 실패는 비밀번호 인증 실패입니다. 잠금·출발지 거부는 별도 목록에서 확인합니다.',
          'gateway':'패킷 기록 건수이며 사용자 수나 접속 세션 수와 다릅니다.',
          'caddy':'4xx에는 정상적인 권한 거부와 입력 오류도 포함됩니다. 공격 건수를 뜻하지 않습니다.',
          'waf':'탐지 후 통과와 실제 차단은 별도 판정입니다.'}[kind]
    table = '<details class="src-hourly"><summary>시간별 수치 · 로그 조회</summary><table><thead><tr><th>시간 (KST)</th>' + ''.join(f'<th>{label}</th>' for _,label,_ in series) + '</tr></thead><tbody>'
    table += ''.join('<tr><td><a href="'+html.escape(r['href'])+'">'+html.escape(r['span'])+'</a></td>' + ''.join(f'<td>{r[key]:,}</td>' for key,_,_ in series) + '</tr>' for r in rows)
    table += '</tbody></table></details>'
    panel=f'<section class="panel"><div class="panel-header"><div><h2>{title}</h2><div class="panel-sub">{totals}</div></div><span class="muted" style="font-size:11px;display:inline-flex;align-items:center;gap:5px;"><i style="width:12px;height:10px;background:rgb(var(--accent-rgb) / .09);border:1px solid var(--line);"></i>심야 23:00–07:00</span></div>{chart}<div class="panel-sub">{note} · 시간 구간을 누르면 해당 로그를 조회합니다.</div>{table if events else ""}</section>'
    # Values used by download buttons follow precisely the same frozen period.
    attrs=f'<div id="source-export-scope" data-from="{start.isoformat()}" data-to="{end.isoformat()}" data-mode="{mode}" hidden></div>'
    return events, controls+attrs, panel
