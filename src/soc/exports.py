"""Authenticated, local downloads for investigation records."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlencode


def export_controls(path: str) -> str:
    if path == '/reports' or path == '/permissions':
        return ''
    if path == '/':
        buttons = '<button type="button" class="export-button" title="현재 개요를 PDF로 저장" onclick="printSocPage()">PDF 저장</button>'
    elif path.startswith('/incidents/'):
        buttons = '<button type="button" class="export-button" title="사건 상세를 PDF로 저장" onclick="printSocPage()">PDF 저장</button><button type="button" class="export-button" title="사건 근거와 원본 로그를 JSON으로 저장" onclick="downloadSoc(\'incident\')">JSON 저장</button>'
    elif path == '/incidents':
        buttons = '<button type="button" class="export-button" title="검색 조건에 맞는 전체 사건을 CSV로 저장" onclick="downloadSoc(\'incidents\')">CSV 저장</button>'
    elif path == '/events' or path.startswith('/logs/'):
        buttons = '<button type="button" class="export-button" title="검색 조건에 맞는 전체 로그를 CSV로 저장" onclick="downloadSoc(\'events\')">CSV 저장</button>'
    else:
        return ''
    return '<div class="export-actions" aria-label="자료 저장">' + buttons + '</div>'


UI = r'''<style>
.export-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-left:auto}
.export-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.export-button{font:inherit;font-size:12px;font-weight:500;line-height:1.2;min-height:30px;background:transparent;color:var(--text-2);border:1px solid var(--line);border-radius:var(--radius-sm);padding:6px 9px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
@media(hover:hover){.export-button:hover{background:var(--raised);color:var(--text)}}
.export-button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.export-button:active{opacity:.7}.export-note{font-size:11px;color:var(--text-3)}
.print-stamp{display:none}
@media(pointer:coarse){.export-button{min-height:44px}}
@media print{
@page{size:A4 landscape;margin:12mm}
html,body{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important;background:var(--bg)!important;color:var(--text)!important}
body,.app,.layout,.content{display:block!important;width:auto!important;margin:0!important;padding:0!important;background:var(--bg)!important;color:var(--text)!important}
.sidebar,.topbar,.foot,.export-actions,.export-button,.pop-overlay,button,form,.filter-chip-bar{display:none!important}
.panel,.mini-card,.stat-card{box-shadow:none!important;break-inside:avoid;border:1px solid var(--line)!important;background:var(--surface)!important;color:var(--text)!important}
details>*:not(summary){display:block!important} .print-stamp{display:block!important;font-size:11px;margin-bottom:12px}
table{width:100%!important}th,td{color:var(--text)!important;border-color:var(--line)!important}a{color:var(--accent)!important}
body.print-flow .content>*:not(.print-stamp):not(.panel){display:none!important}
body.print-flow .panel>*:not(.request-feed){display:none!important}
body.print-flow .request-feed>*:not(.print-selected){display:none!important}
body.print-flow .request-card{background:var(--surface)!important;color:var(--text)!important}
}
</style><script>
function downloadSoc(kind, requestId, rawId){
 var p=new URLSearchParams(location.search);p.delete('page');p.set('kind',kind);
 var search=document.getElementById('socSearchBox');if(search&&search.value)p.set('q',search.value);
 if(typeof activeEventChip!=='undefined')p.set('chip',activeEventChip);
 if(location.pathname.startsWith('/logs/'))p.set('source',location.pathname.split('/').pop());
 var scope=document.getElementById('source-export-scope');if(scope){p.set('from',scope.dataset.from);p.set('to',scope.dataset.to);p.set('mode',scope.dataset.mode)}
 if(location.pathname.startsWith('/incidents/'))p.set('id',decodeURIComponent(location.pathname.split('/').pop()));
 if(requestId)p.set('request_id',requestId);if(rawId)p.set('raw_id',rawId);
 location.href='/exports?'+p.toString();
}
function printSocPage(){
 var stamp=document.querySelector('.print-stamp');
 if(!stamp){stamp=document.createElement('div');stamp.className='print-stamp';document.querySelector('main').prepend(stamp)}
 stamp.textContent=document.title+' · 추출 '+new Date().toLocaleString('ko-KR')+' · '+location.pathname+location.search;
 document.querySelectorAll('details').forEach(function(d){d.dataset.printOpen=d.open?'1':'0';d.open=true});
 window.print();
}
function printSocFlow(button){document.body.classList.add('print-flow');button.closest('.request-card').classList.add('print-selected');printSocPage()}
window.addEventListener('afterprint',function(){document.body.classList.remove('print-flow');document.querySelectorAll('.print-selected').forEach(function(e){e.classList.remove('print-selected')});document.querySelectorAll('details[data-print-open]').forEach(function(d){d.open=d.dataset.printOpen==='1';delete d.dataset.printOpen})});
document.addEventListener('DOMContentLoaded',function(){
 var actions=document.querySelector('.export-actions');var head=document.querySelector('.page-head');
 if(!head&&location.pathname.startsWith('/incidents/')){var back=document.querySelector('main a[href="/incidents"]');if(back)head=back.parentElement}
 if(actions&&head){head.classList.add('export-heading');head.append(actions)}
 document.querySelectorAll('h2,h3,h4').forEach(function(h){if(h.textContent.includes('조치 이력')||h.textContent.includes('감사 이력')){
 var b=document.createElement('button');b.type='button';b.className='export-button';b.textContent='CSV 저장';b.title='조치 이력을 CSV로 저장';b.style.marginLeft='10px';b.onclick=function(){downloadSoc('actions')};h.append(b)
 }});
});
</script>'''


def _time(value):
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _csv(rows, metadata):
    out = io.StringIO(newline='')
    keys = list(dict.fromkeys(k for row in rows for k in row))
    fields = list(metadata) + keys
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    def safe(v):
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False, default=str)
        # Spreadsheet formula injection also applies to attacker-controlled account names.
        if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')):
            return "'" + v
        return v
    for row in rows or [{}]:
        writer.writerow({k: safe(v) for k, v in (metadata | row).items()})
    return out.getvalue().encode('utf-8-sig')


def build_export(store, query):
    from .dashboard import _incident_severity, _incident_type, _is_suspect_event
    kind = query.get('kind', 'events')
    now = datetime.now(timezone.utc).isoformat()
    metadata = {'추출시각_UTC': now, '조회조건': urlencode(query), '시간기준': 'UTC'}
    if kind in {'incidents', 'actions', 'incident'}:
        incidents = store.list_incidents()
        if query.get('id'):
            incidents = [i for i in incidents if i.incident_id == query['id']]
        if kind == 'incident':
            if not incidents:
                raise LookupError('사건을 찾을 수 없습니다.')
            data = {'metadata': metadata, 'incident': asdict(incidents[0])}
            return 'incident.json', 'application/json; charset=utf-8', json.dumps(data, ensure_ascii=False, default=str, indent=2).encode()
        incidents = [i for i in incidents if
                     (not query.get('status') or i.status == query['status']) and
                     (not query.get('severity') or _incident_severity(i) == query['severity']) and
                     (not query.get('type') or _incident_type(i) == query['type'])]
        if kind == 'actions':
            rows = [{'사건_ID': i.incident_id, **asdict(a)} for i in incidents for a in i.approvals]
        else:
            rows = [{'사건_ID': i.incident_id, '제목': i.title, '상태': i.status, '심각도': _incident_severity(i),
                     '유형': _incident_type(i), 'IP': i.target_ip, '계정': i.username,
                     '발생시각_UTC': i.created_at_utc, '수정시각_UTC': i.updated_at_utc,
                     '근거_건수': len(i.evidence_events)} for i in incidents]
    elif kind in {'events', 'flow'}:
        since, until = _time(query.get('from')), _time(query.get('to'))
        if since and until and since >= until:
            raise ValueError('시작 시각은 종료 시각보다 빨라야 합니다.')
        rows = []
        offset = 0
        # Freeze the upper time boundary to prevent new arrivals from moving pages.
        until = until or datetime.fromisoformat(now)
        while True:
            batch = store.list_recent_events(limit=1000, offset=offset, since_utc=since, until_utc=until)
            rows.extend(batch)
            if len(batch) < 1000:
                break
            offset += len(batch)
        def suspect(e):
            return _is_suspect_event(e.get('source', ''), e.get('event_type', ''), e.get('outcome', ''), e.get('status_code'), e.get('http_path') or '')
        counts = Counter(e.get('request_id') for e in rows if e.get('source') in {'erp','caddy'} and e.get('request_id'))
        bad_requests = {e.get('request_id') for e in rows if suspect(e) and e.get('request_id')}
        chip = query.get('chip', 'all')
        rows = [e for e in rows if
                (not query.get('source') or e.get('source') == query['source'] or (query['source']=='waf' and e.get('event_type') in {'waf_detected','waf_blocked'})) and
                (chip not in {'erp','caddy','gateway'} or e.get('source') == chip) and
                (chip != 'flow' or counts[e.get('request_id')] > 1) and
                (not (chip=='anomaly' or query.get('anomaly')=='1') or suspect(e) or e.get('request_id') in bad_requests)]
        if query.get('mode') in {'live','replay','synthetic'}:
            rows = [e for e in rows if e.get('ingest_mode') == query['mode']]
        if query.get('source') == 'erp':
            rows = [e for e in rows if e.get('event_type') in {'login_success','login_failed','login_source_denied','login_blocked','logout'}]
        elif query.get('source') == 'caddy':
            rows = [e for e in rows if e.get('event_type') not in {'waf_detected','waf_blocked'}]
        if kind == 'flow':
            rows = [e for e in rows if (query.get('request_id') and e.get('request_id')==query['request_id']) or
                    (not query.get('request_id') and query.get('raw_id') and e.get('raw_id')==query['raw_id'])]
            raw = []
            if hasattr(store, 'repo'):
                for e in rows:
                    raw.extend(store.repo._fetchall('SELECT raw_id, raw_payload FROM raw_logs WHERE raw_id = ?', (e['raw_id'],)))
            data = {'metadata': metadata, 'count': len(rows), 'events': rows, 'raw_logs': [{'raw_id': r[0], 'raw_payload': r[1]} for r in raw]}
            return 'flow.json', 'application/json; charset=utf-8', json.dumps(data, ensure_ascii=False, default=str, indent=2).encode()
    else:
        raise ValueError('지원하지 않는 저장 형식입니다.')
    search = query.get('q', '').strip().casefold()
    if search:
        rows = [r for r in rows if search in json.dumps(r, ensure_ascii=False, default=str).casefold()]
    metadata['전체_건수'] = len(rows)
    return kind + '.csv', 'text/csv; charset=utf-8', _csv(rows, metadata)
