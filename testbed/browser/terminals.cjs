'use strict';
// 브라우저 입구에서 고를 수 있는 시험 단말 목록과 선택 쿠키 처리.
// 선택값은 localhost 쿠키로만 기억하고 ERP로 전달하지 않는다. 목록에 없는 값은 기본 단말 A로 본다.
const TERMINALS = Object.freeze({
  A: Object.freeze({key: 'A', label: '시험 단말 A', ip: '172.28.10.11', client: 'client-A', service: 'tunnel', tunnel: 'capstone-erp-ui-tunnel-1',
    note: '기본 단말입니다. 반복 실패 사건의 차단 승인 대상입니다.', startHint: '기본 시험망(testbed docker compose up -d)을 먼저 켜세요.'}),
  B: Object.freeze({key: 'B', label: '시험 단말 B', ip: '172.28.10.12', client: 'client-B', service: 'tunnel-b', tunnel: 'capstone-erp-ui-tunnel-b-1',
    note: '기본 ERP 허용 단말입니다. 반복 실패 사건의 차단 승인 대상입니다.', startHint: '기본 시험망(testbed docker compose up -d)을 먼저 켜세요.'}),
  X: Object.freeze({key: 'X', label: '시험 단말 X', ip: '172.28.10.13', client: 'capstone-a-client-x', service: 'tunnel-x', tunnel: 'capstone-erp-ui-tunnel-x-1',
    note: 'multi-ip 프로필 단말입니다. 게이트웨이 차단 대상이 아닙니다.', startHint: 'multi-ip 프로필로 client-x와 route-x를 먼저 켜세요.'}),
});
const DEFAULT_KEY = 'A';
const COOKIE = 'capstone_demo_terminal';

function cookieParts(header) {
  return String(header || '').split(';').map(part => part.trim()).filter(Boolean);
}

function selectTerminal(cookieHeader) {
  const part = cookieParts(cookieHeader).find(p => p.startsWith(COOKIE + '='));
  const value = part ? part.slice(COOKIE.length + 1) : '';
  return Object.prototype.hasOwnProperty.call(TERMINALS, value) ? value : DEFAULT_KEY;
}

function stripTerminalCookie(cookieHeader) {
  return cookieParts(cookieHeader).filter(p => !p.startsWith(COOKIE + '=')).join('; ');
}

// `docker inspect -f '{{.Name}}|{{.State.Running}}|{{.State.StartedAt}}'` 출력 → 이름별 상태.
// 없는 컨테이너는 docker가 오류로 따로 알리므로 출력에 없을 뿐이다.
function parseInspect(stdout) {
  const states = new Map();
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const [name, running, started] = line.trim().split('|');
    if (!name || running === undefined) continue;
    states.set(name.replace(/^\//, ''), {running: running === 'true', started: Date.parse(started)});
  }
  return states;
}

// 중계는 단말의 네트워크를 빌려 쓴다. 단말이 중계보다 늦게 켜졌으면 중계는 사라진 예전 네트워크에 남아 있다(stale).
function tunnelState(terminal, states) {
  const client = states.get(terminal.client), tunnel = states.get(terminal.tunnel);
  if (!client || !client.running) return 'client-down';
  if (!tunnel || !tunnel.running) return 'missing';
  return client.started > tunnel.started ? 'stale' : 'ready';
}

function watchedNames() {
  return Object.values(TERMINALS).flatMap(t => [t.client, t.tunnel]);
}

function publicList(runningNames) {
  return Object.values(TERMINALS).map(t => ({key: t.key, label: t.label, ip: t.ip, note: t.note, startHint: t.startHint,
    available: runningNames ? runningNames.has(t.client) : null}));
}

module.exports = {TERMINALS, DEFAULT_KEY, COOKIE, selectTerminal, stripTerminalCookie, parseInspect, tunnelState, watchedNames, publicList};
