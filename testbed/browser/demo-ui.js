// localhost:18888 입구가 ERP 로그인 화면 끝에 붙이는 시연 보조 스크립트.
// server.cjs가 앞에 `const DEMO_CONFIG={passwords,terminals,selected,cookie};`를 넣는다. ERP 원본 화면 파일은 바꾸지 않는다.
(() => {
  const cfg = DEMO_CONFIG, $ = id => document.getElementById(id);
  const byKey = Object.fromEntries(cfg.terminals.map(t => [t.key, t]));
  let selected = byKey[cfg.selected] ? cfg.selected : 'A';
  const availability = {};

  // 1) 계정·요청 유형에 맞춰 시험 인증값 채우기(기존 동작)
  window.prepareDemoLogin = () => {
    const user = $('username').value, mode = $('auth-mode')?.value;
    $('password').value = mode === 'failure' ? 'DemoWrongPasswordOnly' : (cfg.passwords[user] || '');
  };
  $('username').addEventListener('change', window.prepareDemoLogin);
  $('auth-mode')?.addEventListener('change', window.prepareDemoLogin);
  window.prepareDemoLogin();
  $('auth-message').textContent = '계정과 접속 단말을 선택하고 로그인 버튼을 누르세요.';

  // 2) 접속 단말(IP) 선택 메뉴를 보안 시연 도구의 요청 유형 위에 추가
  const tools = $('demo-tools'), modeLabel = tools.querySelector('label[for="auth-mode"]');
  const label = document.createElement('label');
  label.htmlFor = 'demo-terminal';
  label.textContent = '접속 단말(IP)';
  const select = document.createElement('select');
  select.id = 'demo-terminal';
  for (const t of cfg.terminals) {
    const option = document.createElement('option');
    option.value = t.key;
    select.append(option);
  }
  const hint = document.createElement('p');
  hint.id = 'demo-terminal-hint';
  tools.insertBefore(label, modeLabel);
  tools.insertBefore(select, modeLabel);
  tools.insertBefore(hint, modeLabel);
  tools.open = true;

  // 상단 띠에 현재 접속 단말 표시(로그인 후에도 보임)
  const badge = document.createElement('strong');
  badge.id = 'demo-terminal-badge';
  badge.style.marginLeft = '10px';
  badge.style.color = '#2e5ba5';
  document.querySelector('.strip')?.append(badge);

  const save = key => { document.cookie = cfg.cookie + '=' + key + '; path=/; max-age=43200; SameSite=Strict'; };
  function render() {
    for (const option of select.options) {
      const t = byKey[option.value], down = availability[t.key] === false;
      option.textContent = t.label + ' · ' + t.ip + (down ? ' (실행 중 아님)' : '');
      option.disabled = down && t.key !== selected;
    }
    select.value = selected;
    const t = byKey[selected];
    hint.textContent = availability[selected] === false ? t.label + '가 실행 중이 아닙니다. ' + t.startHint : t.note + ' 관제에는 출발지 ' + t.ip + '로 기록됩니다.';
    hint.style.color = availability[selected] === false ? '#a34b43' : '';
    badge.textContent = '· 접속 단말 ' + t.key + ' (' + t.ip + ')';
  }
  async function refresh() {
    try {
      const response = await fetch('/demo-terminals', {cache: 'no-store'});
      const data = await response.json();
      for (const t of data.terminals || []) availability[t.key] = t.available;
    } catch { /* 목록 확인 실패는 서버의 요청 단계 검사로 처리한다 */ }
    render();
  }
  select.addEventListener('change', () => { selected = select.value; save(selected); render(); refresh(); });
  select.addEventListener('focus', refresh);
  save(selected);
  render();
  refresh();

  // 3) 꺼진 단말로는 로그인 요청을 보내지 않는다(서버도 같은 검사를 한다)
  const warn = message => {
    if (typeof notify === 'function') notify(message, 'error');
    $('auth-message').className = '';
    $('auth-message').textContent = message;
  };
  document.addEventListener('submit', event => {
    if (event.target.id !== 'login-form' || availability[selected] !== false) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    warn(byKey[selected].label + '가 실행 중이 아닙니다. ' + byKey[selected].startHint);
  }, true);

  // 서버가 단말 문제로 요청을 거부하면 ERP 기본 문구 대신 이유를 보여준다
  const originalFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await originalFetch(...args);
    if (response.status === 503) {
      response.clone().json().then(data => {
        if (data && data.error === 'terminal_unavailable') { setTimeout(() => warn(data.message), 80); refresh(); }
      }).catch(() => {});
    }
    return response;
  };
})();
