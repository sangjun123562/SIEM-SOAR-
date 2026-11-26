'use strict';
const crypto = require('crypto');
const cp = require('child_process');
const {promisify} = require('util');
const execFile = promisify(cp.execFile);
const ORIGINS = new Set(['http://127.0.0.1:8050', 'http://localhost:8050']);
function equal(a,b) {
  const x=Buffer.from(String(a)), y=Buffer.from(String(b));
  return x.length===y.length && crypto.timingSafeEqual(x,y);
}
function authorize(headers, form, config, now=Math.floor(Date.now()/1000)) {
  if (!config.enabled || !ORIGINS.has(headers.origin)) return false;
  if (new URL(headers.origin).hostname !== String(headers.host||'').split(':')[0]) return false;
  const token=String(headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('soc_session='))?.slice(12);
  if (!token) return false;
  let user,expiry,sig;
  try { [user,expiry,sig]=Buffer.from(token,'base64url').toString('utf8').split('|'); } catch { return false; }
  if (!(config.admins||[config.username]).includes(user) || !/^\d+$/.test(expiry||'') || Number(expiry)<now) return false;
  const sign=s=>crypto.createHmac('sha256',config.secret).update(s).digest('hex');
  return equal(sig,sign(`${user}|${expiry}`)) && equal(form.get('csrf_token')||'',sign(`csrf|${token}`)) && form.get('confirm')==='reset-practice-logs';
}
function createHandler(dockerBin, execute=execFile) {
  let busy=false;
  const docker=async (...args)=> {
    try { return (await execute(dockerBin,args,{windowsHide:true,timeout:30000,maxBuffer:1024*1024})).stdout.trim(); }
    catch { throw Error('Docker 작업 실패. 초기화가 완료되지 않았습니다.'); }
  };
  const sql=q=>docker('exec','capstone-soc-postgres','psql','-U','soc_admin','-d','soc_db','-v','ON_ERROR_STOP=1','-Atc',q);
  const resetErpLoginState=()=>docker('exec','capstone-a-erp-db','psql','-U','erp_app','-d','erp_db','-v','ON_ERROR_STOP=1','-Atc',`
    BEGIN;
    SELECT id FROM users ORDER BY id FOR UPDATE;
    UPDATE account_locks
       SET unlocked_at=clock_timestamp(), unlocked_by='practice-reset', unlock_reason='연습 기록 초기화'
     WHERE unlocked_at IS NULL AND expires_at>clock_timestamp();
    DELETE FROM login_failures_by_ip;
    COMMIT;
  `);
  async function reset() {
    const expected={'capstone-soc-dashboard':'capstone-soc','capstone-soc-collector':'capstone-soc','capstone-soc-postgres':'capstone-soc','capstone-a-gateway':'capstone-a','capstone-a-caddy':'capstone-a','capstone-a-caddy-log':'capstone-a','capstone-a-erp':'capstone-a','capstone-a-erp-db':'capstone-a'};
    const infos=JSON.parse(await docker('inspect',...Object.keys(expected)));
    if(infos.some(x=>x.Config.Labels['com.docker.compose.project']!==expected[x.Name.slice(1)] || !x.State.Running)) throw Error('캡스톤 서비스 상태를 먼저 확인하세요.');
    try {
      await sql("DELETE FROM collector_offsets WHERE source='__practice_reset'; INSERT INTO collector_offsets(source,file_path,byte_offset) VALUES ('__practice_reset','maintenance',extract(epoch from now())::bigint+180) ON CONFLICT(source,file_path) DO UPDATE SET byte_offset=EXCLUDED.byte_offset");
      let acknowledged=false;
      for(let attempt=0;attempt<25;attempt++) {
        const ready=await sql("SELECT count(*) FROM collector_offsets a JOIN collector_offsets m ON a.source=m.source WHERE a.source='__practice_reset' AND a.file_path='collector-paused' AND m.file_path='maintenance' AND a.byte_offset=m.byte_offset");
        if(Number(ready)===1){acknowledged=true;break;}
        await new Promise(resolve=>setTimeout(resolve,200));
      }
      if(!acknowledged) throw Error('수집기가 대기 상태를 확인하지 못했습니다. 기록은 초기화하지 않았습니다.');
      if(Number(await sql("SELECT count(*) FROM action_approvals WHERE status IN ('pending','unknown') OR (status='applied' AND expires_at_utc>now())"))!==0) throw Error('활성·대기·불확실 승인이 있습니다. 먼저 해제·상태 확인하세요.');
      const rules=await docker('exec','capstone-a-gateway','iptables','-S','GW_BLOCK');
      if(rules.split('\n').some(line=>line.startsWith('-A '))) throw Error('실제 차단 규칙이 남아 있습니다. 먼저 해제하세요.');
      // Drain the short Caddy conversion queue before taking the normalized-file EOF.
      let drained=false;
      for(let attempt=0;attempt<10;attempt++) {
        const ready=await docker('exec','capstone-a-caddy-log','sh','-c','raw=$(stat -c %s /in/access.json 2>/dev/null || echo 0); offset=$(cat /out/caddy.offset 2>/dev/null || echo 0); waf_raw=$(stat -c %s /in/waf.jsonl 2>/dev/null || echo 0); waf_offset=$(cat /out/waf.offset 2>/dev/null || echo 0); if [ "$raw" = "$offset" ] && [ "$waf_raw" = "$waf_offset" ]; then printf 1; else printf 0; fi');
        if(ready==='1'){drained=true;break;}
        await new Promise(resolve=>setTimeout(resolve,200));
      }
      if(!drained) throw Error('Caddy 로그 변환이 진행 중입니다. 잠시 후 다시 시도하세요.');
      // Clear ERP state first so a failed reset cannot discard the only unlock link.
      try { await resetErpLoginState(); }
      catch { throw Error('ERP 로그인 상태를 초기화하지 못했습니다. 관제 기록은 유지합니다.'); }
      await sql("INSERT INTO collector_offsets(source,file_path,byte_offset) SELECT '__practice_reset','reset-request',byte_offset FROM collector_offsets WHERE source='__practice_reset' AND file_path='maintenance'");
      let completed=false;
      for(let attempt=0;attempt<30;attempt++) {
        const status=await sql("SELECT CASE WHEN EXISTS(SELECT 1 FROM collector_offsets s JOIN collector_offsets m ON s.byte_offset=m.byte_offset WHERE s.source='__practice_reset' AND s.file_path='reset-failed' AND m.source='__practice_reset' AND m.file_path='maintenance') THEN 'failed' WHEN EXISTS(SELECT 1 FROM collector_offsets s JOIN collector_offsets m ON s.byte_offset=m.byte_offset WHERE s.source='__practice_reset' AND s.file_path='reset-done' AND m.source='__practice_reset' AND m.file_path='maintenance') THEN 'done' ELSE 'waiting' END");
        if(status==='failed') throw Error('ERP 로그인 상태는 초기화했지만 관제 기록 초기화에 실패했습니다.');
        if(status==='done'){completed=true;break;}
        await new Promise(resolve=>setTimeout(resolve,100));
      }
      if(!completed) throw Error('초기화 완료 응답을 확인하지 못했습니다. 현재 상태를 확인하세요.');
    } finally {
      // Cooperative collector resumes without a container or web-service restart.
      await sql("DELETE FROM collector_offsets WHERE source='__practice_reset'");
    }
  }

  async function handle(req,res) {
    if(req.url!=='/practice-reset') return false;
    const started=Date.now();
    const reply=(status,message)=>{res.writeHead(status,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff',...(ORIGINS.has(req.headers.origin)?{'access-control-allow-origin':req.headers.origin,'access-control-allow-credentials':'true','vary':'Origin'}:{})});res.end(`<!doctype html><html lang="ko"><meta charset="utf-8"><title>연습 로그 초기화</title><body style="background:#101827;color:#fff;font-family:sans-serif;padding:48px"><h1>${message}</h1><p>원본 로그 파일·ERP 계정·코드·공식 자료·기존 백업은 유지합니다.</p><a style="color:#67e8f9" href="${ORIGINS.has(req.headers.origin)?req.headers.origin:'http://127.0.0.1:8050'}/">대시보드로 돌아가기</a></body></html>`);};
    if(req.method!=='POST'||!ORIGINS.has(req.headers.origin)){reply(403,'허용되지 않은 초기화 요청입니다.');return true;}
    if(busy){reply(409,'초기화가 이미 진행 중입니다.');return true;}
    let body='';
    for await(const chunk of req){body+=chunk; if(Buffer.byteLength(body)>4096){reply(413,'요청이 너무 큽니다.');return true;}}
    let config;
    try { const [info]=JSON.parse(await docker('inspect','capstone-soc-dashboard'));
      const env=Object.fromEntries(info.Config.Env.map(entry=>{const at=entry.indexOf('=');return [entry.slice(0,at),entry.slice(at+1)];}));
      config={enabled:env.SOC_ENABLE_PRACTICE_RESET==='1',admins:String(env.SOC_ADMIN_USERS||((env.SOC_OPERATOR_USER||'soc-operator')+',admin1')).split(',').map(x=>x.trim()).filter(Boolean),secret:env.SOC_SESSION_SECRET}; }
    catch {reply(503,'초기화 설정을 확인할 수 없습니다.');return true;}
    if(!authorize(req.headers,new URLSearchParams(body),config)){reply(403,'담당자 로그인 또는 요청 검증에 실패했습니다.');return true;}
    if(busy){reply(409,'초기화가 이미 진행 중입니다.');return true;}
    busy=true;
    try {await reset();reply(200,'관제 기록과 ERP 로그인 상태를 초기화했습니다. ('+((Date.now()-started)/1000).toFixed(1)+'초)');}
    catch(e) {reply(503,e.message);}
    finally {busy=false;}
    return true;
  }
  return {handle,isBusy:()=>busy};
}
module.exports={authorize,createHandler};
