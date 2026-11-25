const fs=require('fs'),path=require('path'),cp=require('child_process'),http=require('http'),https=require('https'),tls=require('tls');
const {Duplex}=require('stream');
const D=process.env.DOCKER_BIN||'docker';
const docker=(...a)=>cp.execFileSync(D,a,{encoding:'utf8',windowsHide:true,timeout:20000}).trim();
const dockerAsync=(args,timeout=30000)=>new Promise((resolve,reject)=>cp.execFile(D,args,{encoding:'utf8',windowsHide:true,timeout,cwd:ROOT},(error,stdout)=>error?reject(error):resolve(String(stdout).trim())));
const ROOT=__dirname,COMPOSE=path.join(ROOT,'compose.json');
const practiceReset=require('./practice-reset.cjs').createHandler(D);
const {TERMINALS,COOKIE,selectTerminal,stripTerminalCookie,parseInspect,tunnelState,watchedNames,publicList}=require('./terminals.cjs');
let childSet=new Set(),active=0;
// 기본 단말 A의 중계는 필수. B·X 중계는 해당 단말이 켜져 있을 때 시작하고, 없으면 처음 선택할 때 다시 시도한다.
cp.execFileSync(D,['compose','-f',COMPOSE,'up','-d','--pull','never',TERMINALS.A.service],{cwd:ROOT,windowsHide:true,stdio:'ignore',timeout:30000});
for(const key of ['B','X']){try{cp.execFileSync(D,['compose','-f',COMPOSE,'up','-d','--pull','never',TERMINALS[key].service],{cwd:ROOT,windowsHide:true,stdio:'ignore',timeout:30000});}catch{}}
const ca=docker('exec','capstone-a-caddy','cat','/data/caddy/pki/authorities/local/root.crt');
const demoPasswords=JSON.parse(docker('exec','capstone-a-erp','python','-c','import os,json; print(json.dumps({u:os.environ[k] for u,k in [("alice","DEMO_PW_ALICE"),("bob","DEMO_PW_BOB"),("carol","DEMO_PW_CAROL"),("dave","DEMO_PW_DAVE"),("erin","DEMO_PW_ERIN"),("frank","DEMO_PW_FRANK")]}))'));
const demoScript=fs.readFileSync(path.join(ROOT,'demo-ui.js'),'utf8');

// 단말·중계 컨테이너 상태(2초 캐시). 켜진 시각까지 읽어 끊긴 중계(stale)를 찾는다.
let stateCache=null;
function inspectStates(){
 return new Promise(resolve=>cp.execFile(D,['inspect','-f','{{.Name}}|{{.State.Running}}|{{.State.StartedAt}}',...watchedNames()],{encoding:'utf8',windowsHide:true,timeout:10000},(_error,stdout)=>resolve(parseInspect(stdout))));
}
async function containerStates(){
 if(stateCache&&Date.now()-stateCache.at<2000)return stateCache.states;
 const states=await inspectStates();
 stateCache={at:Date.now(),states};return states;
}
async function runningNames(){
 const states=await containerStates();
 return new Set([...states].filter(([,s])=>s.running).map(([name])=>name));
}
// 중계를 만들거나(missing) 다시 만든다(stale: 단말이 다시 켜져 중계가 예전 네트워크에 남은 경우).
const starting={};
function prepareTunnel(key,state){
 const t=TERMINALS[key];
 if(state==='stale')agents[key].reset();
 starting[key]??=dockerAsync(['compose','-f',COMPOSE,'up','-d','--pull','never',...(state==='stale'?['--force-recreate']:[]),t.service]).finally(()=>{delete starting[key];stateCache=null;});
 return starting[key];
}
async function ensureTunnel(key){
 const t=TERMINALS[key];
 const state=starting[key]?'starting':tunnelState(t,await containerStates());
 if(state==='client-down')throw Object.assign(Error(`${t.label}(${t.ip})가 실행 중이 아닙니다. ${t.startHint}`),{terminal:true});
 if(state!=='ready'){
  try{await (starting[key]||prepareTunnel(key,state));}
  catch{throw Object.assign(Error(`${t.label}(${t.ip})의 중계를 준비하지 못했습니다. 단말 상태를 확인하세요.`),{terminal:true});}
 }
 agents[key].warm();
}
// 사용자가 요청하기 전에 끊긴 중계를 찾아 다시 만든다(5초마다, docker inspect 1회).
let watching=false;
const watcher=setInterval(async()=>{
 if(watching||stopping)return;watching=true;
 try{const states=await containerStates();
  for(const key of Object.keys(TERMINALS))if(!starting[key]&&tunnelState(TERMINALS[key],states)==='stale')prepareTunnel(key,'stale').then(()=>agents[key].warm(),()=>{});}
 finally{watching=false;}
},5000);
watcher.unref();

// 중계 Python은 CPU 제한 때문에 켜지는 데 수 초가 걸린다(0.06 CPU에서 약 5초). ERP 화면은 5초만 기다리므로
// 중계 CPU를 0.15로 두고(새 연결 약 0.6초), 단말마다 미리 켜 둔 예비 중계를 하나 둔다. 예비 중계는 'G'를 받기 전까지 ERP에 접속하지 않는다(관제 기록 없음).
let stopping=false;
class TerminalAgent extends https.Agent{
 constructor(terminal,options){super(options);this.terminal=terminal;this.spare=null;}
 spawnRelay(){
  const t=this.terminal;
  const child=cp.spawn(D,['exec','-i',t.tunnel,'python','-I','/app/stdio.py',t.ip],{windowsHide:true,stdio:['pipe','pipe','ignore']});
  childSet.add(child);child.stdin.on('error',()=>{});
  child.on('exit',()=>{childSet.delete(child);if(this.spare===child)this.spare=null;});
  return child;
 }
 warm(){if(!stopping&&!this.spare)this.spare=this.spawnRelay();}
 reset(){const spare=this.spare;this.spare=null;if(spare)spare.kill();this.destroy();}
 createConnection(options,callback){
  let child=this.spare;this.spare=null;
  if(!child||child.exitCode!==null||child.killed)child=this.spawnRelay();
  this.warm();
  let called=false;
  const done=(e,s)=>{if(called)return;called=true;clearTimeout(timer);callback(e,s);};
  const timer=setTimeout(()=>{done(Error('connect timeout'));child.kill();},10000);
  child.on('error',e=>done(e));
  child.on('exit',()=>{if(!called)done(Error('tunnel closed'));});
  child.stdout.once('data',data=>{
   if(data[0]!==82){done(Error('upstream unavailable'));child.kill();return;}
   const stream=Duplex.from({readable:child.stdout,writable:child.stdin});
   const secure=tls.connect({socket:stream,host:'172.28.20.5',ca,rejectUnauthorized:true});
   secure.once('secureConnect',()=>done(null,secure));
   secure.on('error',e=>done(e));
   secure.on('close',()=>child.kill());
  });
  child.stdin.write('G');
 }
}
// 단말마다 연결 풀을 따로 둔다. A의 연결을 B 요청에 재사용하지 않는다.
const agents=Object.fromEntries(Object.keys(TERMINALS).map(key=>[key,new TerminalAgent(TERMINALS[key],{keepAlive:true,maxSockets:2,timeout:15000})]));
for(const a of Object.values(agents))a.warm();
const json=(res,status,body)=>{res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(body));};

async function hasGatewayBlock(ip){
 try{
  const rules=await dockerAsync(['exec','capstone-a-gateway','iptables','-w','1','-S','GW_BLOCK'],1400);
  return rules.split(/\r?\n/).some(line=>{
   const parts=line.split(/\s+/);
   return parts[0]==='-A'&&parts[1]==='GW_BLOCK'
    &&parts[parts.indexOf('-s')+1]===ip+'/32'
    &&parts[parts.indexOf('-j')+1]==='DROP'
    &&/^"?apr:APR-[A-Za-z0-9-]+"?$/.test(parts[parts.indexOf('--comment')+1]||'');
  });
 }catch{return false;}
}

const server=http.createServer(async (req,res)=>{
 const allowedHosts=new Set(['localhost:18888','127.0.0.1:18888']);
 if(!allowedHosts.has(req.headers.host)){res.writeHead(403);res.end('Host denied');return;}
 if(req.url==='/practice-reset'){try{await practiceReset.handle(req,res);}catch{res.writeHead(503);res.end('Reset request failed');}return;}
 const key=selectTerminal(req.headers.cookie);
 if(req.url==='/demo-terminals'){
  if(req.method!=='GET'){res.writeHead(405);res.end('Method not allowed');return;}
  ensureTunnel(key).catch(()=>{});
  try{json(res,200,{selected:key,terminals:publicList(await runningNames())});}catch{json(res,503,{selected:key,terminals:publicList(null)});}
  return;
 }
 const origin='http://'+req.headers.host;
 if(!['GET','HEAD'].includes(req.method)&&req.headers.origin!==origin){res.writeHead(403);res.end('Origin denied');return;}
 if(!req.url.startsWith('/')||req.url.startsWith('//')||!['GET','HEAD','POST'].includes(req.method)){res.writeHead(403);res.end('Request denied');return;}
 const urlPath=req.url.split('?')[0];
 if(req.method==='POST'&&urlPath==='/api/login'&&practiceReset.isBusy()){
  json(res,503,{error:'practice reset in progress'});return;
 }
 if(!(['/','/favicon.ico','/api/login','/api/logout','/api/session','/api/documents','/api/access-requests'].includes(urlPath)||/^\/api\/documents\/[0-9A-Za-z-]{1,64}$/.test(urlPath)||/^\/api\/access-requests\/[0-9A-Za-z-]{1,64}\/(approve|reject|revoke)$/.test(urlPath))){res.writeHead(404);res.end('Not found');return;}
 if(active>=4){res.writeHead(503);res.end('Busy');return;}active++;
 res.once('close',()=>active--);
 // 선택한 단말이 꺼져 있으면 API 요청을 다른 단말로 바꿔 보내지 않고 거부한다.
 // 화면(HTML)만은 기본 단말 A로 받아 선택 메뉴에 '실행 중 아님' 경고를 보여준다.
 let routeKey=key;
 try{await ensureTunnel(key);}
 catch(error){
  if(req.method==='GET'&&urlPath==='/'&&key!=='A')routeKey='A';
  else if(error.terminal||key!=='A'){json(res,503,{error:'terminal_unavailable',terminal:key,message:error.message});return;}
 }
 // 본문 크기 감시는 단말 확인(await)이 끝난 뒤 붙인다. 먼저 붙이면 기다리는 동안 본문이 흘러가 버려 ERP에 빈 요청이 간다.
 let length=0;req.on('data',b=>{length+=b.length;if(length>32768)req.destroy();});
 const headers={host:'172.28.20.5:8443','accept':req.headers.accept||'*/*'};
 if(req.headers['content-type'])headers['content-type']=req.headers['content-type'];
 if(req.headers['content-length'] !== undefined)headers['content-length']=req.headers['content-length'];
 const cookie=stripTerminalCookie(req.headers.cookie);if(cookie)headers.cookie=cookie;
 if(req.headers.origin)headers.origin='https://172.28.20.5:8443';
 const upstream=https.request({host:'172.28.20.5',port:8443,path:req.url,method:req.method,headers,agent:agents[routeKey]},back=>{
  const h={'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'};
  for(const k of ['content-type','set-cookie'])if(back.headers[k])h[k]=back.headers[k];
  if(req.method==='GET'&&req.url==='/'&&String(back.headers['content-type']).includes('text/html')){
   let body='';back.setEncoding('utf8');back.on('data',x=>body+=x);back.on('end',()=>{
    const config=JSON.stringify({passwords:demoPasswords,terminals:publicList(null),selected:key,cookie:COOKIE}).replace(/</g,'\\u003c');
    const inject='<script>const DEMO_CONFIG='+config+';\n'+demoScript+'</script>';
    res.writeHead(back.statusCode,h);res.end(body.replace('</body>',()=>inject+'</body>'));
   });
  }else{res.writeHead(back.statusCode,h);back.pipe(res);}
 });
 upstream.setTimeout(5000,()=>upstream.destroy(Error('upstream timeout')));
 upstream.on('error',async ()=>{
  stateCache=null;
  if(res.headersSent||res.destroyed){res.end();return;}
  const terminal=TERMINALS[routeKey];
  const blocked=await hasGatewayBlock(terminal.ip);
  if(res.destroyed)return;
  const message=blocked
   ? '이 IP는 게이트웨이에서 임시 차단되었습니다. 차단이 해제된 후 다시 접속하거나 관제 담당자에게 문의하세요.'
   : `${terminal.label}(${terminal.ip})에서 ERP에 연결할 수 없습니다. 단말 상태를 확인한 뒤 다시 시도하세요.`;
  if(urlPath.startsWith('/api/')){
   json(res,blocked?403:502,{error:blocked?'gateway ip temporarily blocked':'upstream unavailable'});
   return;
  }
  res.writeHead(blocked?403:502,{'cache-control':'no-store','content-type':'text/plain; charset=utf-8'});
  res.end(message);
 });
 if(req.method==='GET'||req.method==='HEAD')upstream.end();else req.pipe(upstream);
});
server.on('error',error=>{console.error('Local UI unavailable: '+error.code);process.exit(1);});
server.listen(18888,'127.0.0.1',()=>console.log('READY http://localhost:18888'));
function stop(){stopping=true;server.close();for(const a of Object.values(agents))a.destroy();for(const c of childSet)c.kill();try{docker('compose','-f',COMPOSE,'down');}catch{}process.exit(0);}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
