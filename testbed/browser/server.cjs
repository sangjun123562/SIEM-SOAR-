const fs=require('fs'),path=require('path'),cp=require('child_process'),http=require('http'),https=require('https'),tls=require('tls');
const {Duplex}=require('stream');
const D=process.env.DOCKER_BIN||'docker';
const docker=(...a)=>cp.execFileSync(D,a,{encoding:'utf8',windowsHide:true,timeout:20000}).trim();
const ROOT=__dirname;
let childSet=new Set(),active=0;
cp.execFileSync(D,['compose','-f',path.join(ROOT,'compose.json'),'up','-d','--force-recreate','--pull','never'],{cwd:ROOT,windowsHide:true,stdio:'ignore',timeout:30000});
const ca=docker('exec','capstone-a-caddy','cat','/data/caddy/pki/authorities/local/root.crt');
const demoPasswords=JSON.parse(docker('exec','capstone-a-erp','python','-c','import os,json; print(json.dumps({u:os.environ[k] for u,k in [("alice","DEMO_PW_ALICE"),("bob","DEMO_PW_BOB"),("carol","DEMO_PW_CAROL")]}))'));
class Agent extends https.Agent{
 createConnection(options,callback){
  const child=cp.spawn(D,['exec','-i','capstone-erp-ui-tunnel-1','python','-I','/app/stdio.py'],{windowsHide:true,stdio:['pipe','pipe','ignore']});
  childSet.add(child);let called=false;
  const done=(e,s)=>{if(called)return;called=true;clearTimeout(timer);callback(e,s);};
  const timer=setTimeout(()=>{done(Error('connect timeout'));child.kill();},10000);
  child.stdin.on('error',()=>{});child.on('error',e=>done(e));
  child.on('exit',()=>{childSet.delete(child);if(!called)done(Error('tunnel closed'));});
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
const agent=new Agent({keepAlive:true,maxSockets:2,timeout:15000});
const server=http.createServer((req,res)=>{
 const allowedHosts=new Set(['localhost:18888','127.0.0.1:18888']);
 if(!allowedHosts.has(req.headers.host)){res.writeHead(403);res.end('Host denied');return;}
 const origin='http://'+req.headers.host;
 if(!['GET','HEAD'].includes(req.method)&&req.headers.origin!==origin){res.writeHead(403);res.end('Origin denied');return;}
 if(!req.url.startsWith('/')||req.url.startsWith('//')||!['GET','HEAD','POST'].includes(req.method)){res.writeHead(403);res.end('Request denied');return;}
 if(!['/','/favicon.ico','/api/login','/api/logout','/api/session'].includes(req.url.split('?')[0])){res.writeHead(404);res.end('Not found');return;}
 if(active>=4){res.writeHead(503);res.end('Busy');return;}active++;
 res.once('close',()=>active--);
 let length=0;req.on('data',b=>{length+=b.length;if(length>32768)req.destroy();});
 const headers={host:'172.28.20.5:8443','accept':req.headers.accept||'*/*'};
 for(const k of ['content-type','cookie'])if(req.headers[k])headers[k]=req.headers[k];
 if(req.headers.origin)headers.origin='https://172.28.20.5:8443';
 const upstream=https.request({host:'172.28.20.5',port:8443,path:req.url,method:req.method,headers,agent},back=>{
  const h={'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'};
  for(const k of ['content-type','set-cookie'])if(back.headers[k])h[k]=back.headers[k];
  if(req.method==='GET'&&req.url==='/'&&String(back.headers['content-type']).includes('text/html')){
   let body='';back.setEncoding('utf8');back.on('data',x=>body+=x);back.on('end',()=>{
    const prefill='<script>const demoPasswords='+JSON.stringify(demoPasswords)+';window.prepareDemoLogin=()=>{const u=document.getElementById("username").value;const mode=document.getElementById("auth-mode")?.value;document.getElementById("password").value=mode==="failure"?"DemoWrongPasswordOnly":(demoPasswords[u]||"");};document.getElementById("username").addEventListener("change",window.prepareDemoLogin);document.getElementById("auth-mode")?.addEventListener("change",window.prepareDemoLogin);window.prepareDemoLogin();document.getElementById("auth-message").textContent="계정을 선택하고 로그인 버튼을 누르세요.";</script>';
    res.writeHead(back.statusCode,h);res.end(body.replace('</body>',prefill+'</body>'));
   });
  }else{res.writeHead(back.statusCode,h);back.pipe(res);}
 });
 upstream.setTimeout(5000,()=>upstream.destroy(Error('upstream timeout')));
 upstream.on('error',()=>{if(!res.headersSent)res.writeHead(502,{'cache-control':'no-store','content-type':'text/plain; charset=utf-8'});res.end('시험 단말의 ERP 연결이 끊겼습니다. 차단 해제 후 새로고침하세요.');});
 req.pipe(upstream);
});
server.on('error',error=>{console.error('Local UI unavailable: '+error.code);process.exit(1);});
server.listen(18888,'127.0.0.1',()=>console.log('READY http://localhost:18888'));
function stop(){server.close();agent.destroy();for(const c of childSet)c.kill();try{docker('compose','-f',path.join(ROOT,'compose.json'),'down');}catch{}process.exit(0);}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
