'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('crypto');
const {Readable}=require('stream');
const {authorize,createHandler}=require('./practice-reset.cjs');
const config={enabled:true,username:'operator',secret:'test-only-secret'};
const sign=s=>crypto.createHmac('sha256',config.secret).update(s).digest('hex');
function credentials(exp=Math.floor(Date.now()/1000)+60){const p=`operator|${exp}`,t=Buffer.from(`${p}|${sign(p)}`).toString('base64url');return {headers:{origin:'http://127.0.0.1:8050',host:'127.0.0.1:18888',cookie:`soc_session=${t}`},form:new URLSearchParams({csrf_token:sign(`csrf|${t}`),confirm:'reset-practice-logs'})};}
test('authenticated operator with CSRF accepted',()=>{const c=credentials();assert.equal(authorize(c.headers,c.form,config),true);});
test('unauthenticated, disabled, expired, foreign origin and missing CSRF refused',()=>{const c=credentials();assert.equal(authorize({...c.headers,cookie:''},c.form,config),false);assert.equal(authorize(c.headers,c.form,{...config,enabled:false}),false);const old=credentials(1);assert.equal(authorize(old.headers,old.form,config),false);assert.equal(authorize({...c.headers,origin:'http://localhost:3000'},c.form,config),false);assert.equal(authorize(c.headers,new URLSearchParams(),config),false);assert.equal(authorize({...c.headers,host:'localhost:18888'},c.form,config),false);});
const names=['capstone-soc-dashboard','capstone-soc-collector','capstone-soc-postgres','capstone-a-gateway','capstone-a-caddy','capstone-a-caddy-log','capstone-a-erp'];
async function invoke({active=false,failHelper=false,forged=false}={}){
 const calls=[];
 const execute=async(_bin,args)=>{
  calls.push(args);
  if(args[0]==='inspect')return {stdout:JSON.stringify(names.map(n=>({Name:`/${n}`,State:{Running:true},Config:{Env:['SOC_ENABLE_PRACTICE_RESET=1','SOC_OPERATOR_USER=operator','SOC_SESSION_SECRET=test-only-secret'],Labels:{'com.docker.compose.project':n.startsWith('capstone-soc-')?'capstone-soc':'capstone-a'}}})))};
  if(args.includes('SOC_SESSION_SECRET')||args.some(a=>a.includes('os.environ[')))return {stdout:JSON.stringify(config)};
  if(args.includes('psql'))return {stdout:args.at(-1).startsWith('SELECT CASE')?(failHelper?'failed':'done'):(args.at(-1).includes('JOIN collector_offsets')?'1':(args.at(-1).startsWith('SELECT')?(active?'1':'0'):''))};
  if(args.includes('capstone-a-caddy-log'))return {stdout:'1'};
  if(args.includes('soc.practice_reset')&&failHelper)throw Error('fake failure');
  return {stdout:args.includes('iptables')?'-N GW_BLOCK':''};
 };
 const handler=createHandler('fake-docker',execute),c=credentials();
 const req=Readable.from([c.form.toString()]);req.url='/practice-reset';req.method='POST';req.headers={...c.headers,...(forged?{cookie:''}:{})};
 let status,body;
 const res={writeHead:s=>status=s,end:b=>body=b};
 await handler.handle(req,res);
 return {calls,status,body};
}
test('unauthorized request never stops or deletes',async()=>{const r=await invoke({forged:true});assert.equal(r.status,403);assert.equal(r.calls.some(c=>['stop','run'].includes(c[0])),false);});
test('active approval refuses reset and clears maintenance',async()=>{const r=await invoke({active:true});assert.equal(r.status,503);assert.equal(r.calls.some(c=>c.at(-1).includes("'reset-request'")),false);assert.ok(r.calls.some(c=>c.at(-1)==="DELETE FROM collector_offsets WHERE source='__practice_reset'"));});
test('transaction failure releases cooperative pause and reports failure',async()=>{const r=await invoke({failHelper:true});assert.equal(r.status,503);assert.ok(r.calls.some(c=>c.at(-1)==="DELETE FROM collector_offsets WHERE source='__practice_reset'"));});
test('reset never restarts services or touches original files',async()=>{const r=await invoke();assert.equal(r.status,200);assert.equal(r.calls.some(c=>['stop','start','restart','run','pause','unpause'].includes(c[0])),false);assert.ok(r.calls.some(c=>c.at(-1).includes("'reset-request'")));assert.equal(r.calls.some(c=>c.includes('python')),false);assert.equal(r.calls.some(c=>c.includes('erp_db')||c.includes('capstone-a-erp-db')),false);});
