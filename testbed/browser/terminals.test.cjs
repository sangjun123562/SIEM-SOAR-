'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {TERMINALS,COOKIE,selectTerminal,stripTerminalCookie,parseInspect,tunnelState,watchedNames,publicList}=require('./terminals.cjs');

test('docker inspect output parses into running state and start time',()=>{
 const states=parseInspect('/client-B|true|2026-11-23T05:58:03.123456789Z\r\n/capstone-erp-ui-tunnel-b-1|false|0001-01-01T00:00:00Z\n\nbroken line\n');
 assert.deepEqual(states.get('client-B'),{running:true,started:Date.parse('2026-11-23T05:58:03.123Z')});
 assert.equal(states.get('capstone-erp-ui-tunnel-b-1').running,false);
 assert.equal(states.has('broken line'),false);
 assert.equal(parseInspect('').size,0);
});
test('relay is stale when the terminal started after it',()=>{
 const x=TERMINALS.X,at=s=>({running:true,started:Date.parse(s)});
 const states=(client,tunnel)=>new Map([[x.client,client],[x.tunnel,tunnel]].filter(([,v])=>v));
 assert.equal(tunnelState(x,states(undefined,at('2026-11-23T05:50:00Z'))),'client-down');
 assert.equal(tunnelState(x,states({running:false,started:0},at('2026-11-23T05:50:00Z'))),'client-down');
 assert.equal(tunnelState(x,states(at('2026-11-23T05:50:00Z'),undefined)),'missing');
 assert.equal(tunnelState(x,states(at('2026-11-23T05:50:00Z'),{running:false,started:0})),'missing');
 assert.equal(tunnelState(x,states(at('2026-11-23T05:56:32Z'),at('2026-11-23T05:50:01Z'))),'stale');
 assert.equal(tunnelState(x,states(at('2026-11-23T05:50:01Z'),at('2026-11-23T05:56:32Z'))),'ready');
 assert.deepEqual(watchedNames().length,6);
});

test('terminal list matches fixed test IPs',()=>{
 assert.deepEqual(Object.values(TERMINALS).map(t=>[t.key,t.ip,t.client]),[['A','172.28.10.11','client-A'],['B','172.28.10.12','client-B'],['X','172.28.10.13','capstone-a-client-x']]);
});
test('selection defaults to A and accepts only listed keys',()=>{
 assert.equal(selectTerminal(undefined),'A');
 assert.equal(selectTerminal('erp_session=abc'),'A');
 assert.equal(selectTerminal(`erp_session=abc; ${COOKIE}=B`),'B');
 assert.equal(selectTerminal(`${COOKIE}=X`),'X');
 for(const bad of ['Z','b','172.28.10.12','A; x','toString','__proto__'])assert.equal(selectTerminal(`${COOKIE}=${bad}`),'A');
});
test('selection cookie is never forwarded to ERP',()=>{
 assert.equal(stripTerminalCookie(`erp_session=abc; ${COOKIE}=B; other=1`),'erp_session=abc; other=1');
 assert.equal(stripTerminalCookie(`${COOKIE}=X`),'');
 assert.equal(stripTerminalCookie(undefined),'');
});
test('public list reports availability by client container',()=>{
 const list=publicList(new Set(['client-A','client-B']));
 assert.deepEqual(list.map(t=>[t.key,t.available]),[['A',true],['B',true],['X',false]]);
 assert.equal(publicList(null).every(t=>t.available===null),true);
});
test('relay compose has one tunnel per terminal on its namespace',()=>{
 const compose=JSON.parse(fs.readFileSync(path.join(__dirname,'compose.json'),'utf8'));
 for(const t of Object.values(TERMINALS)){
  const service=compose.services[t.service];
  assert.ok(service,t.service);
  assert.equal(service.network_mode,`container:${t.client}`);
  assert.equal(`${compose.name}-${t.service}-1`,t.tunnel);
  assert.equal(service.read_only,true);
  assert.deepEqual(service.cap_drop,['ALL']);
  assert.equal(service.cpus,0.15,'5초 화면 제한 안에 새 연결을 만들 수 있는 CPU');
  assert.equal(service.mem_limit,'32m');
 }
 const total=Object.values(TERMINALS).reduce((sum,t)=>sum+compose.services[t.service].cpus,0);
 assert.ok(total<=0.45+1e-9,'중계 CPU 합계 0.45 이하');
});
test('relay accepts only fixed terminal source IPs and waits for the start marker',()=>{
 const relay=fs.readFileSync(path.join(__dirname,'stdio.py'),'utf8');
 assert.match(relay,/SOURCES=\{"172\.28\.10\.11","172\.28\.10\.12","172\.28\.10\.13"\}/);
 assert.match(relay,/if os\.read\(0,1\)!=b"G":\s*\n\s*sys\.exit\(0\)/);
 assert.match(relay,/create_connection\(\("172\.28\.20\.5",8443\)/);
});
