import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_browser_raw_boundaries_and_redaction_under_node():
    node = shutil.which('node')
    if not node: pytest.skip('Node required for pure browser extractor test')
    script = r'''
const assert = require('assert/strict');
const core = require(process.argv[1]);
const details = {requestId:'17',tabId:2,frameId:0,documentId:'doc',method:'POST',url:'https://localhost:9443/upload?password=SECRET',
 requestBody:{raw:[{bytes:new TextEncoder().encode('中文').buffer},{bytes:new TextEncoder().encode(' test').buffer}]}};
assert(core.permitted(details,'https://localhost:9443'));
assert(!core.permitted({...details,url:'https://example.com/upload'},'https://localhost:9443'));
assert(!core.permitted({...details,url:'https://localhost:9444/upload'},'https://localhost:9443'));
let row=core.snapshot(details,1);
assert(row.raw_complete); assert.equal(row.body_bytes,11);
row=core.beforeHeaders(row,{requestHeaders:[{name:'Content-Type',value:'text/plain'},{name:'Cookie',value:'SECRETCOOKIE'}, {name:'Authorization',value:'SECRETBEARER'}]});
let wire=core.wire(row);
assert.equal(Buffer.from(wire.body_base64,'base64').toString(),'中文 test');
assert(!JSON.stringify(wire).includes('SECRET'));
const buffer=new Uint8Array([65,66]);
row=core.snapshot({...details,requestBody:{raw:[{bytes:buffer.buffer}]}},2);
buffer[0]=90; assert.equal(core.wire(row).body_base64,'QUI=');
for(const bad of [{raw:[{file:'C:/secret.txt'}]},{formData:{credential:['SECRET']}},{error:'unavailable'},{}]){
 row=core.snapshot({...details,requestBody:bad},3); assert(!row.raw_complete);assert(row.gaps.length);
 assert(!JSON.stringify(core.wire(row)).includes('secret.txt'));
}
row=core.snapshot({...details,requestBody:{raw:[{bytes:new ArrayBuffer(core.LIMIT+1)}]}},4);
assert(row.gaps.includes('body_limit')); assert.equal(row.bytes,null);
row=core.snapshot({...details,requestBody:{raw:[{bytes:new ArrayBuffer(800000)},{bytes:new ArrayBuffer(400000)}]}},5);
assert(row.gaps.includes('body_limit'));
const a=core.wire(core.snapshot(details,1)),b=core.wire(core.snapshot({...details,tabId:3,requestId:'18'},1));
assert.equal(a.body_base64,b.body_base64);assert.notEqual(a.request_id,b.request_id);assert.notEqual(a.tab_id,b.tab_id);
console.log(JSON.stringify({passed:true, cases:12}));
'''
    result = subprocess.run([node,'-e',script,str(ROOT/'extensions/browser-observe/core.js')],capture_output=True,text=True,timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['passed']


def test_browser_worker_event_order_queue_loss_and_stop_under_node():
    node = shutil.which('node')
    if not node: pytest.skip('Node required for worker event-order test')
    script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict'),path=require('path');
const root=process.argv[1];
const handlers={},sent=[],p={};
global.TTEnrollment={origin:'https://localhost:9443',host_name:'test.host',browser_run_id:'test',enrollment_token:'token'};
global.importScripts=(...names)=>{for(const name of names)if(name!=='enrollment.js')vm.runInThisContext(fs.readFileSync(path.join(root,name),'utf8'));};
const event=name=>({addListener:fn=>handlers[name]=fn});
p.onMessage={addListener:fn=>p.message=fn};p.onDisconnect={addListener:fn=>p.disconnectCallback=fn};
p.postMessage=message=>sent.push(message);p.disconnect=()=>p.disconnectCallback();
global.chrome={webRequest:{onBeforeRequest:event('request'),onBeforeSendHeaders:event('headers'),onCompleted:event('complete'),onErrorOccurred:event('error'),onBeforeRedirect:event('redirect')},
 action:{setBadgeText:()=>{}},storage:{session:{get:async()=>({}),set:async()=>{}}},
 runtime:{id:'extension-id',connectNative:()=>p,onMessage:event('popup')}};
vm.runInThisContext(fs.readFileSync(path.join(root,'worker.js'),'utf8'));
setImmediate(()=>{
 assert.equal(sent.length,1);assert.equal(sent[0].kind,'ready');p.message({protocol:'BWO1',ack:1});
 const request=(id,tab)=>({requestId:id,tabId:tab,frameId:0,documentId:'doc-'+tab,method:'POST',url:'https://localhost:9443/upload?secret=NEVER',requestBody:{raw:[{bytes:new TextEncoder().encode('ordinary').buffer}]}});
 const headers=id=>({requestId:id,requestHeaders:[{name:'Content-Type',value:'text/plain'},{name:'Cookie',value:'COOKIE-NEVER'}]});
 handlers.request(request('same',1));handlers.headers(headers('same'));
 assert.equal(sent[1].kind,'request');assert.equal(sent[1].request_stage,1);p.message({protocol:'BWO1',ack:2});
 handlers.redirect({requestId:'same'});p.message({protocol:'BWO1',ack:3});
 handlers.request(request('same',1));handlers.headers(headers('same'));assert.equal(sent[3].request_stage,2);
 p.message({protocol:'BWO1',ack:4});
 // Hold a host ACK while requests accumulate: bounded queue must report loss.
 for(let i=0;i<14;i++){handlers.request(request('many-'+i,2));handlers.headers(headers('many-'+i));}
 let status;handlers.popup({action:'status'},{id:'extension-id'},value=>status=value);
 assert(status.lost_events>0);assert(status.queued<=8);assert.equal(status.can_enforce,false);
 // A cancelled request with no headers retains explicit incomplete evidence.
 while(sent.at(-1).sequence){const n=sent.at(-1).sequence;p.message({protocol:'BWO1',ack:n});if(sent.at(-1).sequence===n)break;}
 handlers.request(request('cancel',3));handlers.error({requestId:'cancel'});
 while(true){const n=sent.at(-1).sequence;p.message({protocol:'BWO1',ack:n});if(sent.at(-1).sequence===n)break;}
 assert(sent.some(x=>x.event_phase==='request_aborted_before_headers'));
 handlers.popup({action:'finish'},{id:'extension-id'},value=>status=value);
 assert.equal(sent.at(-1).kind,'terminal');assert(sent.at(-1).lost_events>0);
 assert(!JSON.stringify(sent).includes('NEVER'));
 assert(sent.every(x=>x.can_enforce!==true));
 console.log(JSON.stringify({passed:true,frames:sent.length}));
});
'''
    result = subprocess.run([node,'-e',script,str(ROOT/'extensions/browser-observe')],capture_output=True,text=True,timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['passed']
