"""Real Windows Python/OpenSSL + Native observer + isolated TLS origin.

The native DLL observes successful TLS calls; no Python monkeypatch or Frida.
"""
from __future__ import annotations
import argparse,hashlib,json,os,socket,ssl,struct,subprocess,sys,threading,time,base64,gzip
from pathlib import Path
from uuid import uuid4
from probe_codex_tls import certificate,Origin,events
from transpect_trace.observe.windows import discover_profile
from transpect_trace.observe.native import NativeCollector
from transpect_trace.observe.pipeline import Pipeline,report
from transpect_trace.guard.policy import GuardPolicy,Marker

CHILD=r'''
import ssl,socket,sys,json,base64
from pathlib import Path
fixture=json.loads(Path(sys.argv[1]).read_text(encoding='utf8'))
context=ssl.create_default_context(cafile=fixture['ca'])
context.set_alpn_protocols(['h2'] if fixture['protocol']=='h2' else ['http/1.1'])
print('ready',flush=True);sys.stdin.buffer.read(1)
for connection in fixture['connections']:
 with context.wrap_socket(socket.create_connection(('localhost',fixture['port'])),server_hostname='localhost') as sock:
  if fixture['protocol']=='h2' and sock.selected_alpn_protocol()!='h2':raise RuntimeError('h2 ALPN not negotiated')
  if isinstance(connection,dict):
   sock.sendall(base64.b64decode(connection['handshake']))
   response=b''
   while b'\r\n\r\n' not in response:response+=sock.recv(65536)
   connection=connection['chunks']
  for chunk in connection:
   sock.sendall(base64.b64decode(chunk))
  while True:
   try:
    if not sock.recv(65536):break
   except (ssl.SSLError,OSError):break
print('sent',flush=True);sys.stdin.buffer.read(1)
'''


class H2Origin:
    def __init__(self,root,cert,key,marker):
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.context.load_cert_chain(cert,key);self.context.set_alpn_protocols(['h2'])
        self.listener=socket.socket();self.listener.bind(('localhost',0));self.port=self.listener.getsockname()[1];self.listener.listen(5);self.listener.settimeout(0.2)
        self.stop=threading.Event();self.records=[];self.marker=marker;self.thread=threading.Thread(target=self.run,daemon=True)
    def run(self):
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import DataReceived,StreamEnded
        while not self.stop.is_set():
            try:raw,_=self.listener.accept()
            except socket.timeout:continue
            with self.context.wrap_socket(raw,server_side=True) as sock:
                sock.settimeout(10);server=H2Connection(config=H2Configuration(client_side=False));server.initiate_connection();sock.sendall(server.data_to_send());bodies={};finished=0
                while finished<2:
                    data=sock.recv(65536)
                    if not data:break
                    for event in server.receive_data(data):
                        if isinstance(event,DataReceived):bodies.setdefault(event.stream_id,bytearray()).extend(event.data);server.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
                        if isinstance(event,StreamEnded):
                            body=bytes(bodies[event.stream_id]);self.records.append({'protocol':'http/2','alpn':sock.selected_alpn_protocol(),'payload_sha256':hashlib.sha256(body).hexdigest(),'marker_in_origin_payload':self.marker in body})
                            server.send_headers(event.stream_id,[(':status','200')]);server.send_data(event.stream_id,b'OK',end_stream=True);finished+=1
                    sock.sendall(server.data_to_send())


class ManagedCollector:
    def __init__(self,subject,profile,root,policy):
        self.subject,self.profile,self.root,self.policy=subject,profile,root,policy;self.process=None;self.run=None
    def start(self):
        config=self.root/'managed-profile.json';config.write_text(self.profile.model_dump_json())
        policy=self.root/'managed-policy.json';policy.write_text(self.policy.model_dump_json(by_alias=True))
        self.process=subprocess.Popen([sys.executable,'-m','transpect_trace.cli','observe','run','--pid',str(self.subject['pid']),
             '--profile-file',str(config),'--policy-file',str(policy),'--duration','12','--runs-dir',str(self.root/'managed')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            for path in (self.root/'managed').glob('*/status.json'):
                try:state=json.loads(path.read_text())
                except ValueError:continue
                if state['state']=='observing':self.run=path.parent;return
            if self.process.poll() is not None:raise RuntimeError('public observer failed before readiness')
            time.sleep(0.05)
        raise RuntimeError('public observer readiness timeout')
    def records(self,name):
        path=self.run/name if self.run else None
        if path is None or not path.is_file():return []
        rows=[]
        for line in path.read_text(encoding='utf-8').splitlines():
            try:rows.append(json.loads(line))
            except ValueError:pass
        return rows
    @property
    def rows(self):return self.records('observations.jsonl')
    @property
    def assessments(self):return self.records('assessments.jsonl')
    @property
    def gaps(self):return self.records('coverage-gaps.jsonl')
    @property
    def errors(self):
        if self.run and (self.run/'status.json').is_file():return json.loads((self.run/'status.json').read_text()).get('collector_errors',[])
        return []
    def finish(self):pass
    def close(self):
        if self.process:
            try:self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:self.process.terminate();self.process.wait(timeout=5)


def experiment(root:Path,protocol:str,client_kind='python',launcher=False):
    root.mkdir(parents=True,exist_ok=False)
    marker='TRANSPECT_OBSERVE_'+uuid4().hex
    cert,key,ca=certificate(root)
    payload=json.dumps({'model':'fixture','input':[{'role':'user','content':'中文测试 '+marker+' A'*12000},
                       {'type':'function_call_output','call_id':'fake','output':marker}]},ensure_ascii=False).encode()
    origin_decoded=[]
    def source_reply(raw):
        data=gzip.decompress(raw) if protocol=='http' and client_kind=='python' else raw
        origin_decoded.append(hashlib.sha256(data).hexdigest());return events()
    origin=H2Origin(root,cert,key,marker.encode()) if protocol=='h2' else Origin(root,cert,key,marker.encode(),source_reply)
    origin.thread.start()
    if protocol=='http':
        body=gzip.compress(payload)
        wire=(f'POST /responses HTTP/1.1\r\nHost: localhost:{origin.port}\r\nAuthorization: Bearer FAKE_HEADER_SHOULD_NOT_PERSIST\r\n'
              f'Cookie: fake_cookie=DO_NOT_LOG\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()+body
        chunks=[base64.b64encode(wire[i:i+79]).decode() for i in range(0,len(wire),79)]
    elif protocol=='wss':
        handshake=(f'GET /responses HTTP/1.1\r\nHost: localhost:{origin.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n').encode()
        wsbody=json.loads(payload);wsbody['type']='response.create';payload=json.dumps(wsbody,ensure_ascii=False).encode()
        def frame(part,opcode,fin):
            mask=b'fake';prefix=bytes([opcode|(128 if fin else 0)])
            length=len(part);prefix+=bytes([length|128]) if length<126 else b'\xfe'+struct.pack('!H',length)
            return prefix+mask+bytes(b^mask[i%4] for i,b in enumerate(part))
        wire=frame(payload[:100],1,False)+frame(payload[100:],0,True)
        chunks={'handshake':base64.b64encode(handshake).decode(),'chunks':[base64.b64encode(wire[i:i+1500]).decode() for i in range(0,len(wire),1500)]}
    elif protocol=='h2':
        from h2.connection import H2Connection
        client=H2Connection();client.initiate_connection()
        for stream in (1,3):client.send_headers(stream,[(':method','POST'),(':scheme','https'),(':authority',f'localhost:{origin.port}'),(':path','/responses'),('content-type','application/json')])
        for stream in (3,1):
            for start in range(0,len(payload),8192):client.send_data(stream,payload[start:start+8192],end_stream=start+8192>=len(payload))
        wire=client.data_to_send();chunks=[base64.b64encode(wire[i:i+1500]).decode() for i in range(0,len(wire),1500)]
    else:raise ValueError('fixture protocol not implemented')
    fixture={'ca':str(ca),'port':origin.port,'connections':[chunks,chunks],'protocol':protocol}
    (root/'synthetic-input.json').write_text(json.dumps(fixture))
    with (root/'client.log').open('wb') as log:
        if client_kind=='schannel':
            (root/'fake-body.json').write_bytes(payload)
            command=[str(Path('build/observe/schannel_fixture.exe').resolve()),str(origin.port),str(root/'fake-body.json')]
        else:command=[sys._base_executable,'-u','-c',CHILD,str(root/'synthetic-input.json')]
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
        if child.stdout.readline().strip()!=b'ready':raise RuntimeError('fixture failed to initialize TLS module')
        subject,profile=discover_profile(child.pid,'python-api' if client_kind=='python' else 'schannel-fixture',mode='schannel' if client_kind=='schannel' else None)
        (root/'profile.json').write_text(profile.model_dump_json(indent=2))
        policy=GuardPolicy(credential_rules=False,content_markers=[Marker(marker_id='fixture-secret',value=marker,source_path='synthetic-fixture')])
        pipeline=Pipeline(root,policy)
        if launcher:collector=ManagedCollector(subject,profile,root,policy);pipeline=collector
        else:collector=NativeCollector(subject,profile,Path('build/observe/ttrace-observe.dll'),pipeline)
        closed=False
        try:
            collector.start();child.stdin.write(b'1');child.stdin.flush()
            if child.stdout.readline().strip()!=b'sent':raise RuntimeError('fixture did not complete requests')
            deadline=time.monotonic()+10
            count=1 if client_kind=='schannel' else 4 if protocol=='h2' else 2
            while len(pipeline.rows)<count and time.monotonic()<deadline:time.sleep(0.05)
            time.sleep(0.2)
            collector.close();closed=True
            child.stdin.close();code=child.wait(timeout=10)
            time.sleep(0.2)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            if not closed:collector.close()
            origin.stop.set();origin.thread.join(timeout=10);origin.listener.close()
    pipeline.finish()
    expected=hashlib.sha256(payload).hexdigest()
    matched=[row for row in pipeline.rows if row['content_sha256']==expected and row['completeness']=='complete']
    origin_hashes=[r['payload_sha256'] for r in origin.records] if protocol=='h2' else origin_decoded
    result={'schema_version':'transpect.observe.validation/1.0','client':client_kind,'runtime':'native-observer',
            'observer_dll_sha256':hashlib.sha256(Path('build/observe/ttrace-observe.dll').read_bytes()).hexdigest(),
            'frida_used':False,'proxy_used':False,'tls_replaced':False,'synthetic_only':True,'protocol':protocol,
            'returncode':code,'identity':subject,'profile':profile.model_dump(),'native_errors':collector.errors,
            'origin_connections':origin.records,'expected_decoded_body_sha256':expected,'exact_observation_matches':len(matched),
            'source_decoded_hashes':origin_hashes,
            'source_confidence':'Unknown','can_enforce':False,'actual_ai_channel_certified':False,
            'passed':code==0 and len(matched)==count and origin_hashes==[expected]*count and not collector.errors and not pipeline.gaps}
    (root/'status.json').write_text(json.dumps({'state':'stopped','can_enforce':False}))
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    (root/'report.json').write_text(json.dumps(report(collector.run if launcher else root),indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=Path('runs/observe-probes')/uuid4().hex)
    parser.add_argument('--protocol',choices=['http','h2','wss'],default='http');parser.add_argument('--client',choices=['python','schannel'],default='python');parser.add_argument('--launcher',action='store_true')
    args=parser.parse_args()
    if args.client=='schannel' and args.protocol!='http':parser.error('Schannel fixture supports HTTP/1.1 only')
    result=experiment(args.output.resolve(),args.protocol,args.client,args.launcher)
    print(json.dumps({k:v for k,v in result.items() if k not in {'profile','origin_connections'}},indent=2))
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
