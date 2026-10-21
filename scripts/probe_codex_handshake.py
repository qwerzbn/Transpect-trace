"""Research-only runtime TLS trace; does not certify eCapture or enforce policy."""
from __future__ import annotations
import argparse,hashlib,json,sys,time
from pathlib import Path

from _build_support import ROOT,enter_repository
# This experiment may use an isolated environment containing Frida. Runtime
# modules still come from this exact checkout, never a different editable repo.
sys.path.insert(0,str(ROOT/'src'))
from probe_codex_request_capture import experiment
from transpect_trace.observe.windows import identity,modules,digest
from transpect_trace.guard import BINARY_SHA256

TRACE=r'''
const seen=new Set();
// Fixed-image research addresses: PE unwind entries referencing the Rustls
// "Sending ClientHello " diagnostic. Arguments and return ABI are untouched.
const rustlsEntries=[0x0e58fd50,0x0e597b70];
const expectedPrefix='5541574156415541545657534881ec28';
for(const rva of rustlsEntries){
 const p=Process.mainModule.base.add(rva);
 const prefix=Array.from(new Uint8Array(p.readByteArray(16))).map(x=>x.toString(16).padStart(2,'0')).join('');
 if(prefix!==expectedPrefix){send({kind:'research_entry_mismatch',rva:rva});continue;}
 Interceptor.attach(p,{onEnter(){send({kind:'rustls_clienthello_anchor_entry',rva:rva,
  thread_id:Process.getCurrentThreadId()});}});
 send({kind:'rustls_research_hook_installed',rva:rva,prefix:prefix});
}
const functions=['AcquireCredentialsHandleW','AcquireCredentialsHandleA','InitializeSecurityContextW',
 'InitializeSecurityContextA','EncryptMessage','DecryptMessage','WinHttpSendRequest','WinHttpReceiveResponse',
 'CertVerifyCertificateChainPolicy','CertGetCertificateChain'];
Process.attachModuleObserver({onAdded(module){
 for(const name of functions){
  const target=module.findExportByName(name);if(target===null||seen.has(target.toString()))continue;
  seen.add(target.toString());
  try{Interceptor.attach(target,{
   onEnter(args){
    this.caller=Process.findModuleByAddress(this.returnAddress);
    this.event={kind:'api_call',function:name,thread_id:Process.getCurrentThreadId(),
     caller_module:this.caller?this.caller.name:null,
     caller_rva:this.caller?this.returnAddress.sub(this.caller.base).toString():null};
    if(name.startsWith('AcquireCredentialsHandle')){
     try{const p=name.endsWith('W')?args[1].readUtf16String(128):args[1].readUtf8String(128);
      this.event.security_package=['Microsoft Unified Security Protocol Provider','Schannel','UNISP'].includes(p)?p:'other';}catch(e){}
    }
    if(name==='EncryptMessage'){
     try{const d=args[2],n=d.add(4).readU32(),p=d.add(8).readPointer();let bytes=0;
      if(n<=32)for(let i=0;i<n;i++){const b=p.add(i*16);if((b.add(4).readU32()&0xffff)===1)bytes+=b.readU32();}
      this.event.application_data_input_bytes=bytes;}catch(e){}
    }
    if(name==='CertVerifyCertificateChainPolicy')this.event.policy_id=args[0].toString();
    this.event.backtrace=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,16).map(a=>{
      const m=Process.findModuleByAddress(a);return {module:m?m.name:null,rva:m?a.sub(m.base).toString():null,
       symbol:DebugSymbol.fromAddress(a).name};});
   },
   onLeave(value){this.event.return_u32=value.toUInt32();send(this.event);}
  });send({kind:'hook_installed',function:name,module:module.name,rva:target.sub(module.base).toString()});}
  catch(e){send({kind:'hook_unavailable',function:name,module:module.name});}
 }
}});
send({kind:'trace_ready'});
'''

class HandshakeTrace:
    def __init__(self,directory,*,exports=True):
        self.directory=directory;self.records=[];self.errors=[];self.session=None;self.script=None;self.subject=None;self.closed=False
        self.exports=exports
    def start(self,subject):
        import frida
        actual=identity(subject['pid'])
        if actual['image_sha256']!=BINARY_SHA256:raise ValueError('Research addresses require fixed Codex image')
        if (actual['creation_filetime'],actual['image_sha256'])!=(subject['creation_filetime'],subject['image_sha256']):raise ValueError('Trace target lifetime mismatch')
        source=TRACE
        if not self.exports:
            begin=source.index('const functions=');end=source.index(';',begin)
            source=source[:begin]+'const functions=[]'+source[end:]
        self.subject=subject;self.session=frida.attach(subject['pid']);self.script=self.session.create_script(source)
        def message(row,_data):
            if row.get('type')=='send':
                if len(self.records)<10000:self.records.append(row['payload'])
                else:self.errors.append('trace_event_bound')
            elif row.get('type')=='error':self.errors.append('trace_script_error')
        self.script.on('message',message);self.script.load()
        deadline=time.monotonic()+5
        while not any(r['kind']=='trace_ready' for r in self.records) and time.monotonic()<deadline:time.sleep(.01)
        if not any(r['kind']=='trace_ready' for r in self.records):raise RuntimeError('Research trace not ready')
    def close(self,subject=None):
        if self.closed:return
        self.closed=True;self.directory.mkdir(parents=True,exist_ok=True)
        loaded=[]
        if self.subject:
            try:loaded=[{'name':Path(m['path']).name,'sha256':digest(m['path'])} for m in modules(self.subject['pid'])]
            except OSError:self.errors.append('final_module_snapshot_unavailable')
        if self.session:
            try:self.session.detach()
            except Exception:self.errors.append('research_detach_unconfirmed')
        (self.directory/'trace.json').write_text(json.dumps({'research_only':True,'frida_production_dependency':False,
            'research_entry_map':{'image_sha256':BINARY_SHA256,'prologue16':'5541574156415541545657534881ec28',
                'rvas':['0x0e58fd50','0x0e597b70'],'string_rva':'0x1039fc53','rustls_module_label_rva':'0x1039e11c',
                'method':'PE pdata function bounds and RIP-relative ClientHello diagnostic references; not PDB symbols',
                'source_reference':'https://raw.githubusercontent.com/rustls/rustls/v/0.23.45/rustls/src/client/hs.rs'},
            'identity':self.subject,'events':self.records,'errors':sorted(set(self.errors)),'modules':loaded},indent=2)+'\n')
    def report(self,control):
        calls=[r for r in self.records if r['kind']=='api_call']
        names={name:sum(r['function']==name for r in calls) for name in (
            'InitializeSecurityContextW','InitializeSecurityContextA','EncryptMessage','DecryptMessage',
            'WinHttpSendRequest','CertVerifyCertificateChainPolicy','CertGetCertificateChain')}
        sspi=names['InitializeSecurityContextW']+names['InitializeSecurityContextA']>0 and names['EncryptMessage']>0
        rustls_hits=[r for r in self.records if r['kind']=='rustls_clienthello_anchor_entry']
        rustls=bool(rustls_hits) and control['passed'] and not self.errors
        backend='multiple_observed' if rustls and sspi else 'rustls' if rustls else 'schannel' if sspi and control['passed'] else 'unknown'
        return {'actual_tls_backend':backend,
            'backend_evidence':'fixed_image_rustls_clienthello_string_anchor_entry_executed_and_source_handshake' if rustls else 'runtime_sspi_handshake_and_encryption_calls' if sspi else 'absence_of_sspi_calls_is_not_backend_proof',
            'rustls_clienthello_entry_hits':len(rustls_hits),'rustls_observed_rvas':sorted({hex(r['rva']) for r in rustls_hits}),
            'api_call_counts':names,'source_handshakes':control['source_tls_handshakes'],
            'request_control_passed':control['passed'],'capture_layer':'research-api-metadata',
            'ecapture_certified':False,'trace_errors':sorted(set(self.errors)),'can_enforce':False}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--codex',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--trusted-cert',type=Path,required=True)
    p.add_argument('--trusted-key',type=Path,required=True);p.add_argument('--trust-source',required=True)
    args=p.parse_args();enter_repository();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    cases=[]
    for protocol in ('http','wss'):
        trace=HandshakeTrace(root/protocol/'runtime')
        control=experiment(args.codex.resolve(),ROOT/'build/observe/ttrace-observe.dll',root/protocol/'control',protocol,65536,
            tls_probe=trace,trusted_cert=args.trusted_cert.resolve(),trusted_key=args.trusted_key.resolve())
        row={'protocol':protocol,'trust_mode':'default-trust','trust_source':args.trust_source,
            'custom_trust_environment_names':control['custom_trust_environment_names'],**trace.report(control)}
        cases.append(row);print(json.dumps(row),flush=True)
    (root/'summary.json').write_text(json.dumps({'cases':cases,'request_paths_passed':all(r['request_control_passed'] for r in cases),
        'backend_identified':all(r['actual_tls_backend']!='unknown' for r in cases),'research_only':True},indent=2)+'\n')

if __name__=='__main__':main()
