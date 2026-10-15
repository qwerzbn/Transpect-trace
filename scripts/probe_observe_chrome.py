"""Headless isolated Chrome request + process/module discovery.

This fixture certifies origin delivery, not ChatGPT Web capture. Without a
verified BoringSSL entry the capture result remains explicitly unsupported.
"""
import argparse,base64,hashlib,http.server,json,ssl,subprocess,threading,time
from pathlib import Path
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from probe_codex_tls import certificate
from transpect_trace.observe.windows import identity,modules,exports,digest,file_version


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('runs/observe-chrome')/uuid4().hex)
    parser.add_argument('--chrome',type=Path,default=Path('C:/Program Files/Google/Chrome/Application/chrome.exe'))
    args=parser.parse_args();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    cert,key,ca=certificate(root);nonce='FAKE_CHROME_'+uuid4().hex;received=[];event=threading.Event()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            body=('<script>fetch("/responses",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({model:"fixture",input:'+json.dumps(nonce)+'})})</script>').encode()
            self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def do_POST(self):
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<1024*1024:self.send_error(413);return
            body=self.rfile.read(length);received.append({'sha256':hashlib.sha256(body).hexdigest(),'marker_present':nonce.encode() in body});event.set()
            self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
    server=http.server.ThreadingHTTPServer(('localhost',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);context.set_alpn_protocols(['http/1.1']);server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    certificate_object=x509.load_pem_x509_certificate(cert.read_bytes())
    spki=certificate_object.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    trust=base64.b64encode(hashlib.sha256(spki).digest()).decode()
    command=[str(args.chrome),'--headless=new','--no-first-run','--disable-background-networking','--disable-sync','--disable-component-update',
             '--disable-extensions',f'--user-data-dir={root/"profile"}',f'--ignore-certificate-errors-spki-list={trust}',f'https://localhost:{server.server_port}/page']
    with (root/'synthetic-chrome.log').open('wb') as log:
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log,creationflags=0x08000000)
        try:
            delivered=event.wait(20);subject=identity(child.pid)
            # Command lines stay in memory; persist only selected role labels.
            command_query=f'Get-CimInstance Win32_Process | Where-Object {{$_.Name -eq "chrome.exe"}} | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress'
            rows=json.loads(subprocess.check_output(['powershell','-NoProfile','-Command',command_query],encoding='utf-8',errors='replace',timeout=15) or '[]')
            if isinstance(rows,dict):rows=[rows]
            scope={child.pid};changed=True
            while changed:
                before=len(scope);scope.update(int(r['ProcessId']) for r in rows if int(r['ParentProcessId']) in scope);changed=len(scope)!=before
            targets=[]
            for row in rows:
                pid=int(row['ProcessId'])
                if pid not in scope:continue
                role='network-service' if 'network.mojom.NetworkService' in (row.get('CommandLine') or '') else 'chrome-process'
                item={'pid':pid,'role':role}
                try:
                    item['identity']=identity(pid);libs=[m for m in modules(pid) if Path(m['path']).name.lower()=='chrome.dll']
                    item['modules']=[{'path':m['path'],'sha256':digest(m['path']),'tls_exports':[n for n in exports(m['path']) if n.startswith('SSL_')]} for m in libs]
                except OSError:item['module_access']='unavailable'
                targets.append(item)
        finally:
            child.terminate();child.wait(timeout=10);server.shutdown();server.server_close()
    result={'client':'chrome-web','version':file_version(args.chrome),'identity':subject,'origin_delivery_passed':delivered,
            'origin_records':received,'process_evidence':targets,'visibility':'unsupported_no_verified_boringssl_entry',
            'application_plaintext_capture_passed':False,'can_enforce':False,'actual_ai_channel_certified':False,
            'protocol_scope':'isolated HTTP/1.1 origin only; default ChatGPT Web not certified','proxy_used':False,'tls_replaced':False}
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='process_evidence'},indent=2))


if __name__=='__main__':main()
