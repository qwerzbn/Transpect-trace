"""Non-forwarding localhost page, fake attachment and HTTPS upload receiver."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
from uuid import uuid4

from .models import LIMIT

PAGE = b'''<!doctype html><meta charset="utf-8"><title>Transpect controlled browser test</title>
<h1>Controlled browser request experiment</h1><p>Use fake data only. This page never forwards data.</p>
<p><a href="/attachment.txt" download="fake-incident.txt">Download fake attachment</a></p>
<select id="mode"><option value="plain">Fake incident text</option><option value="public">Public text</option>
<option value="large">70 KiB text</option><option value="boundary">1 MiB text</option>
<option value="file">File reference (unsupported coverage)</option></select>
<input type="file" id="file"><button id="send">Submit test request</button><pre id="status"></pre>
<script>
document.getElementById('send').onclick=async()=>{try{
const mode=document.getElementById('mode').value;
let body=mode==='public'?'public incident count: 2':await(await fetch('/attachment.txt')).text();
if(mode==='large'||mode==='boundary'){const length=mode==='large'?70*1024:1024*1024;body+='x'.repeat(length-new TextEncoder().encode(body).length);}
let headers={'Content-Type':'text/plain; charset=utf-8'};
if(mode==='file'){body=new FormData();body.append('file',document.getElementById('file').files[0]);headers={};}
const result=await fetch('/upload',{method:'POST',headers,body});
document.getElementById('status').textContent=JSON.stringify({status:result.status,received:await result.json()});
}catch(_){document.getElementById('status').textContent='Request failed; inspect collector and receiver evidence.';}};
</script>'''


class BrowserOrigin:
    def __init__(self, certificate, private_key, *, port=0):
        self.receipts = []
        self.errors = []
        self.lock = threading.Lock()
        self.connections = set()
        self.closing = False
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_alpn_protocols(['http/1.1'])
        self.context.load_cert_chain(str(certificate), str(private_key))
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_): pass
            def reply(self, data, content, status=200):
                self.send_response(status)
                self.send_header('Content-Type', content)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)
            def do_GET(self):
                if self.path == '/': self.reply(PAGE, 'text/html; charset=utf-8')
                elif self.path == '/attachment.txt':
                    self.reply('故障排查假数据\npassword=browser_fixture_secret_123456\n'.encode('utf-8'), 'text/plain; charset=utf-8')
                else: self.reply(b'{}', 'application/json', 404)
            def upload(self):
                try:
                    length = int(self.headers.get('Content-Length', '-1'))
                    if self.path not in {'/upload', '/chat'} or self.headers.get('Transfer-Encoding') or not 0 <= length <= LIMIT:
                        raise ValueError('unsupported_request')
                    remaining, digest = length, hashlib.sha256()
                    while remaining:
                        data = self.rfile.read(min(remaining, 65536))
                        if not data: raise ValueError('body_incomplete')
                        remaining -= len(data); digest.update(data)
                    receipt = {'receipt_id':uuid4().hex, 'body_sha256':digest.hexdigest(), 'body_bytes':length,
                               'source':'controlled_https_origin', 'can_enforce':False}
                    with owner.lock: owner.receipts.append(receipt)
                    self.reply(json.dumps(receipt).encode(), 'application/json')
                except (ValueError, OSError):
                    with owner.lock: owner.errors.append('upload_incomplete_or_unsupported')
                    self.close_connection = True
            do_POST = upload
            do_PUT = upload

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            def process_request_thread(self, request, address):
                connection = request
                try:
                    with owner.lock:
                        if owner.closing: return
                        connection = owner.context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                        owner.connections.add(connection)
                    connection.settimeout(10)
                    connection.do_handshake()
                    self.finish_request(connection, address)
                except (OSError, ValueError):
                    with owner.lock: owner.errors.append('connection_unavailable')
                finally:
                    with owner.lock: owner.connections.discard(connection)
                    self.shutdown_request(connection)
        self.server = Server(('127.0.0.1', port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self): return f'https://localhost:{self.server.server_port}'
    def start(self): self.thread.start(); return self
    def close(self):
        with self.lock:
            self.closing = True
            connections = list(self.connections)
        for connection in connections:
            try: connection.shutdown(2)
            except OSError: pass
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
