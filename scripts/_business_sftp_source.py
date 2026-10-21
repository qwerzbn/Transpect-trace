"""Isolated Paramiko fake SFTP source: loopback, one allowed key and one memory file.

Run using the explicitly separate test venv, never the production policy engine.
No shell/exec, forwarding, arbitrary filesystem paths, or password authentication.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

import paramiko


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    host=paramiko.RSAKey.generate(2048);client=paramiko.RSAKey.generate(2048)
    key_path=root/'client-key';client.write_private_key_file(str(key_path))
    acl=subprocess.run(['icacls',str(key_path),'/inheritance:r','/grant:r',getpass.getuser()+':(R)'],capture_output=True)
    if acl.returncode:raise RuntimeError('Could not restrict the synthetic client key')
    (root/'empty-config').write_text('')
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(.2)
    port=listener.getsockname()[1]
    (root/'known-hosts').write_text(f'[127.0.0.1]:{port} {host.get_name()} {host.get_base64()}\n')
    receipts=[];lock=threading.Lock();workers=[];transports=[]

    class Authentication(paramiko.ServerInterface):
        def check_auth_publickey(self,username,key):
            return paramiko.AUTH_SUCCESSFUL if username=='fixture' and key==client else paramiko.AUTH_FAILED
        def get_allowed_auths(self,username):return 'publickey'
        def check_channel_request(self,kind,chanid):
            return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    class Handle(paramiko.SFTPHandle):
        def __init__(self,flags,owner):super().__init__(flags);self.data=bytearray();self.owner=owner;self.closed=False
        def write(self,offset,data):
            if offset!=len(self.data) or len(self.data)+len(data)>1024*1024:
                self.owner.failed=True
                return paramiko.SFTP_FAILURE
            self.data.extend(data);return paramiko.SFTP_OK
        def stat(self):
            attr=paramiko.SFTPAttributes();attr.st_size=len(self.data);attr.st_mode=0o100600;return attr
        def chattr(self,attr):
            size=getattr(attr,'st_size',None)
            if size is not None:
                if size<0 or size>len(self.data):self.owner.failed=True;return paramiko.SFTP_FAILURE
                del self.data[size:]
            return paramiko.SFTP_OK
        def close(self):
            if self.closed:return paramiko.SFTP_OK
            self.closed=True;self.owner.completed=True
            with lock:
                receipts.append(dict(body_bytes=len(self.data),body_sha256=hashlib.sha256(self.data).hexdigest()))
                tmp=root/'receipts.tmp';tmp.write_text(json.dumps(receipts,indent=2)+'\n');tmp.replace(root/'receipts.json')
            return paramiko.SFTP_OK

    class Files(paramiko.SFTPServerInterface):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs);self.completed=False;self.failed=False
        def canonicalize(self,path):return '/upload.bin' if path in ('upload.bin','/upload.bin') else '/'
        def open(self,path,flags,attr):
            if path not in ('upload.bin','/upload.bin') or not flags&os.O_WRONLY:
                return paramiko.SFTP_PERMISSION_DENIED
            return Handle(flags,self)
        def stat(self,path):return paramiko.SFTP_NO_SUCH_FILE
        def lstat(self,path):return paramiko.SFTP_NO_SUCH_FILE

    class SourceSFTP(paramiko.SFTPServer):
        def finish_subsystem(self):
            # OpenSSH scp checks SSH exit status after the SFTP close response.
            # Only explicitly closed files qualify; shutdown cleanup is not success.
            self.sock.send_exit_status(0 if self.server.completed and not self.server.failed and not self.file_table else 1)
            super().finish_subsystem()

    def serve(conn):
        transport=paramiko.Transport(conn);transports.append(transport)
        try:
            transport.add_server_key(host)
            transport.set_subsystem_handler('sftp',SourceSFTP,Files)
            transport.start_server(server=Authentication())
            while transport.is_active() and not (root/'stop').exists():time.sleep(.05)
        finally:transport.close()

    (root/'ready.json').write_text(json.dumps(dict(port=port,protocol='sftp_over_ssh',
        paramiko_version=paramiko.__version__,synthetic_key=True,loopback_only=True))+'\n')
    deadline=time.monotonic()+120
    try:
        while time.monotonic()<deadline and not (root/'stop').exists():
            try:conn,_=listener.accept()
            except socket.timeout:continue
            worker=threading.Thread(target=serve,args=(conn,),daemon=True);workers.append(worker);worker.start()
    finally:
        listener.close()
        for transport in transports:transport.close()
        for worker in workers:worker.join(2)


if __name__=='__main__':main()
