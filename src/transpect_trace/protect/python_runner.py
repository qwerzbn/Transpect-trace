"""Private controlled-start entry; no user code runs before Native readiness.

Restored source SHA-256: b829c4f1e2711578dfd75ab6745dc52342c7fb75419d6c60c3f0324b714d7d66.
"""
import json,os,runpy,sys
from pathlib import Path

def main():
    line=sys.stdin.buffer.readline(65537)
    if not line or len(line)>65536:raise SystemExit('missing bounded startup configuration')
    config=json.loads(line)
    from .python_bridge import install
    ready=install(config['dll'],config['server_pid'],config['run_id'],config['manifest'],mode=config.get('mode','llm'))
    print(json.dumps({'kind':'protect.ready','pid':os.getpid(),**ready}),flush=True)
    # Controller explicitly releases after validating Native readiness.
    if sys.stdin.buffer.readline(32)!=b'RUN\n':raise SystemExit('startup not released')
    sys.argv=[config['script'],*config.get('arguments',[])]
    sys.path.insert(0,str(Path(config['script']).parent))
    runpy.run_path(config['script'],run_name='__main__')
if __name__=='__main__':main()
