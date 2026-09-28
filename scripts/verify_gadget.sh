#!/bin/bash
set -u
mkdir -p /tmp/evidence/raw/frida /tmp/evidence/raw/system
export LD_PRELOAD=/opt/transpect-frida/libgadget.so
export TTRACE_FRIDA_LOG_DIR=/tmp/evidence/raw/frida

echo '--- cat ---'
timeout 20 strace -f -o /tmp/evidence/raw/system/strace -e trace=openat,read,write,execve,clone cat /etc/hostname
echo "CAT_RC:${?}"

echo '--- node ---'
timeout 25 node -e 'const {execSync}=require("child_process"); process.stdout.write(execSync("echo child-ok").toString())'
echo "NODE_RC:${?}"

python3 - <<'PY'
import json
from pathlib import Path
frida = sorted(Path("/tmp/evidence/raw/frida").glob("events.*.jsonl"))
strace = sorted(Path("/tmp/evidence/raw/system").glob("strace*"))
print("frida_files", [path.name for path in frida])
print("strace_files", [path.name for path in strace])
loaded = []
for path in frida:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("kind") == "frida.runtime.loaded":
            loaded.append(row.get("pid"))
print("loaded_pids", loaded)
print("loaded_count", len(loaded))
print("event_count", sum(sum(1 for line in path.read_text().splitlines() if line.strip()) for path in frida))
PY
