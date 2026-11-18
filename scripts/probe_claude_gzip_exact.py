"""Exercise the production Native gzip rewrite without a live Claude process."""
from __future__ import annotations

import json
import subprocess
import sys

from _build_support import ROOT

sys.path.insert(0, str(ROOT / "src"))
from transpect_trace.guard import claude_service as svc  # noqa: E402


def main() -> int:
    pin = svc.load_pin()
    binary = svc.installed_claude()
    svc.check_binary(pin, binary)
    output = ROOT / "build" / "claude-guard-lab" / pin["claude_code_version"] / "gzip-exact-probe.exe"
    output.parent.mkdir(parents=True, exist_ok=True)
    sources = ["native/guard/claude_guard.c",
               "native/guard/third_party/minhook/src/buffer.c",
               "native/guard/third_party/minhook/src/hook.c",
               "native/guard/third_party/minhook/src/trampoline.c",
               "native/guard/third_party/minhook/src/hde/hde64.c",
               "native/guard/third_party/miniz/miniz.c",
               "native/guard/third_party/miniz/miniz_tdef.c",
               "native/guard/third_party/miniz/miniz_tinfl.c",
               "native/guard/third_party/miniz/miniz_zip.c"]
    subprocess.run([sys.executable, "-m", "ziglang", "cc", "-target",
                    "x86_64-windows-gnu", "-O2", "-DTTRACE_GZIP_PROBE",
                    "-DJSMN_PARENT_LINKS", "-DMINIZ_NO_STDIO", "-DMINIZ_NO_TIME",
                    "-DMINIZ_NO_ARCHIVE_APIS", "-DMINIZ_NO_ARCHIVE_WRITING_APIS",
                    *svc._defines(pin), *sources, "-lbcrypt", "-o", str(output)],
                   cwd=ROOT, check=True)
    checks = [("abc", 64), ("a" * 4096, 4096), ("text-1234" * 200, 4096)]
    for content, target in checks:
        result = subprocess.run([str(output), str(target), content],
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0 or json.loads(result.stdout).get("result") != "PASS":
            print(json.dumps({"result": "FAIL", "case": len(content),
                              "target": target, "exit": result.returncode}))
            return 1
    negative = subprocess.run([str(output), "18", "abc"],
                              capture_output=True, timeout=10)
    if negative.returncode != 3:
        print(json.dumps({"result": "FAIL", "case": "undersized",
                          "exit": negative.returncode}))
        return 1
    print(json.dumps({"result": "PASS", "decision": "allow",
                      "upstream_app_bytes": 0, "cases": len(checks) + 1}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
