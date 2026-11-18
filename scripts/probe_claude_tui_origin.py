"""No-forward local HTTPS receiver for interactive Claude Code 2.1.317 tests.

Run this in one terminal, then run_claude_tui_local.py with the printed env file
in a second terminal. The durable receipt contains byte counts, hashes and
synthetic-marker offsets, never request bodies or credentials.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

from probe_claude_inprocess_lab import isolated_env
from probe_claude_multiturn import ScriptedOrigin
from _build_support import ROOT


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", action="append", required=True,
                        help="synthetic marker to prove absent at the local receiver")
    parser.add_argument("--scenario", choices=("text", "read"), default="text",
                        help="script the first reply as text or a Read tool call")
    args = parser.parse_args()
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("openssl executable is required")
    directory = ROOT / "runs" / "tui-origin" / datetime.now().strftime("%Y%m%d-%H%M%S")
    directory.mkdir(parents=True, exist_ok=False)
    if args.scenario == "read":
        secret = directory / "secret.txt"
        secret.write_text("内部令牌：" + args.marker[0] + " 请勿外传。\n", encoding="utf-8")
        plans = [{"kind": "tool_use", "tool": "Read",
                  "input": {"file_path": str(secret)}}]
        plans.extend({"kind": "text", "text": "LOCAL_ORIGIN_OK"} for _ in range(64))
    else:
        plans = [{"kind": "text", "text": "LOCAL_ORIGIN_OK"} for _ in range(64)]
    origin = ScriptedOrigin(directory, openssl, "bearer", args.marker[0],
                            plans,
                            tuple(args.marker[1:]))
    env = isolated_env(directory, origin, "bearer")
    env_path = directory / "env.json"
    env_path.write_text(json.dumps(env, indent=2), encoding="utf-8")
    receipt_path = directory / "origin-receipt.json"
    print(json.dumps({"schema": "transpect.claude.tui-origin-ready/1.0",
                      "directory": str(directory), "scenario": args.scenario,
                      "env_file": str(env_path),
                      "receipt_file": str(receipt_path), "url": env["ANTHROPIC_BASE_URL"]}),
          flush=True)
    try:
        while True:
            records = origin.snapshot()
            report = {"schema": "transpect.claude.local-origin-receipt/1.0",
                      "mode": "no_forward", "port": origin.port,
                      "markers_sha256": [hashlib.sha256(value.encode()).hexdigest()
                                         for value in args.marker],
                      "records": records}
            tmp = receipt_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
            os.replace(tmp, receipt_path)
            time.sleep(0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        origin.close()


if __name__ == "__main__":
    raise SystemExit(main())
