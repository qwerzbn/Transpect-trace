"""Read-only portability check for both collection routes, one row per build.

For every `codex.exe` given, without sending any model traffic:

* `codex --version` and `codex features list` under a throwaway CODEX_HOME
  (the `hooks` row says whether Route H's engine is on);
* counts of the hook event names and `hooks.json` in the image;
* the file SHA-256 against every `deploy/guard/*.json` adapter, the adapter
  status, and whether each adapter's entry prefix sits at its RVA;
* a string-anchor locator for the HTTP body-preparation hook: the one copy of
  `Compressed request body with zstd` in .rdata, the RIP-relative `lea` in .text
  that points at it, and the .pdata function holding that `lea`. The WSS and
  header-drop hooks have no portable locator (runs/scratch/compare-port) and are
  reported as `requires_dynamic_validation`.

The binaries are mapped read-only and never executed beyond the two commands.

Usage:
  uv run --no-sync python scripts/check_collection_portability.py \
      --output runs/scratch/compare-portability/portability.json \
      [--sigscan runs/scratch/compare-port/sigscan.json] CODEX_EXE [CODEX_EXE ...]
"""
from __future__ import annotations

import argparse
from array import array
import bisect
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "transpect.collection-portability/1.0"
ADAPTERS = ROOT / "deploy" / "guard"
HOOK_STRINGS = ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PreModelRequest", "hooks.json")
ENFORCED_EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse")
HTTP_ANCHOR = "Compressed request body with zstd"
WSS_ANCHOR = "failed to encode websocket request"
# A `lea r64, [rip+disp32]`: REX.W, 8D, ModRM with mod=00 rm=101.
_LEA = re.compile(rb"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)
# Same tolerance as sigscan.py: a reference may point a little before the
# phrase when it is the tail of a longer literal.
ANCHOR_SLACK = 32


def string_counts(data, strings=HOOK_STRINGS) -> dict[str, int]:
    """Non-overlapping occurrences of each string in a bytes-like buffer."""
    counts = {}
    for text in strings:
        needle, count, position = text.encode(), 0, 0
        while (position := data.find(needle, position)) >= 0:
            count, position = count + 1, position + len(needle)
        counts[text] = count
    return counts


def parse_pdata(raw: bytes) -> tuple[array, array]:
    """(begin, end) RVAs of every RUNTIME_FUNCTION, sorted by begin."""
    entries = struct.iter_unpack("<III", raw[:len(raw) // 12 * 12])
    pairs = sorted((begin, end) for begin, end, _ in entries if begin)
    return array("I", (p[0] for p in pairs)), array("I", (p[1] for p in pairs))


def function_containing(starts: array, ends: array, rva: int) -> tuple[int, int] | None:
    index = bisect.bisect_right(starts, rva) - 1
    return (starts[index], ends[index]) if index >= 0 and rva < ends[index] else None


def lea_xrefs(data, start: int, end: int, base_rva: int,
              ranges: list[tuple[int, int]]) -> dict[tuple[int, int], list[int]]:
    """RVAs of RIP-relative `lea` instructions in data[start:end] (mapped at
    `base_rva`) whose target falls in a half-open [lo, hi) range."""
    ranges = sorted(ranges)
    low, high = ranges[0][0], max(hi for _, hi in ranges)
    found: dict[tuple[int, int], list[int]] = {}
    for match in _LEA.finditer(data, start, end):
        offset = match.start()
        if offset + 7 > end:
            break
        rva = base_rva + offset - start
        target = rva + 7 + struct.unpack_from("<i", data, offset + 3)[0]
        if low <= target < high:
            index = bisect.bisect_right(ranges, (target, float("inf"))) - 1
            if index >= 0 and target < ranges[index][1]:
                found.setdefault(ranges[index], []).append(rva)
    return found


class PEImage:
    """Read-only view of a PE32+ file: sections, .text bytes and .pdata."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._file = self.path.open("rb")
        self.data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE image")
        self.machine, count = struct.unpack_from("<HH", self.data, pe + 4)
        optional = struct.unpack_from("<H", self.data, pe + 20)[0]
        self.sections = {}
        for index in range(count):
            offset = pe + 24 + optional + index * 40
            name = self.data[offset:offset + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, rva, rsize, raw = struct.unpack_from("<IIII", self.data, offset + 8)
            self.sections[name] = (rva, min(vsize, rsize), raw)
        rva, size, raw = self.sections[".pdata"]
        self.starts, self.ends = parse_pdata(self.data[raw:raw + size])

    def close(self) -> None:
        self.data.close()
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def span(self, name: str) -> tuple[int, int, int]:
        """(file start, file end, rva) of a section's raw bytes."""
        rva, size, raw = self.sections[name]
        return raw, raw + size, rva

    def read(self, rva: int, size: int) -> bytes:
        for start, length, raw in self.sections.values():
            if start <= rva and rva + size <= start + length:
                return self.data[raw + rva - start:raw + rva - start + size]
        return b""

    def rdata_rvas(self, phrase: str) -> list[int]:
        start, end, rva = self.span(".rdata")
        needle = re.compile(re.escape(phrase.encode()))
        return [rva + match.start() - start for match in needle.finditer(self.data, start, end)]

    def anchor_functions(self, phrases: list[str]) -> dict[str, dict]:
        """Per phrase: .rdata copies and the .pdata functions that `lea` it."""
        targets = {phrase: self.rdata_rvas(phrase) for phrase in phrases}
        ranges = {(rva - ANCHOR_SLACK, rva + len(phrase)): phrase
                  for phrase, rvas in targets.items() for rva in rvas}
        hits = lea_xrefs(self.data, *self.span(".text"), list(ranges)) if ranges else {}
        result = {phrase: {"rdata_copies": len(rvas), "functions": {}}
                  for phrase, rvas in targets.items()}
        for span, instructions in hits.items():
            for rva in instructions:
                function = function_containing(self.starts, self.ends, rva)
                if function:
                    result[ranges[span]]["functions"].setdefault(function, []).append(rva)
        return result

    def sha256(self, name: str | None = None) -> str:
        start, end = (0, len(self.data)) if name is None else self.span(name)[:2]
        digest = hashlib.sha256()
        for offset in range(start, end, 1 << 24):
            digest.update(self.data[offset:min(offset + (1 << 24), end)])
        return digest.hexdigest()


def load_adapters(directory: Path = ADAPTERS) -> list[dict]:
    adapters = []
    for path in sorted(directory.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and value.get("binary_sha256") and value.get("hooks"):
            adapters.append({"name": path.name, "status": value.get("status"),
                             "sha256": value["binary_sha256"].lower(),
                             "hooks": [(hook["layer"], int(hook["rva"], 16),
                                        bytes.fromhex(hook["entry_prefix_hex"]))
                                       for hook in value["hooks"]]})
    return adapters


def prefix_matches(image: PEImage, adapter: dict) -> dict[str, bool]:
    return {layer: image.read(rva, len(prefix)) == prefix
            for layer, rva, prefix in adapter["hooks"]}


def classify_hook(hooks_enabled: bool | None, counts: dict[str, int]) -> str:
    missing = [event for event in ENFORCED_EVENTS if not counts.get(event)]
    if missing:
        return f"unavailable(events missing: {','.join(missing)})"
    if hooks_enabled is None:
        return "unavailable(features list unreadable)"
    return "available" if hooks_enabled else "unavailable(features.hooks=false)"


def classify_native(pinned: dict | None, prefixes: dict[str, bool] | None,
                    locator_unique: bool, x64: bool = True) -> str:
    """`validated` needs a validated adapter pinned to this exact file whose
    entry bytes are in place; a pin that is not validated is only a candidate."""
    if not x64:
        return "no_pin"
    if pinned is not None and prefixes and all(prefixes.values()):
        return "validated" if pinned["status"] == "validated" else "pinned_unvalidated"
    return "locator_only" if locator_unique else "no_pin"


def codex(path: Path, *args: str) -> tuple[int, str]:
    """Run a local, offline subcommand with a throwaway CODEX_HOME."""
    with tempfile.TemporaryDirectory(prefix="ttrace-port-") as home:
        done = subprocess.run([str(path), *args], env={**os.environ, "CODEX_HOME": home},
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    return done.returncode, done.stdout + done.stderr


def hooks_feature(output: str) -> bool | None:
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0] == "hooks" and fields[-1] in ("true", "false"):
            return fields[-1] == "true"
    return None


def _version(output: str) -> str | None:
    match = re.search(r"codex-cli \S+", output)  # the tool also prints warnings
    return match.group(0) if match else None


def check_build(path: Path, adapters: list[dict]) -> dict:
    code, version = codex(path, "--version")
    features_code, features = codex(path, "features", "list")
    hooks_enabled = hooks_feature(features) if features_code == 0 else None
    with PEImage(path) as image:
        sha = image.sha256()
        counts = string_counts(image.data)
        pinned = next((a for a in adapters if a["sha256"] == sha), None)
        matches = {a["name"]: prefix_matches(image, a) for a in adapters}
        # The adapter whose code this is: the exact pin, else one whose entry
        # bytes all match (same .text under a different file hash).
        reference = pinned or next((a for a in adapters if all(matches[a["name"]].values())), None)
        anchors = image.anchor_functions([HTTP_ANCHOR, WSS_ANCHOR])
        http = sorted(anchors[HTTP_ANCHOR]["functions"])
        wss = sorted(anchors[WSS_ANCHOR]["functions"], key=lambda f: f[1] - f[0])
        expected = next((rva for layer, rva, _ in reference["hooks"] if layer.startswith("http")),
                        None) if reference else None
        row = {"path": str(path), "bytes": len(image.data), "sha256": sha,
               "text_sha256": image.sha256(".text"), "machine": hex(image.machine),
               "version": _version(version) if code == 0 else None,
               "features_hooks": hooks_enabled,
               "hook_event_strings": counts,
               "pre_model_request_event": counts["PreModelRequest"] > 0,
               "adapter": pinned["name"] if pinned else None,
               "adapter_status": pinned["status"] if pinned else None,
               "adapter_prefix_match": matches,
               "reference_adapter": reference["name"] if reference else None,
               "http_locator": {
                   "anchor": HTTP_ANCHOR, "rdata_copies": anchors[HTTP_ANCHOR]["rdata_copies"],
                   "functions": [hex(start) for start, _ in http],
                   "unique": len(http) == 1, "rva": hex(http[0][0]) if len(http) == 1 else None,
                   "adapter_rva": hex(expected) if expected is not None else None,
                   "equals_adapter_rva": (len(http) == 1 and http[0][0] == expected)
                   if expected is not None else None},
               "wss_locator": {"status": "requires_dynamic_validation",
                               "anchor": WSS_ANCHOR, "anchor_functions": len(wss),
                               "smallest_function": hex(wss[0][0]) if wss else None},
               "drop_headers_locator": {"status": "requires_dynamic_validation"}}
    row["hook_route"] = classify_hook(hooks_enabled, counts)
    row["native_route"] = classify_native(pinned, matches.get(pinned["name"]) if pinned else None,
                                          row["http_locator"]["unique"], image.machine == 0x8664)
    return row


def crosscheck(builds: dict[str, dict], sigscan: dict) -> dict:
    """HTTP locator here vs. the capstone prototype's zstd-anchor result."""
    by_sha = {facts["sha256"]: label for label, facts in sigscan.get("binaries", {}).items()}
    result = {}
    for label, row in builds.items():
        source = by_sha.get(row["sha256"])
        if source is None:
            result[label] = {"sigscan_build": None, "agrees": None}
            continue
        expected = sigscan["xref"][source][HTTP_ANCHOR]
        result[label] = {"sigscan_build": source, "sigscan_function": expected["smallest_function"],
                         "sigscan_functions": expected["xref_functions"],
                         "agrees": (row["http_locator"]["rva"] == expected["smallest_function"]
                                    and len(row["http_locator"]["functions"])
                                    == expected["xref_functions"])}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binaries", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sigscan", type=Path)
    args = parser.parse_args(argv)
    adapters = load_adapters()
    builds = {}
    for path in args.binaries:
        path = path.resolve(strict=True)
        row = check_build(path, adapters)
        label = f"{(row['version'] or 'unknown').split()[-1]} ({row['sha256'][:4]})"
        builds[label] = row
        print(json.dumps({"build": label, "hook_route": row["hook_route"],
                          "native_route": row["native_route"],
                          "http_locator": row["http_locator"]["rva"]}), flush=True)
    report = {"schema": SCHEMA, "builds": builds}
    if args.sigscan:
        report["sigscan_crosscheck"] = crosscheck(
            builds, json.loads(args.sigscan.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
