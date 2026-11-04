"""Create an unvalidated desktop Guard candidate from archived official binaries.

This command never attaches to a process and never promotes a static RVA to a
working gate. Dynamic HTTP, WSS, and attachment probes must create separate
evidence before a desktop adapter can be activated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from discover_codex_hooks import discover
from transpect_trace.guard.desktop import (
    OFFICIAL_MSIX_PUBLISHER, OFFICIAL_MSIX_SIGNER_SHA1, SCHEMA,
    PINNED_MSIX_SHA256, validate_desktop_adapter, windows_powershell_env,
)


def _hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_msix_signature(package: Path) -> dict:
    if os.name != "nt":
        raise RuntimeError("official MSIX signature validation requires Windows")
    env = {**windows_powershell_env(), "TTRACE_CANDIDATE_MSIX": str(package.resolve())}
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         '$s=Get-AuthenticodeSignature -LiteralPath $env:TTRACE_CANDIDATE_MSIX; '
         '[pscustomobject]@{Status=$s.Status.ToString();Subject=$s.SignerCertificate.Subject;'
         'Thumbprint=$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        env=env, check=False)
    if result.returncode or not result.stdout.strip():
        raise ValueError("archived desktop MSIX signature unavailable")
    signer = json.loads(result.stdout)
    if (signer.get("Status") != "Valid" or signer.get("Subject") != OFFICIAL_MSIX_PUBLISHER
            or signer.get("Thumbprint", "").lower() != OFFICIAL_MSIX_SIGNER_SHA1):
        raise ValueError("archived desktop MSIX signer does not match the pinned official package")
    return {"package_signer_thumbprint": OFFICIAL_MSIX_SIGNER_SHA1}


def inspect_msix(package: Path, package_full_name: str) -> dict:
    with zipfile.ZipFile(package) as archive:
        manifest = ET.fromstring(archive.read("AppxManifest.xml"))
        identity = next((item for item in manifest.iter() if item.tag.rsplit("}", 1)[-1] == "Identity"), None)
        if identity is None or identity.attrib.get("Name") != "OpenAI.Codex":
            raise ValueError("MSIX is not the official Codex package identity")
        if identity.attrib.get("Publisher") != OFFICIAL_MSIX_PUBLISHER:
            raise ValueError("MSIX manifest publisher does not match pinned signer")
        version = identity.attrib.get("Version", "")
        architecture = identity.attrib.get("ProcessorArchitecture", "").lower()
        if architecture != "x64" or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version):
            raise ValueError("desktop demo requires an x64 fixed MSIX")
        if not package_full_name.startswith(f"OpenAI.Codex_{version}_x64__"):
            raise ValueError("installed package full name does not match archived MSIX")
        desktop_name = next((name for name in archive.namelist() if name.lower() == "app/chatgpt.exe"), None)
        if desktop_name is None:
            raise ValueError("MSIX has no app/ChatGPT.exe")
        digest = hashlib.sha256()
        with archive.open(desktop_name) as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    return {"package_name": "OpenAI.Codex", "package_version": version,
            "package_publisher": OFFICIAL_MSIX_PUBLISHER,
            "package_full_name": package_full_name, "package_sha256": _hash_file(package),
            "desktop_image_sha256": digest.hexdigest()}


def candidate_adapter(msix: dict, backend_discovery: dict, backend_version: str) -> dict:
    if not re.fullmatch(r"codex-cli \d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?", backend_version):
        raise ValueError("backend version must be a codex-cli --version line")
    candidates = {row["layer"]: row for row in backend_discovery["candidates"]}
    if "http_body_preparation" not in candidates or "serialization" not in candidates:
        raise ValueError("model HTTP/WSS static candidates missing; no adapter emitted")
    http, wss = candidates["http_body_preparation"], candidates["serialization"]
    hooks = [
        {"layer": "http_encoded_body_preparation", "rva": http["function_rva"],
         "entry_prefix_hex": http["entry_prefix_hex"], "scope": "candidate HTTP JSON body",
         "owned_headers_drop_rva": "needs_dynamic_validation", "abi_compatible": False},
        {"layer": "wss_request_serialization", "rva": wss["function_rva"],
         "entry_prefix_hex": wss["entry_prefix_hex"], "scope": "candidate WSS response.create",
         "abi_compatible": False},
    ]
    result = {"schema": SCHEMA, **msix, "architecture": "windows-x64",
              "backend_version": backend_version, "binary_sha256": backend_discovery["binary_sha256"],
              "modes": ["app-server"], "hooks": hooks,
              "coverage": {name: {"validated": False, "evidence_sha256": None}
                           for name in ("model.http", "model.wss", "attachment.upload")},
              "status": "candidate_unvalidated", "production_ready": False,
              "validation_required": ["dedicated desktop process ancestry and file hashes",
                                      "actual model HTTP and WSS path coverage",
                                      "HTTP/WSS argument, buffer and error ABI",
                                      "HTTP owned headers cleanup RVA",
                                      "desktop attachment byte capture before upload",
                                      "denied origin receives zero body bytes for every path"]}
    validate_desktop_adapter(result, require_validated=False)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msix", type=Path, required=True)
    parser.add_argument("--package-full-name", required=True)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    signer = verify_msix_signature(args.msix)
    if _hash_file(args.msix) != PINNED_MSIX_SHA256:
        raise ValueError("MSIX differs from the archived fixed official release")
    msix = inspect_msix(args.msix, args.package_full_name) | signer
    version = subprocess.run([str(args.backend), "--version"], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    result = candidate_adapter(msix, discover(args.backend), version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Static candidate only: {args.output.resolve()}")


if __name__ == "__main__":
    main()
