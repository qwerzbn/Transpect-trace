"""Observation-only identity for the currently pinned Codex desktop backend.

This profile admits ETW metadata collection only. It is deliberately separate
from the desktop Guard adapter and cannot attest request interception.
"""
from __future__ import annotations

import json
import ntpath
import re
import subprocess

from transpect_trace.guard.desktop import _cim_process, desktop_mode, windows_powershell_env
from transpect_trace.guard.native import command_arguments
from transpect_trace.observe.windows import identity as image_identity


PACKAGE_FULL_NAME = "OpenAI.Codex_26.1103.3517.0_x64__2p2nqsd0c76g0"
PACKAGE_PUBLISHER = "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B"
DESKTOP_IMAGE_SHA256 = "ff3eb0872f1b259a15ca65f785a438f16bd4f904fd6cdfbb23c9f8dd3fb99c31"
BACKEND_IMAGE_SHA256 = "40ecc3d8b6899afd8f935a8cccb7d53ba41ffd7c199f679e186d30ddd0d0bf39"
BACKEND_VERSION = "codex-cli 0.167.0-alpha.3.2"
_SID = re.compile(r"S-1-(?:\d+-)+\d+\Z")


def _windows_path(path: object) -> str:
    return ntpath.normcase(ntpath.normpath(str(path or "")))


def _package_metadata() -> dict:
    command = (
        "$ErrorActionPreference='Stop'; "
        "$items=@(Get-AppxPackage -Name OpenAI.Codex); "
        "if ($items.Count -ne 1) { exit 2 }; "
        "$items[0] | Select-Object PackageFullName,Publisher,InstallLocation | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        check=False, env=windows_powershell_env(),
    )
    if result.returncode or not result.stdout.strip():
        raise ValueError("cannot establish installed desktop package")
    try:
        package = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("invalid installed desktop package metadata") from error
    if not isinstance(package, dict):
        raise ValueError("ambiguous installed desktop package")
    return package


def _backend_version(path: str) -> str:
    result = subprocess.run(
        [path, "--version"], stdin=subprocess.DEVNULL, capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=15, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def validate_desktop_observation_identity(
    backend: dict, backend_process: dict, desktop: dict, desktop_process: dict,
    package: dict,
) -> dict:
    """Validate only process and installed-package facts; never a Guard hook."""
    if (package.get("PackageFullName") != PACKAGE_FULL_NAME
            or package.get("Publisher") != PACKAGE_PUBLISHER):
        raise ValueError("desktop observation package pin mismatch")
    install_location = package.get("InstallLocation")
    if not isinstance(install_location, str) or not install_location:
        raise ValueError("desktop observation package path missing")
    if _windows_path(desktop.get("image_path")) != _windows_path(
            ntpath.join(install_location, "app", "ChatGPT.exe")):
        raise ValueError("desktop parent is outside the pinned package")
    if desktop.get("image_sha256") != DESKTOP_IMAGE_SHA256:
        raise ValueError("desktop parent image hash mismatch")
    if (ntpath.basename(str(backend.get("image_path", ""))).lower() != "codex.exe"
            or backend.get("image_sha256") != BACKEND_IMAGE_SHA256
            or backend.get("version") != BACKEND_VERSION):
        raise ValueError("desktop backend image or version mismatch")
    try:
        backend_pid = int(backend["pid"])
        desktop_pid = int(desktop["pid"])
        backend_birth = int(backend["creation_filetime"])
        desktop_birth = int(desktop["creation_filetime"])
        parent_pid = int(backend_process["ParentProcessId"])
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError("desktop process generation unavailable") from error
    if (backend_pid < 1 or desktop_pid < 1 or backend_birth < 1 or desktop_birth < 1
            or backend_pid == desktop_pid or parent_pid != desktop_pid):
        raise ValueError("desktop backend parent or process generation mismatch")
    backend_sid = backend_process.get("UserSid")
    if (not isinstance(backend_sid, str) or not _SID.fullmatch(backend_sid)
            or backend_sid != desktop_process.get("UserSid")):
        raise ValueError("desktop backend and parent SID mismatch")
    if backend.get("mode") != "app-server":
        raise ValueError("desktop observation requires local app-server")
    return {
        "pid": backend_pid,
        "creation_filetime": backend_birth,
        "guard_session_id": f"{backend_pid}-{backend_birth}",
        "baseline": {"path": str(backend["image_path"]),
                     "sha256": BACKEND_IMAGE_SHA256, "version": BACKEND_VERSION,
                     "supported": True},
        "channel": "desktop", "mode": "app-server", "observation_only": True,
        "user_sid": backend_sid, "desktop_pid": desktop_pid,
        "desktop_creation_filetime": desktop_birth,
        "desktop_image_sha256": DESKTOP_IMAGE_SHA256,
        "package_full_name": PACKAGE_FULL_NAME,
        "package_publisher": PACKAGE_PUBLISHER,
    }


def validate_desktop_observation_subject(subject: dict) -> None:
    """Reject an unpinned or non-observation subject before ETW starts."""
    baseline = subject.get("baseline", {})
    if (subject.get("channel") != "desktop" or subject.get("mode") != "app-server"
            or subject.get("observation_only") is not True
            or baseline.get("sha256") != BACKEND_IMAGE_SHA256
            or baseline.get("version") != BACKEND_VERSION
            or baseline.get("supported") is not True
            or subject.get("desktop_image_sha256") != DESKTOP_IMAGE_SHA256
            or subject.get("package_full_name") != PACKAGE_FULL_NAME
            or subject.get("package_publisher") != PACKAGE_PUBLISHER
            or not isinstance(subject.get("user_sid"), str)
            or not _SID.fullmatch(subject["user_sid"])):
        raise ValueError("desktop observation identity is not pinned")
    for key in ("pid", "creation_filetime", "desktop_pid", "desktop_creation_filetime"):
        if not isinstance(subject.get(key), int) or subject[key] < 1:
            raise ValueError("desktop observation process generation unavailable")


def collect_desktop_observation_identity(pid: int) -> dict:
    """Inspect an explicit PID without retaining or printing its command line."""
    if pid < 1:
        raise ValueError("invalid desktop backend PID")
    backend_process = _cim_process(pid)
    try:
        parent_pid = int(backend_process["ParentProcessId"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("desktop backend parent unavailable") from error
    desktop_process = _cim_process(parent_pid)
    backend = image_identity(pid)
    backend["version"] = _backend_version(backend["image_path"])
    backend["mode"] = desktop_mode(command_arguments(backend_process.get("CommandLine") or ""))
    desktop = image_identity(parent_pid)
    package = _package_metadata()
    return validate_desktop_observation_identity(
        backend, backend_process, desktop, desktop_process, package,
    )


def same_desktop_observation_subject(expected: dict, actual: dict) -> bool:
    validate_desktop_observation_subject(expected)
    validate_desktop_observation_subject(actual)
    keys = ("pid", "creation_filetime", "user_sid", "desktop_pid",
            "desktop_creation_filetime", "desktop_image_sha256", "package_full_name")
    return (all(expected[key] == actual[key] for key in keys)
            and expected["baseline"]["sha256"] == actual["baseline"]["sha256"]
            and _windows_path(expected["baseline"]["path"])
            == _windows_path(actual["baseline"]["path"]))
