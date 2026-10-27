"""Build the pinned Windows Chrome Content Analysis Agent.

The command never downloads, updates, or checks out dependencies implicitly.
Use ``--prepare`` only after placing the pinned SDK and vcpkg repositories in
the local ``.external`` cache. Preparation uses those local repositories.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from _build_support import ROOT, enter_repository


PIN_FILE = ROOT / "patches/content-analysis-sdk/manifest.json"
DEFAULT_SDK = ROOT / ".external/content-analysis-sdk"
DEFAULT_VCPKG = ROOT / ".external/vcpkg"
def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _run(*command: str, cwd: Path | None = None, capture: bool = False) -> str:
    result = subprocess.run(
        list(command),
        cwd=cwd,
        check=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def _git(root: Path, *arguments: str) -> str:
    return _run("git", "-C", str(root), *arguments, capture=True)


def load_pin() -> dict:
    value = json.loads(PIN_FILE.read_text(encoding="utf-8"))
    if value.get("schema") != "transpect.vendor.content-analysis-sdk/1.0":
        raise RuntimeError("unsupported Content Analysis SDK manifest")
    return value


def verify_sdk_checkout(root: Path, pin: dict | None = None) -> dict[str, str]:
    pin = pin or load_pin()
    if not (root / ".git").exists() and not _is_git_worktree(root):
        raise RuntimeError(f"SDK is not a Git checkout: {root}")
    head = _git(root, "rev-parse", "HEAD")
    if head != pin["commit"]:
        raise RuntimeError(
            f"SDK commit mismatch: got {head}; need {pin['commit']}. "
            "Use --prepare to make an isolated checkout without changing the cache."
        )
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise RuntimeError("SDK checkout is dirty; refusing a non-reproducible build")
    observed: dict[str, str] = {}
    for name, expected in pin["source_sha256"].items():
        path = root / name
        if not path.is_file():
            raise RuntimeError(f"pinned SDK source is missing: {name}")
        observed[name] = sha256_file(path)
        if observed[name] != expected:
            raise RuntimeError(f"pinned SDK source hash mismatch: {name}")
    return observed


def _is_git_worktree(root: Path) -> bool:
    try:
        return _git(root, "rev-parse", "--is-inside-work-tree") == "true"
    except (OSError, subprocess.CalledProcessError):
        return False


def prepare_sdk(source_repository: Path, destination: Path, pin: dict) -> Path:
    if not _is_git_worktree(source_repository):
        raise RuntimeError(
            "No local Content Analysis SDK repository is available. Clone it explicitly "
            f"to {source_repository}; this build command never downloads dependencies."
        )
    _git(source_repository, "cat-file", "-e", f"{pin['commit']}^{{commit}}")
    if destination.exists():
        verify_sdk_checkout(destination, pin)
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    _run(
        "git",
        "-C",
        str(source_repository),
        "worktree",
        "add",
        "--detach",
        str(destination),
        pin["commit"],
    )
    verify_sdk_checkout(destination, pin)
    return destination


def verify_vcpkg(root: Path, pin: dict | None = None) -> str:
    pin = pin or load_pin()
    expected = pin["toolchain"]["vcpkg_commit"]
    if not _is_git_worktree(root):
        raise RuntimeError(
            "No local vcpkg repository is available. Clone vcpkg explicitly to "
            f"{root}, check out {expected}, then rerun."
        )
    head = _git(root, "rev-parse", "HEAD")
    if head != expected:
        raise RuntimeError(f"vcpkg commit mismatch: got {head}; need {expected}")
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise RuntimeError("vcpkg checkout is dirty; refusing a non-reproducible build")
    return head


def prepare_vcpkg(root: Path, pin: dict) -> None:
    verify_vcpkg(root, pin)
    executable = root / "vcpkg.exe"
    if not executable.is_file():
        bootstrap = root / "bootstrap-vcpkg.bat"
        if not bootstrap.is_file():
            raise RuntimeError("pinned vcpkg bootstrap script is missing")
        _run("cmd.exe", "/d", "/c", str(bootstrap), "-disableMetrics", cwd=root)
    packages = [
        f"{name}:{pin['toolchain']['triplet']}" for name in pin["toolchain"]["packages"]
    ]
    _run(str(executable), "install", *packages, "--disable-metrics", cwd=root)


def locate_cmake(explicit: Path | None = None) -> Path:
    if explicit:
        candidate = explicit.resolve()
        if candidate.is_file():
            return candidate
        raise RuntimeError(f"CMake executable does not exist: {candidate}")
    discovered = shutil.which("cmake")
    if discovered:
        return Path(discovered).resolve()
    program_files = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    vswhere = program_files / "Microsoft Visual Studio/Installer/vswhere.exe"
    if vswhere.is_file():
        try:
            installation = _run(
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
                capture=True,
            )
            candidate = Path(installation) / (
                "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
            )
            if candidate.is_file():
                return candidate.resolve()
        except subprocess.CalledProcessError:
            pass
    roots = sorted((program_files / "Microsoft Visual Studio").glob("*/BuildTools"), reverse=True)
    for root in roots:
        candidate = root / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("CMake was not found on PATH or in Visual Studio Build Tools")


def _artifact(build_dir: Path, name: str) -> Path:
    matches = [
        path
        for path in build_dir.rglob(name)
        if path.is_file()
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one {name}, found {len(matches)}")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/content-analysis-agent")
    parser.add_argument("--sdk-root", type=Path, default=DEFAULT_SDK)
    parser.add_argument("--vcpkg-root", type=Path, default=DEFAULT_VCPKG)
    parser.add_argument("--cmake", type=Path)
    parser.add_argument(
        "--prepare",
        action="store_true",
        help="make an isolated pinned SDK worktree and prepare already-cloned pinned vcpkg",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify pinned sources and installed prerequisites without building",
    )
    args = parser.parse_args()
    enter_repository()
    output = args.output.resolve()
    pin = load_pin()

    sdk = args.sdk_root.resolve()
    vcpkg = args.vcpkg_root.resolve()
    if args.prepare:
        sdk = prepare_sdk(sdk, output / "vendor/content-analysis-sdk", pin)
        prepare_vcpkg(vcpkg, pin)
    sources = verify_sdk_checkout(sdk, pin)
    vcpkg_commit = verify_vcpkg(vcpkg, pin)
    if not (vcpkg / "installed/x64-windows/share/protobuf/protobuf-config.cmake").is_file():
        raise RuntimeError(
            "protobuf:x64-windows is not installed in pinned vcpkg; rerun with --prepare"
        )

    cmake = locate_cmake(args.cmake)
    if args.check:
        print(
            json.dumps(
                {
                    "ready": True,
                    "sdk_commit": pin["commit"],
                    "vcpkg_commit": vcpkg_commit,
                    "cmake": str(cmake),
                    "verified_sdk_sources": len(sources),
                },
                indent=2,
            )
        )
        return
    build_dir = output / "cmake"
    build_dir.mkdir(parents=True, exist_ok=True)
    configure = [
        str(cmake),
        "-S",
        str(ROOT / "native/content_analysis"),
        "-B",
        str(build_dir),
        "-A",
        "x64",
        f"-DCMAKE_TOOLCHAIN_FILE={vcpkg / 'scripts/buildsystems/vcpkg.cmake'}",
        "-DVCPKG_TARGET_TRIPLET=x64-windows",
        f"-DCONTENT_ANALYSIS_SDK_ROOT={sdk}",
        "-DTTRACE_BUILD_SDK_TEST_CLIENT=ON",
    ]
    _run(*configure)
    _run(
        str(cmake),
        "--build",
        str(build_dir),
        "--config",
        "Release",
        "--target",
        "ttrace-content-agent",
        "ttrace-content-sdk-client",
    )
    destinations = []
    for name in ("ttrace-content-agent.exe", "ttrace-content-sdk-client.exe"):
        destination = output / name
        shutil.copy2(_artifact(build_dir, name), destination)
        destinations.append(destination)
    # x64-windows is a dynamic triplet.  Keep the ignored local build output
    # self-contained for protocol validation; release packaging remains a
    # separate, reviewed operation.
    runtime_bin = vcpkg / "installed/x64-windows/bin"
    runtime_libraries = []
    for runtime_name in ("abseil_dll.dll", "libprotobuf.dll"):
        library = runtime_bin / runtime_name
        if not library.is_file():
            raise RuntimeError(f"required protobuf runtime is missing: {runtime_name}")
        copied = output / library.name
        shutil.copy2(library, copied)
        runtime_libraries.append(copied)

    native_sources = sorted((ROOT / "native/content_analysis").glob("*"))
    manifest = {
        "schema": "transpect.native.content-analysis.build/1.0",
        "architecture": "x86_64",
        "sdk": {
            "commit": pin["commit"],
            "manifest_sha256": sha256_file(PIN_FILE),
            "sources_sha256": sources,
        },
        "vcpkg_commit": vcpkg_commit,
        "cmake": _run(str(cmake), "--version", capture=True).splitlines()[0],
        "sources_sha256": {
            path.relative_to(ROOT).as_posix(): sha256_file(path)
            for path in native_sources
            if path.is_file()
        },
        "artifacts_sha256": {
            path.name: sha256_file(path)
            for path in [*destinations, *runtime_libraries]
        },
    }
    (output / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output / "ttrace-content-agent.exe")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"content analysis build failed: {error}") from error
