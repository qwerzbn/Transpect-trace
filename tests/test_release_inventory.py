"""Public release checks must scan staged bytes even when the working file differs."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from audit_release import MAX_FILE_SIZE, audit


def test_staged_and_working_tree_release_checks(tmp_path):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "--quiet")
    fixture = bytes(range(256))
    (tmp_path / "fixture.docx").write_bytes(fixture)
    (tmp_path / "large.txt").write_bytes(b"x" * (MAX_FILE_SIZE + 1))
    sample = "\n".join(("ghp_" + "a" * 36, "rk_live_" + "b" * 32, "AIza" + "c" * 35))
    (tmp_path / "public notes.txt").write_text(sample, encoding="utf-8")
    manifest = {"files": ["large.txt", "public notes.txt", "release-files.json", "later.txt"],
                "binary_fixtures": {"fixture.docx": hashlib.sha256(fixture).hexdigest()}}
    (tmp_path / "release-files.json").write_text(json.dumps(manifest), encoding="utf-8")
    git("add", "--", ".")
    for name in ("large.txt", "public notes.txt", "later.txt"):
        (tmp_path / name).write_text("publishable", encoding="utf-8")

    assert audit(tmp_path)["issues"] == [
        {"path": "large.txt", "reason": "unexpected_large_file"},
        {"path": "later.txt", "reason": "release_file_not_staged"},
        {"path": "public notes.txt", "reason": "github_token"},
        {"path": "public notes.txt", "reason": "stripe_live_key"},
        {"path": "public notes.txt", "reason": "google_api_key"},
    ]
    assert audit(tmp_path, working_tree=True)["passed"]
    git("add", "--", ".")
    assert audit(tmp_path)["passed"]

    # Windows may check out a Git symlink as plain text. The index mode is authoritative.
    oid = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", ":later.txt"], text=True).strip()
    git("update-index", "--cacheinfo", f"120000,{oid},later.txt")
    assert audit(tmp_path)["issues"] == [{"path": "later.txt", "reason": "non_regular_index_entry"}]
