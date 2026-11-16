"""Safe, deterministic repository scanning."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple, Union

from .globs import matches_any, normalize_path
from .model import ScanFile, SkippedFile

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".opencode",
    ".claude",
    ".agents",
    ".cursor",
    ".codex",
    ".copilot",
    ".vs",
    ".idea",
    ".vscode",
    "node_modules",
    "bin",
    "obj",
    "dist",
    "build",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    "vendor",
    ".secureflow",
    ".next",
    ".nuxt",
    "target",
    "out",
}

DEFAULT_EXCLUDED_GLOBS = [
    ".secureflow/**",
    "**/.secureflow/**",
    ".github/skills/**",
    "**/.github/skills/**",
    ".github/copilot/skills/**",
    "**/.github/copilot/skills/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
]

MAX_FILE_BYTES = 2 * 1024 * 1024


class ScanError(RuntimeError):
    """Raised when the scan root is invalid."""


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan_tree(
    root: Union[str, Path],
    extra_excludes: Sequence[str] = (),
    max_file_bytes: int = MAX_FILE_BYTES,
) -> Tuple[List[ScanFile], List[SkippedFile], List[str]]:
    """Read text files under root without following symlinks.

    Returns files, skipped files, and the effective exclude globs.
    """

    root_path = Path(root).expanduser()
    try:
        root_path = root_path.resolve(strict=True)
    except OSError as exc:
        raise ScanError("scan root does not exist: %s" % root) from exc
    if not root_path.is_dir():
        raise ScanError("scan root is not a directory: %s" % root)

    excludes = list(DEFAULT_EXCLUDED_GLOBS)
    for pattern in extra_excludes:
        normalized = normalize_path(pattern)
        if normalized and normalized not in excludes:
            excludes.append(normalized)

    files: List[ScanFile] = []
    skipped: List[SkippedFile] = []

    def on_error(error: OSError) -> None:
        rel = _relative(error.filename or "", root_path)
        skipped.append(SkippedFile(rel or ".", "unreadable directory: %s" % error.strerror))

    for current, dirnames, filenames in os.walk(root_path, topdown=True, onerror=on_error, followlinks=False):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in DEFAULT_EXCLUDED_DIRS
            and not Path(current, name).is_symlink()
            and not matches_any(_relative(Path(current, name), root_path), excludes)
        )
        for filename in sorted(filenames):
            absolute = Path(current, filename)
            rel = _relative(absolute, root_path)
            if absolute.is_symlink():
                skipped.append(SkippedFile(rel, "symlink not followed"))
                continue
            if matches_any(rel, excludes):
                continue
            try:
                stat = absolute.stat()
            except OSError as exc:
                skipped.append(SkippedFile(rel, "stat failed: %s" % exc))
                continue
            if not absolute.is_file():
                skipped.append(SkippedFile(rel, "not a regular file"))
                continue
            if stat.st_size > max_file_bytes:
                skipped.append(SkippedFile(rel, "larger than %d bytes" % max_file_bytes))
                continue
            try:
                data = absolute.read_bytes()
            except OSError as exc:
                skipped.append(SkippedFile(rel, "read failed: %s" % exc))
                continue
            if _is_binary(data):
                skipped.append(SkippedFile(rel, "binary content"))
                continue
            text = data.decode("utf-8", errors="replace")
            files.append(
                ScanFile(
                    relpath=rel,
                    abspath=str(absolute),
                    text=text,
                    sha256=hashlib.sha256(data).hexdigest(),
                    size=len(data),
                )
            )

    files.sort(key=lambda item: item.relpath)
    skipped.sort(key=lambda item: item.relpath)
    return files, skipped, excludes


def _relative(path: Union[str, Path], root: Path) -> str:
    if not str(path):
        return ""
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return normalize_path(str(path))


def inventory_sha256(files: Iterable[ScanFile]) -> str:
    payload = [[item.relpath, item.sha256, item.size] for item in sorted(files, key=lambda f: f.relpath)]
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_inventory(files: Iterable[ScanFile]) -> List[dict]:
    return [
        {"path": item.relpath, "sha256": item.sha256, "size": item.size}
        for item in sorted(files, key=lambda f: f.relpath)
    ]
