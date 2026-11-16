"""Shared helpers for the SecureFlow test suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "skill" / "secureflow"
SCRIPTS_DIR = SKILL_DIR / "scripts"
LAUNCHER = SCRIPTS_DIR / "secureflow-gate.py"
EXAMPLES = REPO_ROOT / "examples"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from secureflow_gate.engine import run_scan  # noqa: E402
from secureflow_gate.model import Status  # noqa: E402


def write_project(root: Path, files: Dict[str, str]) -> Path:
    """Write a project tree represented as relative path -> text."""
    for relpath, content in files.items():
        target = root / Path(relpath)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    return root


def temporary_project(files: Dict[str, str]) -> tempfile.TemporaryDirectory:
    """Create a TemporaryDirectory containing the supplied files."""
    directory = tempfile.TemporaryDirectory(prefix="secureflow-test-")
    write_project(Path(directory.name), files)
    return directory


def scan(root: Path, **kwargs):
    return run_scan(str(root), **kwargs)


def control_statuses(report: Dict) -> Dict[str, str]:
    return {item["id"]: item["status"] for item in report["controls"]}


def run_cli(*args: str, cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    command = [sys.executable, str(LAUNCHER), *args]
    return subprocess.run(
        command,
        cwd=str(cwd or REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_frontmatter(path: Path):
    """Parse the small YAML subset used by SKILL.md without PyYAML."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise AssertionError("file does not start with YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise AssertionError("frontmatter is not closed")
    raw = text[4:end]
    data = {}
    key = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("  ") and key:
            nested = data.setdefault(key, {})
            if ":" in line:
                child_key, child_value = line.strip().split(":", 1)
                nested[child_key.strip()] = child_value.strip().strip('"')
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            data[key] = value.strip('"')
        else:
            data[key] = {}
    return data, text[end + 5 :]


class GateTestCase(unittest.TestCase):
    """Base class with assertion helpers for gate reports."""

    def assert_status(self, report: Dict, control: str, expected: str) -> None:
        statuses = control_statuses(report)
        self.assertIn(control, statuses)
        self.assertEqual(expected, statuses[control], "control %s" % control)

    def assert_rules(self, report: Dict, expected: Iterable[str]) -> None:
        actual = {finding["rule_id"] for finding in report["findings"]}
        self.assertTrue(set(expected).issubset(actual), "expected %s in %s" % (set(expected), actual))
