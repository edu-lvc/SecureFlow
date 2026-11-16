"""Installer destinations, idempotence, and user scope."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.support import REPO_ROOT

INSTALLER = REPO_ROOT / "integrations" / "install.py"


def run_installer(*args: str, env=None) -> subprocess.CompletedProcess:
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(INSTALLER), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=merged,
    )


class InstallerTests(unittest.TestCase):
    def test_project_install_opencode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-install-") as directory:
            project = Path(directory)
            result = run_installer("--agent", "opencode", "--scope", "project", "--project-dir", directory)
            self.assertEqual(0, result.returncode, result.stderr)
            destination = project / ".opencode" / "skills" / "secureflow"
            self.assertTrue((destination / "SKILL.md").is_file())
            self.assertTrue((destination / "scripts" / "secureflow-gate.py").is_file())
            marker = json.loads((destination / ".secureflow-install.json").read_text(encoding="utf-8"))
            self.assertEqual("opencode", marker["agent"])
            self.assertEqual("project", marker["scope"])

    def test_project_install_all_agents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-install-") as directory:
            project = Path(directory)
            result = run_installer("--agent", "all", "--scope", "project", "--project-dir", directory)
            self.assertEqual(0, result.returncode, result.stderr)
            expected = {
                "opencode": project / ".opencode" / "skills" / "secureflow",
                "claude-code": project / ".claude" / "skills" / "secureflow",
                "codex": project / ".agents" / "skills" / "secureflow",
                "cursor": project / ".cursor" / "skills" / "secureflow",
                "copilot": project / ".github" / "skills" / "secureflow",
            }
            for agent, destination in expected.items():
                with self.subTest(agent=agent):
                    self.assertTrue((destination / "SKILL.md").is_file())
                    marker = json.loads((destination / ".secureflow-install.json").read_text(encoding="utf-8"))
                    self.assertEqual(agent, marker["agent"])

    def test_user_scope_uses_home_override(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-home-") as directory:
            home = Path(directory)
            result = run_installer(
                "--agent",
                "claude-code",
                "--scope",
                "user",
                env={"SECUREFLOW_HOME": directory},
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((home / ".claude" / "skills" / "secureflow" / "SKILL.md").is_file())

    def test_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-install-") as directory:
            first = run_installer("--agent", "codex", "--project-dir", directory)
            self.assertEqual(0, first.returncode, first.stderr)
            second = run_installer("--agent", "codex", "--project-dir", directory)
            self.assertEqual(3, second.returncode)
            self.assertIn("--force", second.stderr)
            third = run_installer("--agent", "codex", "--project-dir", directory, "--force")
            self.assertEqual(0, third.returncode, third.stderr)

    def test_dry_run_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-install-") as directory:
            result = run_installer("--agent", "copilot", "--project-dir", directory, "--dry-run")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse((Path(directory) / ".github").exists())
            self.assertIn("Would install", result.stdout)

    def test_missing_project_directory_is_usage_error(self) -> None:
        result = run_installer("--agent", "opencode", "--project-dir", str(REPO_ROOT / "missing"))
        self.assertEqual(3, result.returncode)
        self.assertIn("project directory not found", result.stderr)

    def test_source_tree_is_not_modified_by_install(self) -> None:
        marker = REPO_ROOT / "skill" / "secureflow" / ".secureflow-install.json"
        with tempfile.TemporaryDirectory(prefix="secureflow-install-") as directory:
            result = run_installer("--agent", "opencode", "--project-dir", directory)
            self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
