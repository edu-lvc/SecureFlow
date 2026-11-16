"""Validate the Agent Skill contract and the shape of the shipped skill."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from tests.support import REPO_ROOT, SKILL_DIR, read_frontmatter

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class SkillStructureTests(unittest.TestCase):
    def test_skill_file_exists(self) -> None:
        self.assertTrue((SKILL_DIR / "SKILL.md").is_file())

    def test_frontmatter_contract(self) -> None:
        metadata, body = read_frontmatter(SKILL_DIR / "SKILL.md")
        self.assertEqual("secureflow", metadata.get("name"))
        self.assertEqual(SKILL_DIR.name, metadata.get("name"))
        self.assertRegex(metadata.get("name", ""), NAME_RE)
        self.assertTrue(1 <= len(metadata.get("name", "")) <= 64)
        description = metadata.get("description", "")
        self.assertTrue(32 <= len(description) <= 1024, len(description))
        self.assertIn("security", description.lower())
        self.assertLessEqual(len(metadata.get("compatibility", "")), 500)
        self.assertTrue(body.strip(), "SKILL.md body must not be empty")

    def test_skill_is_small_enough_for_progressive_disclosure(self) -> None:
        lines = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8").splitlines()
        self.assertLess(len(lines), 500, "SKILL.md should stay below 500 lines")

    def test_required_references_and_assets_exist(self) -> None:
        required = [
            "references/workflow.md",
            "references/threat-modeling.md",
            "references/controls.md",
            "references/secure-coding-csharp.md",
            "references/checklists.md",
            "references/gate.md",
            "references/agent-compatibility.md",
            "references/reporting.md",
            "assets/threat-model-template.md",
            "assets/security-requirements-template.md",
            "assets/claims-template.json",
            "assets/policy-template.json",
            "assets/report-template.md",
            "scripts/secureflow-gate.py",
        ]
        for relpath in required:
            with self.subTest(relpath=relpath):
                self.assertTrue((SKILL_DIR / relpath).is_file(), relpath)

    def test_markdown_files_are_utf8_and_english_named(self) -> None:
        for path in sorted(SKILL_DIR.rglob("*.md")):
            with self.subTest(path=str(path)):
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text.strip(), "empty Markdown file")
                self.assertNotIn("\ufffd", text)

    def test_relative_markdown_links_resolve(self) -> None:
        for path in sorted(SKILL_DIR.rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            for target in LINK_RE.findall(text):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                clean = target.split("#", 1)[0]
                if not clean:
                    continue
                destination = (path.parent / clean).resolve()
                with self.subTest(source=str(path), target=target):
                    self.assertTrue(destination.exists(), "%s -> %s" % (path, target))

    def test_json_assets_are_valid(self) -> None:
        import json

        for path in sorted(SKILL_DIR.rglob("*.json")):
            with self.subTest(path=str(path)):
                json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
