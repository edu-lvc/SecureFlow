"""Static portability checks for the zero-dependency gate."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests.support import SCRIPTS_DIR


class PythonCompatibilityTests(unittest.TestCase):
    def test_package_uses_python_39_compatible_syntax(self) -> None:
        paths = list(SCRIPTS_DIR.rglob("*.py"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=str(path)):
                source = path.read_text(encoding="utf-8")
                ast.parse(source, filename=str(path), feature_version=(3, 9))

    def test_no_third_party_imports(self) -> None:
        allowed = {
            "__future__",
            "argparse",
            "ast",
            "collections",
            "copy",
            "dataclasses",
            "datetime",
            "enum",
            "fnmatch",
            "functools",
            "hashlib",
            "json",
            "os",
            "pathlib",
            "re",
            "shutil",
            "subprocess",
            "sys",
            "tempfile",
            "typing",
            "unittest",
        }
        for path in SCRIPTS_DIR.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        with self.subTest(path=str(path), module=alias.name):
                            self.assertIn(alias.name.split(".")[0], allowed)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    with self.subTest(path=str(path), module=node.module):
                        root = node.module.split(".")[0]
                        if root != "secureflow_gate":
                            self.assertIn(root, allowed)

    def test_launcher_has_no_shell_or_network_calls(self) -> None:
        launcher = (SCRIPTS_DIR / "secureflow-gate.py").read_text(encoding="utf-8")
        self.assertNotIn("shell=True", launcher)
        self.assertNotIn("requests", launcher)


if __name__ == "__main__":
    unittest.main()
