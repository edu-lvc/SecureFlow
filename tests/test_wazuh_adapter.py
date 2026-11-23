"""Tests for the optional Wazuh adapter stub."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tests.support  # noqa: F401

from tests.support import REPO_ROOT


class WazuhAdapterTests(unittest.TestCase):
    def _run(self, sigma_out: Path, out: Path) -> subprocess.CompletedProcess[str]:
        script = REPO_ROOT / "integrations" / "siem" / "wazuh" / "sigma-to-wazuh.py"
        return subprocess.run(
            [sys.executable, str(script), "--sigma-out", str(sigma_out), "--out", str(out)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )

    def test_converts_yaml_sigma_to_wazuh_xml(self) -> None:
        sigma = '''title: SQL injection attempt
id: secureflow.test.001
status: experimental
logsource:
  product: webserver
  category: webserver
detection:
  selection:
    cs-method: GET
    sc-status: 500
  condition: selection
falsepositives:
  - "penetration tests"
level: high
tags:
  - attack.t1190
references:
  - "src/Data.cs:10"
'''
        with tempfile.TemporaryDirectory(prefix="secureflow-sigma-") as directory:
            sigma_dir = Path(directory) / "sigma"
            sigma_dir.mkdir()
            (sigma_dir / "rule.yml").write_text(sigma, encoding="utf-8")
            out = Path(directory) / "wazuh.xml"
            result = self._run(sigma_dir, out)
            self.assertEqual(0, result.returncode, result.stderr)
            xml = out.read_text(encoding="utf-8")
            self.assertIn('id="secureflow.test.001"', xml)
            self.assertIn('level="7"', xml)
            self.assertIn("SQL injection attempt", xml)
            self.assertIn("<location>web-accesslog</location>", xml)
            self.assertIn("<id>T1190</id>", xml)
            self.assertIn("penetration tests", xml)

    def test_converts_json_sigma_to_wazuh_xml(self) -> None:
        sigma = {
            "title": "Dynamic OS command",
            "id": "secureflow.test.002",
            "status": "experimental",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"CommandLine": "*cmd.exe*"},
                "condition": "selection",
            },
            "falsepositives": ["admin scripts"],
            "level": "medium",
            "tags": ["attack.t1059"],
            "references": ["src/Run.cs:15"],
        }
        with tempfile.TemporaryDirectory(prefix="secureflow-sigma-") as directory:
            sigma_dir = Path(directory) / "sigma"
            sigma_dir.mkdir()
            (sigma_dir / "rule.json").write_text(json.dumps(sigma), encoding="utf-8")
            out = Path(directory) / "wazuh.xml"
            result = self._run(sigma_dir, out)
            self.assertEqual(0, result.returncode, result.stderr)
            xml = out.read_text(encoding="utf-8")
            self.assertIn('id="secureflow.test.002"', xml)
            self.assertIn('level="5"', xml)
            self.assertIn("<id>T1059</id>", xml)


if __name__ == "__main__":
    unittest.main()
