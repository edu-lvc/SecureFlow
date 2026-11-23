"""Incident response template tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import tests.support  # noqa: F401

from secureflow_gate.incident import IncidentError, init_incident


class IncidentTests(unittest.TestCase):
    def test_init_incident_copies_templates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-incident-") as directory:
            output = Path(directory) / "incident-2026-11-22"
            written = init_incident(str(output))
            self.assertEqual(3, len(written))
            for name in ("incident-response-template.md", "ioc-template.md", "timeline-template.md"):
                path = output / name
                self.assertTrue(path.is_file(), name)
                self.assertIn("#", path.read_text(encoding="utf-8"))

    def test_init_incident_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-incident-") as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            (output / "incident-response-template.md").write_text("existing\n", encoding="utf-8")
            with self.assertRaises(IncidentError):
                init_incident(str(output))

    def test_init_incident_force_overwrites(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-incident-") as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            stale = output / "incident-response-template.md"
            stale.write_text("stale\n", encoding="utf-8")
            init_incident(str(output), force=True)
            self.assertIn("Incident Response", stale.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
