"""Report determinism, integrity schema, and Markdown rendering."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from tests.support import SKILL_DIR, temporary_project

from secureflow_gate.engine import run_scan
from secureflow_gate.report import (
    canonical_json,
    compute_report_sha256,
    finalize_report,
    render_markdown,
    verify_report,
    write_json,
)


class ReportTests(unittest.TestCase):
    def test_report_contains_required_contract_fields(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            report = run_scan(directory)
        for key in (
            "schema_version",
            "tool",
            "scan",
            "summary",
            "controls",
            "findings",
            "suppressed_findings",
            "claims_audit",
            "adapters",
            "limitations",
            "integrity",
        ):
            self.assertIn(key, report)
        self.assertEqual("secureflow.gate.report/v1", report["schema_version"])
        self.assertEqual(
            {"PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"},
            set(report["summary"]["status_counts"]),
        )
        self.assertIn("report_sha256", report["integrity"])
        self.assertIn("inventory_sha256", report["integrity"])
        self.assertEqual(64, len(report["integrity"]["report_sha256"]))

    def test_gate_is_deterministic_except_wall_clock_fields(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            first = run_scan(directory)
            second = run_scan(directory)
        self.assertEqual(first["integrity"]["report_sha256"], second["integrity"]["report_sha256"])
        self.assertEqual(first["integrity"]["inventory_sha256"], second["integrity"]["inventory_sha256"])
        self.assertEqual(
            first["summary"]["status_counts"],
            second["summary"]["status_counts"],
        )

    def test_report_hash_changes_when_material_content_changes(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            report = run_scan(directory)
            original = compute_report_sha256(report)
            report["summary"]["finding_count"] = 1
            changed = compute_report_sha256(report)
        self.assertNotEqual(original, changed)

    def test_canonical_json_is_stable(self) -> None:
        self.assertEqual('{"a":1,"b":2}', canonical_json({"b": 2, "a": 1}))
        self.assertEqual('{"a":"caf\u00e9"}', canonical_json({"a": "caf\u00e9"}))

    def test_written_report_verifies(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report = run_scan(directory, report_path=str(report_path))
            write_json(report, str(report_path))
            result = verify_report(str(report_path))
        self.assertTrue(result.valid, result.errors)

    def test_markdown_contains_statuses_and_limitations(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            report = run_scan(directory)
        text = render_markdown(report)
        self.assertIn("# SecureFlow Gate Report", text)
        self.assertIn("**Overall status:**", text)
        self.assertIn("## Controls", text)
        self.assertIn("## Limitations", text)
        self.assertIn("NOT_APPLICABLE", text)

    def test_schema_file_is_valid_json_and_declares_statuses(self) -> None:
        schema_path = SKILL_DIR / "scripts" / "secureflow_gate" / "schema" / "report.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertIn("$defs", schema)
        self.assertEqual(
            ["PASS", "FAIL", "UNVERIFIED", "NOT_APPLICABLE"],
            schema["$defs"]["status"]["enum"],
        )
        self.assertIn("controls", schema["required"])

    def test_no_non_ascii_arrow_replacement_in_generated_reports(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            report = run_scan(directory)
        text = render_markdown(report)
        self.assertNotIn("\ufffd", text)

    def test_verify_report_rejects_path_traversal_entries(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report = run_scan(directory, report_path=str(report_path))
            report["integrity"]["files"][0]["path"] = "../../outside.txt"
            inventory = [
                [item["path"], item["sha256"], item["size"]]
                for item in report["integrity"]["files"]
            ]
            report["integrity"]["inventory_sha256"] = hashlib.sha256(
                json.dumps(inventory, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            finalize_report(report)
            write_json(report, str(report_path))
            result = verify_report(str(report_path))
        self.assertFalse(result.valid)
        self.assertTrue(any("safe relative path" in error for error in result.errors))

    def test_verify_report_detects_inventory_hash_tampering(self) -> None:
        with temporary_project({"notes.txt": "nothing\n"}) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report = run_scan(directory, report_path=str(report_path))
            report["integrity"]["inventory_sha256"] = "0" * 64
            finalize_report(report)
            write_json(report, str(report_path))
            result = verify_report(str(report_path))
        self.assertFalse(result.valid)
        self.assertTrue(any("Inventory SHA-256" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
