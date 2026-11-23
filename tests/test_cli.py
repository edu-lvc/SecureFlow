"""CLI contract, exit codes, and report workflows."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.support import EXAMPLES, LAUNCHER, REPO_ROOT, run_cli, temporary_project, write_project


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        result = run_cli("version")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("secureflow-gate", result.stdout)
        self.assertIn("0.2.1", result.stdout)

    def test_explain(self) -> None:
        result = run_cli("explain", "--rule", "SF-INJ-001")
        self.assertEqual(0, result.returncode, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual("SF-INJ-001", data["id"])
        self.assertEqual("injection-prevention", data["control"])

    def test_explain_unknown_rule_is_usage_error(self) -> None:
        result = run_cli("explain", "--rule", "SF-NOPE-999")
        self.assertEqual(3, result.returncode)
        self.assertIn("Unknown rule", result.stderr)

    def test_scan_pass_exit_zero(self) -> None:
        result = run_cli("scan", "--root", str(EXAMPLES / "csharp-secure" / "SecureOrders.Api"))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_scan_fail_exit_one(self) -> None:
        result = run_cli("scan", "--root", str(EXAMPLES / "csharp-vulnerable" / "VulnerableOrders.Api"))
        self.assertEqual(1, result.returncode, result.stderr)

    def test_scan_unverified_exit_two_with_fail_on(self) -> None:
        project = {
            "Program.cs": """var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
var app = builder.Build();
app.UseAuthorization();
app.MapControllers();
public class ReadController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok();
}
"""
        }
        with temporary_project(project) as directory:
            result = run_cli(
                "scan",
                "--root",
                directory,
                "--fail-on",
                "unverified",
            )
        self.assertEqual(2, result.returncode, result.stderr)

    def test_scan_unverified_exit_zero_by_default(self) -> None:
        project = {"notes.txt": "nothing to scan\n"}
        with temporary_project(project) as directory:
            result = run_cli("scan", "--root", directory)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_invalid_root_is_usage_error(self) -> None:
        result = run_cli("scan", "--root", str(REPO_ROOT / "does-not-exist"))
        self.assertEqual(3, result.returncode)
        self.assertIn("not a directory", result.stderr)

    def test_missing_command_is_usage_error_three(self) -> None:
        result = run_cli()
        self.assertEqual(3, result.returncode)

    def test_report_and_verify_roundtrip(self) -> None:
        with temporary_project({"notes.txt": "nothing to scan\n"}) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            markdown_path = root / "report.md"
            scan_result = run_cli(
                "scan",
                "--root",
                directory,
                "--report",
                str(report_path),
                "--markdown",
                str(markdown_path),
            )
            self.assertEqual(0, scan_result.returncode, scan_result.stderr)
            self.assertTrue(report_path.is_file())
            self.assertTrue(markdown_path.is_file())
            verify_result = run_cli("verify-report", "--report", str(report_path))
            self.assertEqual(0, verify_result.returncode, verify_result.stderr)
            self.assertIn("verified", verify_result.stdout.lower())

    def test_tampered_report_exits_four(self) -> None:
        with temporary_project({"notes.txt": "nothing to scan\n"}) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            run_cli("scan", "--root", directory, "--report", str(report_path))
            data = json.loads(report_path.read_text(encoding="utf-8"))
            data["summary"]["finding_count"] = 99
            report_path.write_text(json.dumps(data), encoding="utf-8")
            result = run_cli("verify-report", "--report", str(report_path))
        self.assertEqual(4, result.returncode)
        self.assertIn("SHA-256", result.stderr)

    def test_init_policy_and_refuse_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-policy-") as directory:
            policy = Path(directory) / "policy.json"
            first = run_cli("init-policy", "--output", str(policy))
            self.assertEqual(0, first.returncode, first.stderr)
            data = json.loads(policy.read_text(encoding="utf-8"))
            self.assertEqual("secureflow.policy/v1", data["schema_version"])
            second = run_cli("init-policy", "--output", str(policy))
            self.assertEqual(3, second.returncode)
            forced = run_cli("init-policy", "--output", str(policy), "--force")
            self.assertEqual(0, forced.returncode, forced.stderr)

    def test_launcher_exists_and_is_stdlib_only(self) -> None:
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("secureflow_gate.cli", text)
        self.assertNotIn("pip install", text)


if __name__ == "__main__":
    unittest.main()
