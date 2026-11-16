"""End-to-end status and detection tests for the scan engine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.support import EXAMPLES, GateTestCase, control_statuses, scan, temporary_project

from secureflow_gate.engine import run_scan
from secureflow_gate.model import Status
from secureflow_gate.report import verify_report, write_json, write_markdown


NA_PROJECT = {"notes.txt": "This project contains no web endpoints or credentials.\n"}

UNVERIFIED_PROJECT = {
    "Program.cs": """using Microsoft.AspNetCore.Mvc;
var builder = WebApplication.CreateBuilder(args);
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

INJECTION_PROJECT = {
    "Data.cs": """using System.Diagnostics;
using Microsoft.Data.Sqlite;
public class DataAccess
{
    public void Run(string id, SqliteConnection connection)
    {
        var unsafeCommand = new SqliteCommand("SELECT * FROM Orders WHERE Id = " + id, connection);
        Process.Start("cmd.exe", "/c ping " + id);
        var safeCommand = new SqliteCommand("SELECT * FROM Orders WHERE Id = @id", connection);
        safeCommand.Parameters.AddWithValue("@id", id);
    }
}
"""
}

SECRET_PROJECT = {
    "appsettings.json": """{
  "ExternalApi": {
    "ApiKey": "prod_key_7f3a9c2e5b8d4f1a"
  },
  "ConnectionStrings": {
    "Orders": "Server=db;Database=orders;User Id=app;Password=Sup3rS3cret!"
  }
}
""",
    "Program.cs": "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\n",
}


class EngineStatusTests(GateTestCase):
    def test_all_controls_not_applicable_for_non_web_tree(self) -> None:
        with temporary_project(NA_PROJECT) as directory:
            report = scan(Path(directory))
        self.assertEqual("NOT_APPLICABLE", report["summary"]["overall_status"])
        self.assertEqual(
            {"NOT_APPLICABLE"},
            set(control_statuses(report).values()),
        )

    def test_installed_agent_skill_directories_are_excluded(self) -> None:
        project = {
            ".opencode/skills/secureflow/rulepacks/fake.json": '{"ApiKey": "prod_key_123456789"}\n',
            ".claude/skills/secureflow/rulepacks/fake.json": '{"Password": "Sup3rS3cret!"}\n',
            ".github/skills/secureflow/fake.json": '{"ApiKey": "prod_key_123456789"}\n',
            "src/notes.txt": "Application file\n",
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assertEqual(1, report["scan"]["files_scanned"])
        self.assertEqual("NOT_APPLICABLE", report["summary"]["overall_status"])

    def test_read_only_web_project_is_unverified(self) -> None:
        with temporary_project(UNVERIFIED_PROJECT) as directory:
            report = scan(Path(directory))
        statuses = control_statuses(report)
        self.assertEqual("UNVERIFIED", statuses["authentication"])
        self.assertEqual("UNVERIFIED", statuses["authorization"])
        self.assertEqual("UNVERIFIED", statuses["input-validation"])
        self.assertEqual("NOT_APPLICABLE", statuses["injection-prevention"])
        self.assertEqual("UNVERIFIED", report["summary"]["overall_status"])

    def test_injection_positive_and_negative_cases(self) -> None:
        with temporary_project(INJECTION_PROJECT) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "injection-prevention", "FAIL")
        self.assert_rules(report, ["SF-INJ-001", "SF-INJ-002"])
        # The safe parameterized statement must not create an additional SQL finding.
        sql_findings = [item for item in report["findings"] if item["rule_id"] == "SF-INJ-001"]
        self.assertEqual(1, len(sql_findings))

    def test_from_sql_interpolated_counts_as_parameterized_surface(self) -> None:
        project = {
            "Query.cs": """using Microsoft.EntityFrameworkCore;
public class Query
{
    public void Run(DbContext db, int id)
    {
        var rows = db.Set<Order>().FromSqlInterpolated($"SELECT * FROM Orders WHERE Id = {id}");
    }
}
public class Order { public int Id { get; set; } }
"""
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "injection-prevention", "PASS")

    def test_shell_argument_list_with_dynamic_data_is_reported(self) -> None:
        project = {
            "Runner.cs": """using System.Diagnostics;
public class Runner
{
    public void Run(string value)
    {
        var shell = new ProcessStartInfo { FileName = "cmd.exe" };
        shell.ArgumentList.Add("-c");
        shell.ArgumentList.Add(value);
        Process.Start(shell);
    }
}
"""
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "injection-prevention", "FAIL")
        self.assert_rules(report, ["SF-INJ-002"])

    def test_process_start_info_without_argument_list_is_unverified(self) -> None:
        project = {
            "Runner.cs": """using System.Diagnostics;
public class Runner
{
    public void Run()
    {
        var startInfo = new ProcessStartInfo("dotnet");
        Process.Start(startInfo);
    }
}
"""
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "injection-prevention", "UNVERIFIED")
        self.assert_rules(report, ["SF-INJ-003"])

    def test_process_start_info_with_dynamic_file_name_is_reported(self) -> None:
        project = {
            "Runner.cs": """using System.Diagnostics;
public class Runner
{
    public void Run(string executable)
    {
        var startInfo = new ProcessStartInfo { FileName = executable };
        startInfo.ArgumentList.Add("--version");
        Process.Start(startInfo);
    }
}
"""
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "injection-prevention", "FAIL")
        self.assert_rules(report, ["SF-INJ-002"])

    def test_authentication_without_a_scheme_is_unverified(self) -> None:
        project = {
            "Program.cs": """var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication();
var app = builder.Build();
app.UseAuthentication();
app.MapPost("/status", () => Results.Ok());
"""
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "authentication", "UNVERIFIED")
        checks = {
            item["id"]: item
            for control in report["controls"]
            if control["id"] == "authentication"
            for item in control["checks"]
        }
        self.assertEqual("UNVERIFIED", checks["authentication-scheme"]["status"])

    def test_secret_positive_finding_is_redacted(self) -> None:
        with temporary_project(SECRET_PROJECT) as directory:
            report = scan(Path(directory))
        self.assert_status(report, "secrets-management", "FAIL")
        self.assert_rules(report, ["SF-SEC-001", "SF-SEC-004"])
        for finding in report["findings"]:
            snippet = finding["evidence"]["snippet"]
            self.assertNotIn("Sup3rS3cret!", snippet)
            self.assertNotIn("prod_key_7f3a9c2e5b8d4f1a", snippet)

    def test_secret_negative_placeholder_is_allowed(self) -> None:
        project = {
            "appsettings.json": '{"ExternalApi": {"ApiKey": "your-api-key-here"}}\n',
            "Program.cs": "var key = builder.Configuration[\"ExternalApi:ApiKey\"];\n",
        }
        with temporary_project(project) as directory:
            report = scan(Path(directory))
        self.assertNotEqual("FAIL", control_statuses(report)["secrets-management"])

    def test_secure_example_passes_every_control(self) -> None:
        report = scan(EXAMPLES / "csharp-secure" / "SecureOrders.Api")
        self.assertEqual("PASS", report["summary"]["overall_status"])
        self.assertEqual({"PASS"}, set(control_statuses(report).values()))
        self.assertEqual([], report["findings"])

    def test_vulnerable_example_fails_every_control(self) -> None:
        report = scan(EXAMPLES / "csharp-vulnerable" / "VulnerableOrders.Api")
        self.assertEqual("FAIL", report["summary"]["overall_status"])
        self.assertEqual(
            {"FAIL"},
            set(control_statuses(report).values()),
        )
        self.assert_rules(
            report,
            [
                "SF-AUTH-001",
                "SF-AUTH-003",
                "SF-AUTH-004",
                "SF-AUTHZ-001",
                "SF-INJ-001",
                "SF-INJ-002",
                "SF-SEC-001",
                "SF-SEC-004",
                "SF-VAL-001",
            ],
        )

    def test_report_integrity_detects_source_tampering(self) -> None:
        with temporary_project(INJECTION_PROJECT) as directory:
            root = Path(directory)
            report_path = root / "secureflow-report.json"
            report = scan(root, report_path=str(report_path))
            write_json(report, str(report_path))
            self.assertTrue(verify_report(str(report_path)).valid)
            (root / "Data.cs").write_text(
                (root / "Data.cs").read_text(encoding="utf-8") + "\n// changed\n",
                encoding="utf-8",
            )
            result = verify_report(str(report_path))
            self.assertFalse(result.valid)
            self.assertTrue(any("content changed" in error for error in result.errors))

    def test_report_integrity_detects_added_file(self) -> None:
        with temporary_project(NA_PROJECT) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report = scan(root, report_path=str(report_path))
            write_json(report, str(report_path))
            (root / "new.txt").write_text("new file\n", encoding="utf-8")
            result = verify_report(str(report_path))
            self.assertFalse(result.valid)
            self.assertTrue(any("added" in error for error in result.errors))

    def test_report_hash_tampering_is_detected(self) -> None:
        with temporary_project(NA_PROJECT) as directory:
            root = Path(directory)
            report_path = root / "report.json"
            report = scan(root, report_path=str(report_path))
            write_json(report, str(report_path))
            data = json.loads(report_path.read_text(encoding="utf-8"))
            data["summary"]["overall_status"] = "PASS"
            report_path.write_text(json.dumps(data), encoding="utf-8")
            result = verify_report(str(report_path))
            self.assertFalse(result.valid)
            self.assertTrue(any("SHA-256" in error for error in result.errors))

    def test_markdown_report_is_rendered(self) -> None:
        with temporary_project(NA_PROJECT) as directory:
            root = Path(directory)
            markdown_path = root / "report.md"
            report = scan(root, markdown_path=str(markdown_path))
            write_markdown(report, str(markdown_path))
            text = markdown_path.read_text(encoding="utf-8")
        self.assertIn("# SecureFlow Gate Report", text)
        self.assertIn("NOT_APPLICABLE", text)
        self.assertIn("Limitations", text)

    def test_build_control_is_aligned_with_its_own_reason(self) -> None:
        adapter = {
            "enabled": True,
            "status": "PASS",
            "exit_code": 0,
            "target": "Demo.csproj",
            "output": "Build succeeded.",
        }
        with temporary_project(NA_PROJECT) as directory:
            with mock.patch("secureflow_gate.engine._run_dotnet_build", return_value=adapter):
                report = run_scan(directory, build=True)
        controls = {item["id"]: item for item in report["controls"]}
        self.assertEqual(
            [
                "authentication",
                "authorization",
                "build-integrity",
                "injection-prevention",
                "input-validation",
                "secrets-management",
            ],
            [item["id"] for item in report["controls"]],
        )
        self.assertEqual("PASS", controls["build-integrity"]["status"])
        self.assertIn("Demo.csproj", controls["build-integrity"]["reason"])
        self.assertNotIn("injection", controls["build-integrity"]["reason"].lower())
        self.assertEqual("PASS", report["summary"]["overall_status"])


if __name__ == "__main__":
    unittest.main()
