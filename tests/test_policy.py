"""Policy suppression must be explicit, expiring, and auditable."""

from __future__ import annotations

import datetime
import json
import tempfile
import unittest
from pathlib import Path

from tests.support import scan, temporary_project

from secureflow_gate.engine import run_scan
from secureflow_gate.policy import apply_policy, load_policy
from secureflow_gate.model import Status


POLICY = {
    "schema_version": "secureflow.policy/v1",
    "suppressions": [
        {
            "rule_id": "SF-SEC-001",
            "path": "appsettings.json",
            "reason": "Synthetic fixture used only in automated tests.",
            "expires": "2099-12-31",
            "owner": "security@example.invalid",
        }
    ],
}

VULNERABLE_SECRET = {
    "appsettings.json": '{"ExternalApi": {"ApiKey": "prod_key_7f3a9c2e5b8d4f1a"}}\n',
    "Program.cs": 'var apiKey = builder.Configuration["ExternalApi:ApiKey"];\n',
}


class PolicyTests(unittest.TestCase):
    def test_active_suppression_moves_finding_to_audit(self) -> None:
        with temporary_project(VULNERABLE_SECRET) as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(POLICY), encoding="utf-8")
            report = scan(root, policy_path=str(policy_path))
        secrets = {c["id"]: c for c in report["controls"]}["secrets-management"]
        self.assertEqual("PASS", secrets["status"])
        self.assertEqual(1, report["summary"]["suppressed_count"])
        self.assertEqual("SF-SEC-001", report["suppressed_findings"][0]["rule_id"])
        self.assertIn("reason", report["suppressed_findings"][0]["suppression"])

    def test_expired_suppression_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-policy-") as directory:
            path = Path(directory) / "policy.json"
            expired = json.loads(json.dumps(POLICY))
            expired["suppressions"][0]["expires"] = "2020-01-01"
            path.write_text(json.dumps(expired), encoding="utf-8")
            policy = load_policy(str(path), today=datetime.date(2026, 1, 1))
        self.assertEqual([], policy.suppressions)
        self.assertTrue(any("expired" in warning for warning in policy.warnings))

    def test_suppression_requires_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="secureflow-policy-") as directory:
            path = Path(directory) / "policy.json"
            invalid = json.loads(json.dumps(POLICY))
            del invalid["suppressions"][0]["reason"]
            path.write_text(json.dumps(invalid), encoding="utf-8")
            policy = load_policy(str(path), today=datetime.date(2026, 1, 1))
        self.assertEqual([], policy.suppressions)
        self.assertTrue(policy.warnings)

    def test_suppression_never_upgrades_unverified(self) -> None:
        """Only FAIL findings can be suppressed; UNVERIFIED checks stay UNVERIFIED."""
        from secureflow_gate.engine import run_scan

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
""",
            "policy.json": json.dumps(
                {
                    "schema_version": "secureflow.policy/v1",
                    "suppressions": [
                        {
                            "rule_id": "SF-VAL-001",
                            "path": "**",
                            "reason": "Attempt to hide an unverified control.",
                            "expires": "2099-12-31",
                        }
                    ],
                }
            ),
        }
        with tempfile.TemporaryDirectory(prefix="secureflow-policy-") as directory:
            root = Path(directory)
            for relpath, text in project.items():
                target = root / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            report = run_scan(str(root), policy_path=str(root / "policy.json"))
        self.assertEqual("UNVERIFIED", {c["id"]: c for c in report["controls"]}["input-validation"]["status"])


if __name__ == "__main__":
    unittest.main()
