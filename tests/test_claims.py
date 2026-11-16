"""Claims are untrusted annotations and must never upgrade a gate status."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.support import temporary_project, write_project

from secureflow_gate.claims import audit_claims, load_claims
from secureflow_gate.model import Status


SOURCE = """public class Sample
{
    public void Run() { }
}
"""


class ClaimsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = temporary_project({"Sample.cs": SOURCE, "claims.json": "{}"})
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def claims(self, control: str, status: str, **evidence):
        item = {
            "control": control,
            "status": status,
            "summary": "Agent claim",
            "evidence": [],
        }
        if evidence:
            item["evidence"].append(evidence)
        return {"schema_version": "secureflow.claims/v1", "claims": [item]}

    def test_valid_claim_with_matching_evidence_is_confirmed(self) -> None:
        data = self.claims(
            "input-validation",
            "PASS",
            path="Sample.cs",
            line=1,
            snippet="public class Sample",
        )
        audit = audit_claims(
            data,
            str(self.root),
            {},
            {"input-validation": Status.PASS},
        )
        self.assertEqual("confirmed", audit["claims"][0]["verdict"])
        self.assertEqual(1, audit["summary"]["accepted"])

    def test_wrong_snippet_is_rejected(self) -> None:
        data = self.claims(
            "input-validation",
            "PASS",
            path="Sample.cs",
            line=1,
            snippet="public class Different",
        )
        audit = audit_claims(data, str(self.root), {}, {"input-validation": Status.PASS})
        self.assertEqual("rejected", audit["claims"][0]["verdict"])
        self.assertEqual(1, audit["summary"]["rejected"])

    def test_evidence_path_cannot_escape_root(self) -> None:
        data = self.claims(
            "input-validation",
            "PASS",
            path="../outside.cs",
            line=1,
            snippet="anything",
        )
        audit = audit_claims(data, str(self.root), {}, {"input-validation": Status.PASS})
        self.assertEqual("rejected", audit["claims"][0]["verdict"])
        self.assertTrue(audit["claims"][0]["errors"] and any("outside" in error or "escapes" in error for error in audit["claims"][0]["errors"]))

    def test_claim_pass_against_gate_fail_is_overstated(self) -> None:
        data = self.claims(
            "authorization",
            "PASS",
            path="Sample.cs",
            line=1,
            snippet="public class Sample",
        )
        audit = audit_claims(data, str(self.root), {}, {"authorization": Status.FAIL})
        self.assertEqual("contradiction_overstated", audit["claims"][0]["verdict"])
        self.assertEqual(1, audit["summary"]["contradictions"])

    def test_claim_cannot_upgrade_engine_status(self) -> None:
        """Claims are annotations only; the engine report status is unchanged."""
        from secureflow_gate.engine import run_scan

        project = {
            "Program.cs": """var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
var app = builder.Build();
app.UseAuthorization();
app.MapControllers();
public class OpenController : ControllerBase
{
    [HttpPost]
    public IActionResult Create() => Ok();
}
""",
            "claims.json": '{"schema_version": "secureflow.claims/v1", "claims": []}',
        }
        with tempfile.TemporaryDirectory(prefix="secureflow-claims-") as directory:
            root = Path(directory)
            write_project(root, project)
            claims_path = root / "claims.json"
            claims_path.write_text(
                '{"schema_version":"secureflow.claims/v1","claims":[{"control":"authorization","status":"PASS","summary":"trust me","evidence":[{"path":"Program.cs","line":1,"snippet":"var builder = WebApplication.CreateBuilder(args);"}]}]}',
                encoding="utf-8",
            )
            report = run_scan(str(root), claims_path=str(claims_path))
        self.assertEqual("FAIL", {c["id"]: c["status"] for c in report["controls"]}["authorization"])
        self.assertEqual("contradiction_overstated", report["claims_audit"]["claims"][0]["verdict"])

    def test_missing_evidence_for_pass_claim_is_rejected(self) -> None:
        data = self.claims("input-validation", "PASS")
        audit = audit_claims(data, str(self.root), {}, {"input-validation": Status.PASS})
        self.assertEqual("rejected", audit["claims"][0]["verdict"])

    def test_claims_file_requires_schema(self) -> None:
        path = self.root / "bad.json"
        path.write_text('{"claims": []}', encoding="utf-8")
        with self.assertRaises(Exception):
            load_claims(str(path))


if __name__ == "__main__":
    unittest.main()
