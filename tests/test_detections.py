"""Tests for detection engineering helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.support import GateTestCase

from secureflow_gate.detections.mitre import (
    applicable_sources_for_finding,
    load_mapping,
    technique_tactics,
    validate_technique_id,
)
from secureflow_gate.detections.sigma import generate_sigma, sigma_to_json, sigma_to_yaml
from secureflow_gate.detections.telemetry import load_sources
from secureflow_gate.detections.coverage import build_coverage


class MitreHelpersTests(unittest.TestCase):
    def test_validate_technique_id_accepts_valid(self) -> None:
        self.assertTrue(validate_technique_id("T1190"))
        self.assertTrue(validate_technique_id("T1059.001"))

    def test_validate_technique_id_rejects_invalid(self) -> None:
        self.assertFalse(validate_technique_id("TA0043"))
        self.assertFalse(validate_technique_id("T119"))
        self.assertFalse(validate_technique_id("T1190.1"))
        self.assertFalse(validate_technique_id("T1190.1234"))
        self.assertFalse(validate_technique_id(""))

    def test_load_mapping_returns_techniques(self) -> None:
        mapping = load_mapping()
        self.assertIsInstance(mapping, dict)
        self.assertIn("T1190", mapping)
        self.assertEqual("secureflow.mitre-mapping/v1", _schema_version())

    def test_technique_tactics_are_listed(self) -> None:
        mapping = load_mapping()
        tactics = technique_tactics(mapping["T1078"])
        self.assertIsInstance(tactics, list)
        self.assertTrue(tactics)

    def test_applicable_sources_for_finding_matches_both_control_and_source(self) -> None:
        mapping = load_mapping()
        finding = {
            "rule_id": "SF-INJ-001",
            "control": "injection-prevention",
            "mitre_attack": ["T1190"],
            "telemetry_sources": ["web_server_logs", "wazuh"],
            "severity": "critical",
            "title": "Dynamic SQL",
            "message": "SQL injection",
            "evidence": {"path": "Data.cs", "line": 10},
        }
        pairs = applicable_sources_for_finding(finding, mapping)
        ids = [p["technique_id"] for p in pairs]
        self.assertIn("T1190", ids)

    def test_applicable_sources_empty_when_source_not_supported(self) -> None:
        mapping = load_mapping()
        finding = {
            "rule_id": "SF-INJ-001",
            "control": "injection-prevention",
            "mitre_attack": ["T1190"],
            "telemetry_sources": ["unsupported_source"],
            "severity": "critical",
            "title": "Dynamic SQL",
            "message": "SQL injection",
            "evidence": {"path": "Data.cs", "line": 10},
        }
        self.assertEqual([], applicable_sources_for_finding(finding, mapping))

    def test_applicable_sources_empty_when_control_not_applicable(self) -> None:
        mapping = load_mapping()
        finding = {
            "rule_id": "SF-SEC-001",
            "control": "secrets-management",
            "mitre_attack": ["T1190"],
            "telemetry_sources": ["web_server_logs"],
            "severity": "high",
            "title": "Hardcoded credential",
            "message": "Credential",
            "evidence": {"path": "appsettings.json", "line": 5},
        }
        self.assertEqual([], applicable_sources_for_finding(finding, mapping))


class SigmaGenerationTests(GateTestCase):
    def test_generate_sigma_experimental_rule_shape(self) -> None:
        finding = {
            "rule_id": "SF-INJ-001",
            "control": "injection-prevention",
            "severity": "critical",
            "title": "Dynamic SQL construction",
            "message": "SQL text is built with interpolation.",
            "evidence": {"path": "Data.cs", "line": 12, "snippet": "new SqliteCommand(...)"},
            "fingerprint": "abc123",
            "mitre_attack": ["T1190"],
            "telemetry_sources": ["wazuh"],
        }
        mapping = load_mapping()
        rule = generate_sigma(finding, "T1190", mapping["T1190"], "wazuh")
        self.assertIn("SecureFlow: Dynamic SQL construction [T1190]", rule["title"])
        self.assertEqual("experimental", rule["status"])
        self.assertEqual("wazuh", rule["logsource"].get("product"))
        self.assertIn("attack.T1190", rule["tags"])
        self.assertEqual("file://Data.cs#12", rule["references"][0])
        self.assertEqual("abc123", rule["metadata"]["secureflow.fingerprint"])

    def test_sigma_to_json_roundtrips(self) -> None:
        rule = {"title": "Test", "id": "secureflow-test", "status": "experimental"}
        text = sigma_to_json(rule)
        self.assertEqual(rule, json.loads(text))

    def test_sigma_to_yaml_contains_required_fields(self) -> None:
        rule = {
            "title": "Test Rule",
            "id": "secureflow-test",
            "status": "experimental",
            "logsource": {"product": "wazuh"},
            "detection": {"selection": {"foo": "bar"}, "condition": "selection"},
            "level": "high",
            "tags": ["attack.T1190"],
        }
        text = sigma_to_yaml(rule)
        self.assertIn("title:", text)
        self.assertIn("Test Rule", text)
        self.assertIn("id:", text)
        self.assertIn("secureflow-test", text)
        self.assertIn("status:", text)
        self.assertIn("experimental", text)


class CoverageLedgerTests(unittest.TestCase):
    def test_build_coverage_maps_controls_and_techniques(self) -> None:
        findings = [
            {
                "rule_id": "SF-INJ-001",
                "control": "injection-prevention",
                "severity": "critical",
                "title": "Dynamic SQL",
                "message": "SQL injection",
                "evidence": {"path": "Data.cs", "line": 10},
                "fingerprint": "fp1",
                "mitre_attack": ["T1190"],
                "telemetry_sources": ["wazuh", "web_server_logs"],
            },
            {
                "rule_id": "SF-LOG-001",
                "control": "security-logging",
                "severity": "medium",
                "title": "No logging infra",
                "message": "No logging",
                "evidence": {"path": "Program.cs", "line": 1},
                "fingerprint": "fp2",
                "mitre_attack": ["T1562"],
                "telemetry_sources": ["wazuh"],
            },
        ]
        coverage = build_coverage(findings, ["injection-prevention", "security-logging"])
        self.assertIn("injection-prevention", coverage["covered_controls"])
        self.assertIn("security-logging", coverage["covered_controls"])
        self.assertEqual([], coverage["uncovered_controls"])
        self.assertGreaterEqual(coverage["sigma_rules_generated"], 2)
        self.assertTrue(any(t["technique_id"] == "T1190" for t in coverage["mitre_techniques"]))

    def test_build_coverage_reports_uncovered_controls(self) -> None:
        findings = [
            {
                "rule_id": "SF-INJ-001",
                "control": "injection-prevention",
                "severity": "critical",
                "title": "Dynamic SQL",
                "message": "SQL injection",
                "evidence": {"path": "Data.cs", "line": 10},
                "fingerprint": "fp1",
                "mitre_attack": ["T1190"],
                "telemetry_sources": ["wazuh"],
            }
        ]
        coverage = build_coverage(findings, ["injection-prevention", "authentication"])
        self.assertIn("injection-prevention", coverage["covered_controls"])
        self.assertIn("authentication", coverage["uncovered_controls"])

    def test_build_coverage_records_missing_justification(self) -> None:
        findings = [
            {
                "rule_id": "SF-INJ-001",
                "control": "injection-prevention",
                "severity": "critical",
                "title": "Dynamic SQL",
                "message": "SQL injection",
                "evidence": {"path": "Data.cs", "line": 10},
                "fingerprint": "fp1",
                "mitre_attack": ["T1190"],
                "telemetry_sources": ["no_such_source"],
            }
        ]
        coverage = build_coverage(findings, ["injection-prevention"])
        self.assertEqual([], coverage["covered_controls"])
        self.assertTrue(any("SF-INJ-001" in j for j in coverage["missing_detection_justifications"]))


def _schema_version() -> str:
    from secureflow_gate.detections.mitre import DATA_FILE
    return json.loads(DATA_FILE.read_text(encoding="utf-8")).get("schema_version", "")


if __name__ == "__main__":
    unittest.main()
