"""Lint the rule packs that define the gate contract."""

from __future__ import annotations

import unittest

from tests.support import GateTestCase

from secureflow_gate.model import Status
from secureflow_gate.rules import available_profiles, explain_rule, load_profile


class RulePackTests(GateTestCase):
    def setUp(self) -> None:
        self.profile = load_profile("csharp-aspnetcore")

    def test_expected_profiles_and_controls(self) -> None:
        self.assertIn("csharp-aspnetcore", available_profiles())
        self.assertEqual(
            [
                "authentication",
                "authorization",
                "injection-prevention",
                "input-validation",
                "secrets-management",
                "security-logging",
            ],
            list(self.profile.controls),
        )

    def test_rule_ids_are_unique_and_prefixed(self) -> None:
        ids = [rule.id for rule in self.profile.rules]
        self.assertEqual(len(ids), len(set(ids)))
        for rule_id in ids:
            self.assertRegex(rule_id, r"^SF-[A-Z]+-[0-9]{3}$")

    def test_every_rule_has_actionable_metadata(self) -> None:
        for rule in self.profile.rules:
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.control)
                self.assertTrue(rule.title)
                self.assertTrue(rule.message)
                self.assertTrue(rule.remediation)
                self.assertTrue(rule.cwe)
                self.assertTrue(rule.asvs)
                self.assertTrue(rule.owasp)
                self.assertIn(rule.control, self.profile.controls)
                if rule.kind == "regex":
                    self.assertIsNotNone(rule.regex)
                if rule.allow_pattern:
                    self.assertIsNotNone(rule.allow_regex)

    def test_every_standard_control_has_at_least_one_rule(self) -> None:
        for control in self.profile.controls:
            with self.subTest(control=control):
                self.assertTrue(self.profile.rules_for_control(control))

    def test_explain_returns_machine_readable_rule(self) -> None:
        rule = explain_rule(self.profile, "SF-INJ-001")
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual("injection-prevention", rule["control"])
        self.assertEqual(["CWE-89"], rule["cwe"])
        self.assertIsNone(explain_rule(self.profile, "SF-NOPE-999"))

    def test_secret_rules_match_common_token_shapes(self) -> None:
        samples = {
            "SF-SEC-001": 'ApiKey = "prod_live_value_123"',
            "SF-SEC-002": "-----BEGIN RSA PRIVATE KEY-----",
            "SF-SEC-003": "token = ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "SF-SEC-004": "Server=db;Database=app;User Id=sa;Password=Sup3rS3cret!",
        }
        for rule_id, sample in samples.items():
            rule = self.profile.rules_by_id()[rule_id]
            with self.subTest(rule=rule_id):
                assert rule.regex is not None
                self.assertIsNotNone(rule.regex.search(sample), sample)

    def test_secret_allowlist_rejects_placeholders(self) -> None:
        rule = self.profile.rules_by_id()["SF-SEC-001"]
        assert rule.regex is not None and rule.allow_regex is not None
        sample = 'ApiKey = "your-api-key-here"'
        match = rule.regex.search(sample)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertIsNotNone(rule.allow_regex.search(sample))

    def test_status_parser_rejects_unknown_values(self) -> None:
        self.assertEqual(Status.PASS, Status.parse("PASS"))
        with self.assertRaises(ValueError):
            Status.parse("OK")


if __name__ == "__main__":
    unittest.main()
