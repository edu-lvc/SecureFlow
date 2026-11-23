"""Tests for the pfSense firewall auditor.

All tests use fixture XML files; no live firewall is contacted.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.support import EXAMPLES, REPO_ROOT, run_cli

from secureflow_gate.firewall.changes import (
    Change,
    ChangeError,
    apply_changes,
    audit_and_plan,
    plan_changes,
)
from secureflow_gate.firewall.model import ConfigParseError
from secureflow_gate.firewall.pfsense import analyze_pfsense, control_ids, parse_pfsense, redact_config_snippet
from secureflow_gate.firewall.reports import (
    FIREWALL_REPORT_SCHEMA,
    build_report,
    render_markdown,
)
from secureflow_gate.model import Status


FIXTURES = REPO_ROOT / "tests" / "fixtures" / "firewall"
SECURE = FIXTURES / "pfsense-secure.xml"
VULNERABLE = FIXTURES / "pfsense-vulnerable.xml"


class PfSenseParserTests(unittest.TestCase):
    def test_parse_valid_config(self) -> None:
        config = parse_pfsense(str(SECURE))
        self.assertEqual(config.vendor, "pfsense")
        self.assertEqual(config.version, "22.5")
        self.assertIsNotNone(config.find("./system/hostname"))

    def test_parse_missing_file_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "Configuration file not found"):
            parse_pfsense(str(REPO_ROOT / "does-not-exist.xml"))

    def test_parse_invalid_xml_raises(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tmp:
            tmp.write("<not-even-xml")
            path = tmp.name
        try:
            with self.assertRaises(ConfigParseError):
                parse_pfsense(path)
        finally:
            Path(path).unlink()

    def test_parse_wrong_root_raises(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tmp:
            tmp.write('<?xml version="1.0"?><other></other>')
            path = tmp.name
        try:
            with self.assertRaises(ConfigParseError):
                parse_pfsense(path)
        finally:
            Path(path).unlink()

    def test_evidence_has_line_numbers(self) -> None:
        config = parse_pfsense(str(SECURE))
        hostname = config.find("./system/hostname")
        self.assertIsNotNone(hostname)
        evidence = config.evidence(hostname)
        self.assertGreaterEqual(evidence.line, 1)
        self.assertIn("fw-secure", evidence.snippet)

    def test_redact_config_snippet_masks_passwords(self) -> None:
        raw = '<password>SuperSecret123</password>'
        redacted = redact_config_snippet(raw)
        self.assertNotIn("SuperSecret123", redacted)
        self.assertIn("***REDACTED***", redacted)


class PfSenseAnalyzerTests(unittest.TestCase):
    def _outcome_map(self, config_path: str):
        config = parse_pfsense(config_path)
        outcomes = analyze_pfsense(config)
        return {control_id: outcome for control_id, outcome in outcomes}

    def test_secure_config_passes_admin_and_rules(self) -> None:
        outcomes = self._outcome_map(str(SECURE))
        self.assertEqual(outcomes["admin-exposure"].status, Status.PASS)
        self.assertEqual(outcomes["rule-permissiveness"].status, Status.PASS)
        self.assertEqual(outcomes["nat-security"].status, Status.NOT_APPLICABLE)
        self.assertEqual(outcomes["segmentation"].status, Status.PASS)
        self.assertEqual(outcomes["logging-ntp"].status, Status.PASS)
        self.assertEqual(outcomes["vpn-security"].status, Status.NOT_APPLICABLE)
        # WAN uses DHCP: the RFC 1918 question cannot be answered from the
        # configuration alone, so the control stays UNVERIFIED instead of PASS.
        self.assertEqual(outcomes["interface-security"].status, Status.UNVERIFIED)
        self.assertEqual(outcomes["ipv6-security"].status, Status.NOT_APPLICABLE)

    def test_vulnerable_config_fails_multiple_controls(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        self.assertEqual(outcomes["admin-exposure"].status, Status.FAIL)
        self.assertEqual(outcomes["rule-permissiveness"].status, Status.FAIL)
        self.assertEqual(outcomes["nat-security"].status, Status.FAIL)
        self.assertEqual(outcomes["segmentation"].status, Status.UNVERIFIED)
        self.assertEqual(outcomes["logging-ntp"].status, Status.FAIL)
        self.assertEqual(outcomes["vpn-security"].status, Status.UNVERIFIED)
        self.assertEqual(outcomes["interface-security"].status, Status.UNVERIFIED)
        # IPv6 is enabled (wan ipaddrv6=dhcp6) but all rules are IPv4-only.
        self.assertEqual(outcomes["ipv6-security"].status, Status.UNVERIFIED)

    def test_http_webgui_is_fail(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["admin-exposure"].findings]
        self.assertIn("FW-ADMIN-001", rule_ids)

    def test_wan_ssh_rule_is_fail(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["admin-exposure"].findings]
        self.assertIn("FW-ADMIN-003", rule_ids)

    def test_overly_permissive_wan_rule_is_fail(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["rule-permissiveness"].findings]
        self.assertIn("FW-RULE-001", rule_ids)

    def test_sensitive_port_exposure_is_fail(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["rule-permissiveness"].findings]
        self.assertIn("FW-RULE-003", rule_ids)

    def test_conflicting_rules_are_unverified(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["rule-permissiveness"].findings]
        self.assertIn("FW-RULE-004", rule_ids)

    def test_port_forward_to_rdp_is_fail(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["nat-security"].findings]
        self.assertIn("FW-NAT-001", rule_ids)

    def test_shared_key_openvpn_is_unverified(self) -> None:
        outcomes = self._outcome_map(str(VULNERABLE))
        rule_ids = [f.rule_id for f in outcomes["vpn-security"].findings]
        self.assertIn("FW-VPN-002", rule_ids)


class FirewallReportTests(unittest.TestCase):
    def test_build_report_schema_and_integrity(self) -> None:
        config = parse_pfsense(str(SECURE))
        outcomes = analyze_pfsense(config)
        report = build_report(config, outcomes)
        self.assertEqual(report["schema_version"], FIREWALL_REPORT_SCHEMA)
        self.assertIn("integrity", report)
        self.assertIn("report_sha256", report["integrity"])
        # Secure fixture has no FAIL findings; UNVERIFIED comes from the
        # DHCP-assigned WAN address that cannot be verified statically.
        self.assertEqual(report["summary"]["overall_status"], Status.UNVERIFIED.value)
        self.assertEqual(report["device"]["vendor"], "pfsense")

    def test_markdown_contains_findings(self) -> None:
        config = parse_pfsense(str(VULNERABLE))
        outcomes = analyze_pfsense(config)
        report = build_report(config, outcomes)
        md = render_markdown(report)
        self.assertIn("FW-ADMIN-001", md)
        self.assertIn("Integrity", md)


class FirewallPlanApplyTests(unittest.TestCase):
    def test_plan_generates_changes_from_findings(self) -> None:
        config = parse_pfsense(str(VULNERABLE))
        outcomes = analyze_pfsense(config)
        changes = plan_changes(config, outcomes)
        self.assertTrue(changes)
        rule_ids = {change.xpath for change in changes}
        self.assertTrue(any("webgui/protocol" in x for x in rule_ids))

    def test_apply_without_confirm_raises(self) -> None:
        config = parse_pfsense(str(VULNERABLE))
        outcomes = analyze_pfsense(config)
        changes = plan_changes(config, outcomes)
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as out:
            output_path = out.name
        try:
            with self.assertRaises(ChangeError):
                apply_changes(str(VULNERABLE), changes, output_path, confirm=False)
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_apply_with_confirm_writes_output(self) -> None:
        config = parse_pfsense(str(VULNERABLE))
        outcomes = analyze_pfsense(config)
        changes = [Change(action="set_text", xpath="./system/webgui/protocol", description="test", value="https")]
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "out.xml"
            backup_path = Path(tmpdir) / "out.xml.bak"
            applied, _ = apply_changes(str(VULNERABLE), changes, str(output_path), backup_path=str(backup_path), confirm=True)
            self.assertTrue(output_path.is_file())
            self.assertTrue(backup_path.is_file())
            self.assertEqual(applied[0].get("status"), "applied")
            new_text = output_path.read_text(encoding="utf-8")
            self.assertIn("<protocol>https</protocol>", new_text)


class FirewallCliTests(unittest.TestCase):
    def test_audit_firewall_secure_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "report.json"
            completed = run_cli(
                "audit-firewall",
                "--config", str(SECURE),
                "--report", str(report),
            )
            self.assertEqual(completed.returncode, 0)
            data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["overall_status"], Status.UNVERIFIED.value)

    def test_audit_firewall_vulnerable_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "report.json"
            completed = run_cli(
                "audit-firewall",
                "--config", str(VULNERABLE),
                "--report", str(report),
            )
            self.assertEqual(completed.returncode, 1)
            data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["overall_status"], Status.FAIL.value)

    def test_plan_firewall_writes_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changes_path = Path(tmpdir) / "changes.json"
            completed = run_cli(
                "plan-firewall",
                "--config", str(VULNERABLE),
                "--changes", str(changes_path),
            )
            self.assertEqual(completed.returncode, 1)
            data = json.loads(changes_path.read_text(encoding="utf-8"))
            self.assertEqual(data.get("schema_version"), "secureflow.firewall.changes/v1")
            self.assertTrue(data.get("changes"))

    def test_apply_firewall_without_confirm_exits_three(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "out.xml"
            completed = run_cli(
                "apply-firewall",
                "--config", str(VULNERABLE),
                "--output", str(output_path),
            )
            self.assertEqual(completed.returncode, 3)
            self.assertFalse(output_path.exists())

    def test_apply_firewall_with_confirm_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            changes_path = Path(tmpdir) / "changes.json"
            run_cli("plan-firewall", "--config", str(VULNERABLE), "--changes", str(changes_path))
            output_path = Path(tmpdir) / "out.xml"
            completed = run_cli(
                "apply-firewall",
                "--config", str(VULNERABLE),
                "--output", str(output_path),
                "--plan", str(changes_path),
                "--confirm",
            )
            self.assertEqual(completed.returncode, 1)  # original audit still FAIL
            self.assertTrue(output_path.exists())


def _inline(
    inner_system: str = "",
    interfaces: str = "",
    filter_rules: str = "",
    rest: str = "",
) -> str:
    """Build a minimal pfSense configuration for focused analyzer tests."""
    if not interfaces:
        interfaces = (
            "  <interfaces>\n"
            "    <wan><enable/><if>em0</if><ipaddr>203.0.113.10</ipaddr><subnet>24</subnet></wan>\n"
            "    <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>\n"
            "  </interfaces>\n"
        )
    return (
        '<?xml version="1.0"?>\n'
        "<pfsense>\n"
        "  <version>24.0</version>\n"
        "  <system>\n"
        "    <hostname>fw-inline</hostname>\n"
        "%s"
        "  </system>\n"
        "%s"
        "  <filter>\n"
        "%s"
        "  </filter>\n"
        "%s"
        "</pfsense>\n"
    ) % (inner_system, interfaces, filter_rules, rest)


class _InlineCase(unittest.TestCase):
    def _outcomes(self, xml: str):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "inline.xml"
            path.write_text(xml, encoding="utf-8")
            config = parse_pfsense(str(path))
        return config, {cid: outcome for cid, outcome in analyze_pfsense(config)}


class SensitivePortContextTests(_InlineCase):
    """FW-RULE-003 must weigh interface, source and destination context."""

    def test_internal_restricted_rule_is_low_unverified(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>lan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><network>lan</network></source>\n"
            "      <destination><address>10.0.0.50</address><port>445</port></destination>\n"
            "      <descr>SMB to file server</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(filter_rules=rule))
        outcome = outcomes["rule-permissiveness"]
        self.assertEqual(outcome.status, Status.UNVERIFIED)
        findings = [f for f in outcome.findings if f.rule_id == "FW-RULE-003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].result, Status.UNVERIFIED)
        self.assertIn("internal access", findings[0].message.lower())

    def test_wan_exposed_rule_is_critical_fail(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><any/></source>\n"
            "      <destination><network>wanip</network><port>22</port></destination>\n"
            "      <descr>Allow SSH from WAN</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(filter_rules=rule))
        outcome = outcomes["rule-permissiveness"]
        self.assertEqual(outcome.status, Status.FAIL)
        findings = [f for f in outcome.findings if f.rule_id == "FW-RULE-003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].result, Status.FAIL)

    def test_internal_any_origin_rule_is_high_fail(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>lan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><any/></source>\n"
            "      <destination><address>10.0.0.50</address><port>135</port></destination>\n"
            "      <descr>RPC from anywhere</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(filter_rules=rule))
        outcome = outcomes["rule-permissiveness"]
        findings = [f for f in outcome.findings if f.rule_id == "FW-RULE-003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].result, Status.FAIL)
        self.assertEqual(outcome.status, Status.FAIL)

    def test_internal_broad_destination_is_medium_unverified(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>lan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><network>lan</network></source>\n"
            "      <destination><any/><port>445</port></destination>\n"
            "      <descr>SMB anywhere</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(filter_rules=rule))
        outcome = outcomes["rule-permissiveness"]
        findings = [f for f in outcome.findings if f.rule_id == "FW-RULE-003"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].result, Status.UNVERIFIED)
        self.assertEqual(outcome.status, Status.UNVERIFIED)


class NtpEvidenceTests(_InlineCase):
    """FW-LOG-004 must recognise pfSense >= 24.0 <system><timeservers>."""

    def test_system_timeservers_counts_as_ntp_evidence(self) -> None:
        xml = _inline(
            inner_system="    <timeservers>0.pool.ntp.org</timeservers>\n",
            rest='  <syslog><remoteserver>10.0.0.10</remoteserver></syslog>\n',
        )
        config, outcomes = self._outcomes(xml)
        outcome = outcomes["logging-ntp"]
        self.assertEqual(outcome.status, Status.PASS)
        ntp_checks = [c for c in outcome.checks if c.id == "ntp-servers"]
        self.assertEqual(len(ntp_checks), 1)
        self.assertEqual(ntp_checks[0].status, Status.PASS)
        self.assertTrue(ntp_checks[0].evidence)
        line = ntp_checks[0].evidence[0].line
        self.assertIn("timeservers", config.text.splitlines()[line - 1])
        rule_ids = [f.rule_id for f in outcome.findings]
        self.assertNotIn("FW-LOG-004", rule_ids)

    def test_missing_ntp_emits_fw_log_004(self) -> None:
        xml = _inline(rest='  <syslog><remoteserver>10.0.0.10</remoteserver></syslog>\n')
        _, outcomes = self._outcomes(xml)
        outcome = outcomes["logging-ntp"]
        rule_ids = [f.rule_id for f in outcome.findings]
        self.assertIn("FW-LOG-004", rule_ids)
        self.assertEqual(outcome.status, Status.UNVERIFIED)

    def test_empty_ntp_section_is_fw_log_003(self) -> None:
        xml = _inline(
            rest='  <syslog><remoteserver>10.0.0.10</remoteserver></syslog>\n  <ntp><timeservers></timeservers></ntp>\n'
        )
        _, outcomes = self._outcomes(xml)
        rule_ids = [f.rule_id for f in outcomes["logging-ntp"].findings]
        self.assertIn("FW-LOG-003", rule_ids)


class VpnPresenceTests(_InlineCase):
    """VPN security requires real tunnel children, not bare elements."""

    def test_empty_vpn_elements_are_not_applicable(self) -> None:
        xml = _inline(rest="  <ipsec></ipsec>\n  <openvpn></openvpn>\n")
        _, outcomes = self._outcomes(xml)
        outcome = outcomes["vpn-security"]
        self.assertEqual(outcome.status, Status.NOT_APPLICABLE)

    def test_ipsec_phase1_passes_with_evidence(self) -> None:
        xml = _inline(rest="  <ipsec><phase1><mode>main</mode><interface>wan</interface></phase1></ipsec>\n")
        _, outcomes = self._outcomes(xml)
        outcome = outcomes["vpn-security"]
        self.assertEqual(outcome.status, Status.PASS)
        self.assertTrue(outcome.checks)
        self.assertTrue(outcome.checks[0].evidence)


class Ipv6RuleTests(_InlineCase):
    """IPv6 analysis uses ipprotocol and only counts active rules."""

    _IPV6_WAN = (
        "  <interfaces>\n"
        "    <wan><enable/><if>em0</if><ipaddr>203.0.113.10</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan>\n"
        "    <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>\n"
        "  </interfaces>\n"
    )

    def test_disabled_ipv6_rule_does_not_count(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet6</ipprotocol>\n"
            "      <source><any/></source>\n"
            "      <destination><any/></destination>\n"
            "      <descr>Disabled IPv6 allow</descr>\n"
            "      <disabled></disabled>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(interfaces=self._IPV6_WAN, filter_rules=rule))
        outcome = outcomes["ipv6-security"]
        self.assertEqual(outcome.status, Status.UNVERIFIED)
        self.assertIn("FW-IPV6-001", [f.rule_id for f in outcome.findings])

    def test_active_ipv6_rule_passes_with_evidence(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>block</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet6</ipprotocol>\n"
            "      <source><any/></source>\n"
            "      <destination><any/></destination>\n"
            "      <descr>Block IPv6 inbound</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(interfaces=self._IPV6_WAN, filter_rules=rule))
        outcome = outcomes["ipv6-security"]
        self.assertEqual(outcome.status, Status.PASS)
        checks = [c for c in outcome.checks if c.id == "ipv6-rules"]
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0].evidence)

    def test_ipv4_wan_rules_do_not_count_as_ipv6(self) -> None:
        # Regression: the old heuristic treated any WAN-interface rule as an
        # IPv6 rule.
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><any/></source>\n"
            "      <destination><network>wanip</network><port>443</port></destination>\n"
            "      <descr>IPv4 HTTPS</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(interfaces=self._IPV6_WAN, filter_rules=rule))
        outcome = outcomes["ipv6-security"]
        self.assertEqual(outcome.status, Status.UNVERIFIED)
        self.assertIn("FW-IPV6-001", [f.rule_id for f in outcome.findings])


class EvidenceLineTests(_InlineCase):
    """Evidence lines must point at the exact XML element."""

    def test_rule_evidence_points_to_actual_rule(self) -> None:
        rules = (
            "    <rule>\n"
            "      <type>block</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <source><any/></source>\n"
            "      <destination><any/></destination>\n"
            "      <descr>First rule marker</descr>\n"
            "    </rule>\n"
            "    <rule>\n"
            "      <type>block</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <source><any/></source>\n"
            "      <destination><any/></destination>\n"
            "      <descr>Second rule marker</descr>\n"
            "    </rule>\n"
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>wan</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><any/></source>\n"
            "      <destination><network>wanip</network><port>22</port></destination>\n"
            "      <descr>Third rule marker SSH</descr>\n"
            "    </rule>\n"
        )
        config, outcomes = self._outcomes(_inline(filter_rules=rules))
        findings = [f for f in outcomes["rule-permissiveness"].findings if f.rule_id == "FW-RULE-003"]
        self.assertEqual(len(findings), 1)
        lines = config.text.splitlines()
        descr_line = next(i for i, line in enumerate(lines, 1) if "Third rule marker SSH" in line)
        expected = max(i for i, line in enumerate(lines[:descr_line], 1) if line.strip() == "<rule>")
        self.assertEqual(findings[0].evidence.line, expected)
        self.assertIn("Third rule marker SSH", findings[0].evidence.snippet)

    def test_filter_evidence_does_not_match_filterdescriptions(self) -> None:
        xml = (
            '<?xml version="1.0"?>\n'
            "<pfsense>\n"
            "  <version>24.0</version>\n"
            "  <system>\n"
            "    <hostname>fw-inline</hostname>\n"
            "    <timeservers>0.pool.ntp.org</timeservers>\n"
            "  </system>\n"
            "  <interfaces>\n"
            "    <wan><enable/><if>em0</if><ipaddr>203.0.113.10</ipaddr><ipaddrv6>dhcp6</ipaddrv6></wan>\n"
            "    <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>\n"
            "  </interfaces>\n"
            "  <syslog><remoteserver>10.0.0.10</remoteserver><filterdescriptions>1</filterdescriptions></syslog>\n"
            "  <filter>\n"
            "  </filter>\n"
            "</pfsense>\n"
        )
        config, outcomes = self._outcomes(xml)
        findings = [f for f in outcomes["ipv6-security"].findings if f.rule_id == "FW-IPV6-001"]
        self.assertEqual(len(findings), 1)
        line = findings[0].evidence.line
        self.assertEqual(config.text.splitlines()[line - 1].strip(), "<filter>")


REAL_CONFIG = REPO_ROOT / "tests" / "config-pfsense.utp.local-20261016052206.xml"


@unittest.skipUnless(REAL_CONFIG.is_file(), "real pfSense export not present")
class RealConfigEvidenceTests(unittest.TestCase):
    """Evidence lines in the real pfSense 24.0 export must match the XML."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = parse_pfsense(str(REAL_CONFIG))
        cls.outcomes = {cid: outcome for cid, outcome in analyze_pfsense(cls.config)}
        cls.lines = cls.config.text.splitlines()

    def _finding(self, control: str, rule_id: str):
        found = [f for f in self.outcomes[control].findings if f.rule_id == rule_id]
        self.assertTrue(found, "%s not present in %s" % (rule_id, control))
        return found[0]

    def test_admin_and_syslog_lines(self) -> None:
        admin = self._finding("admin-exposure", "FW-ADMIN-001")
        self.assertEqual(self.lines[admin.evidence.line - 1].strip(), "<webgui>")
        syslog = self._finding("logging-ntp", "FW-LOG-001")
        self.assertEqual(self.lines[syslog.evidence.line - 1].strip(), "<syslog>")

    def test_ntp_found_via_system_timeservers(self) -> None:
        rule_ids = [f.rule_id for f in self.outcomes["logging-ntp"].findings]
        self.assertNotIn("FW-LOG-004", rule_ids)
        self.assertNotIn("FW-LOG-003", rule_ids)
        ntp_checks = [c for c in self.outcomes["logging-ntp"].checks if c.id == "ntp-servers"]
        self.assertEqual(len(ntp_checks), 1)
        line = ntp_checks[0].evidence[0].line
        self.assertIn("timeservers", self.lines[line - 1])

    def test_rule_findings_point_to_their_own_rules(self) -> None:
        findings = [f for f in self.outcomes["rule-permissiveness"].findings if f.rule_id == "FW-RULE-003"]
        self.assertTrue(findings)
        sensitive = {"22", "23", "135", "139", "445", "3389", "5900", "5800"}
        seen_lines = set()
        for finding in findings:
            line = finding.evidence.line
            self.assertNotIn(line, seen_lines, "two findings share evidence line %d" % line)
            seen_lines.add(line)
            self.assertEqual(self.lines[line - 1].strip(), "<rule>")
            self.assertTrue(finding.evidence.snippet.startswith("<rule"))
            # The rule this line points at must actually carry a sensitive port.
            block_lines = []
            for raw in self.lines[line - 1 :]:
                block_lines.append(raw)
                if "</rule>" in raw:
                    break
            ports = re.findall(r"<port>(\d+)</port>", "\n".join(block_lines))
            self.assertTrue(
                any(port in sensitive for port in ports),
                "rule at line %d has no sensitive port (found %s)" % (line, ports),
            )

    def test_ipv6_finding_points_to_filter_element(self) -> None:
        finding = self._finding("ipv6-security", "FW-IPV6-001")
        self.assertEqual(self.lines[finding.evidence.line - 1].strip(), "<filter>")

    def test_sensitive_rules_are_low_severity_in_context(self) -> None:
        findings = [f for f in self.outcomes["rule-permissiveness"].findings if f.rule_id == "FW-RULE-003"]
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding.severity, "low")
            self.assertEqual(finding.result, Status.UNVERIFIED)


class SegmentationTests(_InlineCase):
    """WiFi/guest isolation and evidence-carrying PASS checks."""

    _GUEST_IFACES = (
        "  <interfaces>\n"
        "    <wan><enable/><if>em0</if><ipaddr>203.0.113.10</ipaddr></wan>\n"
        "    <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>\n"
        "    <opt3><enable/><if>em4</if><descr>WiFi</descr><ipaddr>172.16.20.1</ipaddr><subnet>24</subnet></opt3>\n"
        "  </interfaces>\n"
    )

    def test_wifi_block_to_lan_passes_with_evidence(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>block</type>\n"
            "      <interface>opt3</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <source><network>opt3</network></source>\n"
            "      <destination><network>lan</network></destination>\n"
            "      <descr>Block WiFi to LAN</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(interfaces=self._GUEST_IFACES, filter_rules=rule))
        outcome = outcomes["segmentation"]
        self.assertEqual(outcome.status, Status.PASS)
        guest_checks = [c for c in outcome.checks if c.id == "guest-isolation"]
        self.assertEqual(len(guest_checks), 1)
        self.assertEqual(guest_checks[0].status, Status.PASS)
        self.assertTrue(guest_checks[0].evidence)

    def test_wifi_broad_allow_flags_guest_isolation(self) -> None:
        rule = (
            "    <rule>\n"
            "      <type>pass</type>\n"
            "      <interface>opt3</interface>\n"
            "      <ipprotocol>inet</ipprotocol>\n"
            "      <protocol>tcp</protocol>\n"
            "      <source><network>opt3</network></source>\n"
            "      <destination><any/><port>443</port></destination>\n"
            "      <descr>WiFi HTTPS anywhere</descr>\n"
            "    </rule>\n"
        )
        _, outcomes = self._outcomes(_inline(interfaces=self._GUEST_IFACES, filter_rules=rule))
        outcome = outcomes["segmentation"]
        self.assertEqual(outcome.status, Status.UNVERIFIED)
        self.assertIn("FW-SEG-003", [f.rule_id for f in outcome.findings])

    def test_dmz_block_check_carries_evidence(self) -> None:
        config = parse_pfsense(str(SECURE))
        outcomes = {cid: outcome for cid, outcome in analyze_pfsense(config)}
        checks = [c for c in outcomes["segmentation"].checks if c.id == "dmz-to-lan-block"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].status, Status.PASS)
        self.assertTrue(checks[0].evidence)
        line = checks[0].evidence[0].line
        self.assertEqual(config.text.splitlines()[line - 1].strip(), "<rule>")


class InterfaceSecurityTests(_InlineCase):
    """DHCP-assigned WAN addresses must not be reported as verified PASS."""

    def test_dhcp_wan_yields_unverified_address_check(self) -> None:
        config = parse_pfsense(str(SECURE))
        outcomes = {cid: outcome for cid, outcome in analyze_pfsense(config)}
        outcome = outcomes["interface-security"]
        self.assertEqual(outcome.status, Status.UNVERIFIED)
        wan_checks = [c for c in outcome.checks if c.id == "wan-address"]
        self.assertEqual(len(wan_checks), 1)
        self.assertEqual(wan_checks[0].status, Status.UNVERIFIED)
        self.assertTrue(wan_checks[0].evidence)

    def test_static_public_wan_passes_with_evidence(self) -> None:
        _, outcomes = self._outcomes(_inline())
        outcome = outcomes["interface-security"]
        self.assertEqual(outcome.status, Status.PASS)
        wan_checks = [c for c in outcome.checks if c.id == "wan-address"]
        self.assertEqual(wan_checks[0].status, Status.PASS)
        self.assertTrue(wan_checks[0].evidence)
        enabled_checks = [c for c in outcome.checks if c.id == "interface-enabled"]
        self.assertTrue(enabled_checks and enabled_checks[0].evidence)

    def test_rfc1918_wan_is_flagged(self) -> None:
        interfaces = (
            "  <interfaces>\n"
            "    <wan><enable/><if>em0</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></wan>\n"
            "    <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>\n"
            "  </interfaces>\n"
        )
        _, outcomes = self._outcomes(_inline(interfaces=interfaces))
        outcome = outcomes["interface-security"]
        self.assertIn("FW-IFACE-001", [f.rule_id for f in outcome.findings])
        self.assertEqual(outcome.status, Status.UNVERIFIED)


class ReportSecretsTests(_InlineCase):
    """Reports must never leak credentials, hashes or private keys."""

    _SECRET_XML = (
        '<?xml version="1.0"?>\n'
        "<pfsense>\n"
        "  <version>24.0</version>\n"
        "  <system>\n"
        "    <hostname>fw-secret</hostname>\n"
        "    <password>TopSecretPw1</password>\n"
        "    <bcrypt-hash>$2y$10$abcdefghijklmnopqrstuv</bcrypt-hash>\n"
        "    <webgui>\n"
        "      <protocol>http</protocol>\n"
        "      <key>PRIVATEKEYDATA</key>\n"
        "    </webgui>\n"
        "  </system>\n"
        "  <interfaces>\n"
        "    <wan><enable/><if>em0</if><ipaddr>203.0.113.10</ipaddr></wan>\n"
        "    <lan><enable/><if>em1</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan>\n"
        "  </interfaces>\n"
        "  <filter>\n"
        "  </filter>\n"
        "</pfsense>\n"
    )

    def test_report_contains_no_secrets(self) -> None:
        config, outcomes_list = self._outcomes(self._SECRET_XML)
        report = build_report(config, list(outcomes_list.items()))
        md = render_markdown(report)
        blob = json.dumps(report) + md
        self.assertNotIn("TopSecretPw1", blob)
        self.assertNotIn("PRIVATEKEYDATA", blob)
        self.assertNotIn("$2y$10$abcdefghijklmnopqrstuv", blob)
        self.assertIn("***REDACTED***", blob)


if __name__ == "__main__":
    unittest.main()
