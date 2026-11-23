"""Command line interface for SecureFlow Gate."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import POLICY_SCHEMA, __version__
from .claims import ClaimsError
from .engine import GateError, exit_code_for, run_scan
from .incident import IncidentError, init_incident
from .policy import PolicyError
from .report import ReportError, verify_report, write_json, write_markdown
from .rules import RulePackError, explain_rule, load_profile


try:
    from .detections.coverage import build_coverage
    from .detections.sigma import sigma_to_json, sigma_to_yaml

    _DETECTIONS_AVAILABLE = True
except Exception:  # noqa: BLE001
    _DETECTIONS_AVAILABLE = False
    build_coverage = None  # type: ignore[assignment]
    sigma_to_yaml = None  # type: ignore[assignment]


try:
    from .firewall.changes import ChangeError, apply_changes, audit_and_plan, apply_plan_and_verify
    from .firewall.pfsense import parse_pfsense, analyze_pfsense
    from .firewall.reports import (
        build_report as build_firewall_report,
        render_markdown as render_firewall_markdown,
        write_json as write_firewall_json,
        write_markdown as write_firewall_markdown,
    )
    _FIREWALL_AVAILABLE = True
except Exception:  # noqa: BLE001 - optional firewall module must not break the gate
    _FIREWALL_AVAILABLE = False
    ChangeError = GateError


def _print_summary(report) -> None:
    summary = report.get("summary", {})
    print("SecureFlow Gate %s" % __version__)
    print("Overall: %s" % summary.get("overall_status", "UNVERIFIED"))
    print("Profile: %s" % report.get("scan", {}).get("profile", ""))
    print("Files scanned: %s" % report.get("scan", {}).get("files_scanned", 0))
    for control in report.get("controls", []):
        print(
            "  %-18s %-14s %s"
            % (control.get("id", ""), control.get("status", ""), control.get("reason", ""))
        )
    findings = report.get("findings", [])
    if findings:
        print("Findings and unresolved checks: %d" % len(findings))
        for finding in findings[:20]:
            evidence = finding.get("evidence", {})
            print(
                "  %-14s %s:%s  %s"
                % (
                    finding.get("rule_id", ""),
                    evidence.get("path", ""),
                    evidence.get("line", ""),
                    finding.get("title", ""),
                )
            )
        if len(findings) > 20:
            print("  ... %d more" % (len(findings) - 20))
    if report.get("summary", {}).get("suppressed_count"):
        print("Policy-suppressed findings: %d" % report["summary"]["suppressed_count"])
    claims = report.get("claims_audit")
    if claims:
        counts = claims.get("summary", {})
        print(
            "Claims: accepted=%s rejected=%s contradictions=%s unverified=%s"
            % (
                counts.get("accepted", 0),
                counts.get("rejected", 0),
                counts.get("contradictions", 0),
                counts.get("unverified", 0),
            )
        )


    if report.get("detections"):
        det = report["detections"]
        print("Detection coverage: %d control(s) covered, %d rule(s) generated" % (
            len(det.get("covered_controls", [])),
            det.get("sigma_rules_generated", 0),
        ))


def _write_sigma_rules(report: Dict[str, Any], out_dir: str, fmt: str) -> int:
    if not _DETECTIONS_AVAILABLE:
        raise GateError("Detection module is not available.")
    sigma_rules = report.get("detections", {}).get("sigma_rules", [])
    if not sigma_rules:
        # Recompute from the report contents in case the schema was stripped.
        control_ids = [c["id"] for c in report.get("controls", [])]
        sigma_rules = build_coverage(report.get("findings", []), control_ids).get("sigma_rules", [])
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for rule in sigma_rules:
        filename = re.sub(r"[^A-Za-z0-9._-]+", "_", rule.get("id", "rule-%d" % count))
        filename = filename.strip("._")
        if not filename:
            filename = "rule-%d" % count
        suffix = ".json" if fmt == "json" else ".yml"
        path = output / (filename + suffix)
        if fmt == "json":
            path.write_text(sigma_to_json(rule) + "\n", encoding="utf-8")
        else:
            path.write_text(sigma_to_yaml(rule) + "\n", encoding="utf-8")
        count += 1
    print("Sigma rules written: %d" % count)
    return count


def _cmd_scan(args: argparse.Namespace) -> int:
    report = run_scan(
        root=args.root,
        profile_name=args.profile,
        report_path=args.report,
        markdown_path=args.markdown,
        claims_path=args.claims,
        policy_path=args.policy,
        build=args.build,
    )
    if args.report:
        write_json(report, args.report)
    if args.markdown:
        write_markdown(report, args.markdown)
    if args.sigma_out:
        _write_sigma_rules(report, args.sigma_out, args.sigma_format)
    _print_summary(report)
    if args.report:
        print("Report: %s" % Path(args.report).resolve())
    if args.markdown:
        print("Markdown: %s" % Path(args.markdown).resolve())
    if args.sigma_out:
        print("Sigma rules: %s" % Path(args.sigma_out).resolve())
    return exit_code_for(report, args.fail_on)


def _cmd_verify(args: argparse.Namespace) -> int:
    result = verify_report(args.report, args.root)
    if result.valid:
        print("Report integrity verified.")
        if result.warnings:
            for warning in result.warnings:
                print("Warning: %s" % warning, file=sys.stderr)
        return 0
    print("Report integrity verification failed:", file=sys.stderr)
    for error in result.errors:
        print("  - %s" % error, file=sys.stderr)
    return 4


def _cmd_explain(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile)
    rule = explain_rule(profile, args.rule)
    if rule is None:
        raise GateError("Unknown rule: %s" % args.rule)
    print(json.dumps(rule, indent=2, ensure_ascii=False))
    return 0


def _cmd_init_policy(args: argparse.Namespace) -> int:
    target = Path(args.output)
    if target.exists() and not args.force:
        raise GateError("Refusing to overwrite existing policy without --force: %s" % target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "schema_version": POLICY_SCHEMA,
                "suppressions": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Policy written to %s" % target.resolve())
    return 0


def _cmd_init_incident(args: argparse.Namespace) -> int:
    written = init_incident(args.output, force=args.force)
    print("Incident response templates written to %s" % Path(args.output).resolve())
    for path in written:
        print("  - %s" % path.name)
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print("secureflow-gate %s" % __version__)
    return 0


def _cmd_generate_sigma(args: argparse.Namespace) -> int:
    if not _DETECTIONS_AVAILABLE:
        raise GateError("Detection module is not available.")
    report_path = Path(args.report)
    if not report_path.is_file():
        raise GateError("Report file not found: %s" % report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("schema_version") != "secureflow.gate.report/v1":
        raise GateError("Report schema_version must be secureflow.gate.report/v1")
    _write_sigma_rules(report, args.out, args.sigma_format)
    return 0


def _print_firewall_summary(report: Dict[str, Any]) -> None:
    summary = report.get("summary", {})
    device = report.get("device", {})
    print("SecureFlow Firewall %s" % __version__)
    print("Overall: %s" % summary.get("overall_status", "UNVERIFIED"))
    print("Device: %s %s (%s)" % (device.get("vendor", ""), device.get("version") or "unknown", device.get("hostname", "")))
    print("Config: %s" % report.get("config", {}).get("path", ""))
    for control in report.get("controls", []):
        print(
            "  %-22s %-14s %s"
            % (control.get("id", ""), control.get("status", ""), control.get("reason", ""))
        )
    findings = report.get("findings", [])
    if findings:
        print("Findings: %d" % len(findings))
        for finding in findings[:20]:
            evidence = finding.get("evidence", {})
            print(
                "  %-14s %s:%s  %s"
                % (
                    finding.get("rule_id", ""),
                    evidence.get("path", ""),
                    evidence.get("line", ""),
                    finding.get("title", ""),
                )
            )
        if len(findings) > 20:
            print("  ... %d more" % (len(findings) - 20))
    proposed = report.get("proposed_changes", [])
    if proposed:
        print("Proposed changes: %d" % len(proposed))
    applied = report.get("applied_changes", [])
    if applied:
        applied_count = sum(1 for c in applied if c.get("status") == "applied")
        skipped_count = len(applied) - applied_count
        print("Applied changes: %d, skipped: %d" % (applied_count, skipped_count))


def _cmd_audit_firewall(args: argparse.Namespace) -> int:
    if not _FIREWALL_AVAILABLE:
        raise GateError("Firewall module is not available.")
    if args.vendor != "pfsense":
        raise GateError("Unsupported firewall vendor: %s" % args.vendor)
    config = parse_pfsense(args.config)
    outcomes = analyze_pfsense(config)
    report = build_firewall_report(config, outcomes, operation="audit")
    if args.report:
        write_firewall_json(report, args.report)
    if args.markdown:
        write_firewall_markdown(report, args.markdown)
    _print_firewall_summary(report)
    return exit_code_for(report, args.fail_on)


def _cmd_plan_firewall(args: argparse.Namespace) -> int:
    if not _FIREWALL_AVAILABLE:
        raise GateError("Firewall module is not available.")
    if args.vendor != "pfsense":
        raise GateError("Unsupported firewall vendor: %s" % args.vendor)
    config, outcomes, changes = audit_and_plan(args.config)
    proposed = [change.to_dict() for change in changes]
    report = build_firewall_report(config, outcomes, operation="plan", proposed_changes=proposed)
    if args.report:
        write_firewall_json(report, args.report)
    if args.markdown:
        write_firewall_markdown(report, args.markdown)
    if args.changes:
        Path(args.changes).write_text(
            json.dumps({"schema_version": "secureflow.firewall.changes/v1", "changes": proposed}, indent=2) + "\n",
            encoding="utf-8",
        )
        print("Proposed changes: %s" % Path(args.changes).resolve())
    _print_firewall_summary(report)
    return exit_code_for(report, args.fail_on)


def _cmd_apply_firewall(args: argparse.Namespace) -> int:
    if not _FIREWALL_AVAILABLE:
        raise GateError("Firewall module is not available.")
    if args.vendor != "pfsense":
        raise GateError("Unsupported firewall vendor: %s" % args.vendor)
    if not args.confirm:
        raise GateError(
            "apply-firewall requires explicit --confirm after reviewing the plan. "
            "Use plan-firewall to preview changes."
        )

    if args.plan:
        from .firewall.changes import Change

        data = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != "secureflow.firewall.changes/v1":
            raise GateError("Changes file schema_version must be secureflow.firewall.changes/v1")
        changes = [Change(**entry) for entry in data.get("changes", [])]
    else:
        _, _, changes = audit_and_plan(args.config)

    applied, output_path, verify_report = apply_plan_and_verify(
        args.config,
        changes,
        args.output,
        backup_path=args.backup,
        confirm=True,
    )
    verification = {
        "status": verify_report.get("summary", {}).get("overall_status", "UNVERIFIED"),
        "reason": "Re-audit of %s after applying changes." % output_path,
        "report": verify_report,
    }
    original_config = parse_pfsense(args.config)
    original_outcomes = analyze_pfsense(original_config)
    original_proposed = [change.to_dict() for change in changes]
    report = build_firewall_report(
        original_config,
        original_outcomes,
        operation="apply",
        proposed_changes=original_proposed,
        applied_changes=applied,
        verification=verification,
    )
    if args.report:
        write_firewall_json(report, args.report)
    if args.markdown:
        write_firewall_markdown(report, args.markdown)
    _print_firewall_summary(report)
    return exit_code_for(report, args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    class _Parser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            self.print_usage(sys.stderr)
            self.exit(3, "%s: error: %s\n" % (self.prog, message))

    parser = _Parser(
        prog="secureflow-gate",
        description="Evidence-based security gate for the SecureFlow Agent Skill.",
    )
    parser.add_argument("--version", action="version", version="secureflow-gate %s" % __version__)
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    scan = subparsers.add_parser("scan", help="Scan a project and produce a gate report.")
    scan.add_argument("--root", default=".", help="Project root to scan. Defaults to the current directory.")
    scan.add_argument("--profile", default="csharp-aspnetcore", help="Rule profile to use.")
    scan.add_argument("--report", help="Write the machine-readable JSON report to this path.")
    scan.add_argument("--markdown", help="Write a human-readable Markdown report to this path.")
    scan.add_argument("--claims", help="Audit an agent claims JSON file.")
    scan.add_argument("--policy", help="Apply a suppression policy JSON file.")
    scan.add_argument(
        "--fail-on",
        choices=("fail", "unverified", "never"),
        default="fail",
        help="Exit non-zero on FAIL, on FAIL or UNVERIFIED, or never.",
    )
    scan.add_argument(
        "--build",
        action="store_true",
        help="Opt in to a dotnet build adapter. Build targets are executed with the project's permissions.",
    )
    scan.add_argument("--sigma-out", help="Write generated Sigma rules to this directory.")
    scan.add_argument(
        "--sigma-format",
        choices=("yaml", "json"),
        default="yaml",
        help="Format for generated Sigma rules.",
    )
    scan.set_defaults(func=_cmd_scan)

    verify = subparsers.add_parser("verify-report", help="Verify report hash, file hashes, and inventory.")
    verify.add_argument("--report", required=True, help="Report JSON path.")
    verify.add_argument("--root", help="Override the scan root stored in the report.")
    verify.set_defaults(func=_cmd_verify)

    explain = subparsers.add_parser("explain", help="Print a rule definition as JSON.")
    explain.add_argument("--rule", required=True, help="Rule identifier, for example SF-INJ-001.")
    explain.add_argument("--profile", default="csharp-aspnetcore", help="Rule profile to load.")
    explain.set_defaults(func=_cmd_explain)

    init_policy = subparsers.add_parser("init-policy", help="Create an empty suppression policy.")
    init_policy.add_argument("--output", default="secureflow-policy.json", help="Policy output path.")
    init_policy.add_argument("--force", action="store_true", help="Overwrite an existing policy file.")
    init_policy.set_defaults(func=_cmd_init_policy)

    init_incident = subparsers.add_parser("init-incident", help="Create incident response templates.")
    init_incident.add_argument("--output", default="incident-response", help="Output directory for templates.")
    init_incident.add_argument("--force", action="store_true", help="Overwrite an existing directory.")
    init_incident.set_defaults(func=_cmd_init_incident)

    version = subparsers.add_parser("version", help="Print the gate version.")
    version.set_defaults(func=_cmd_version)

    if _DETECTIONS_AVAILABLE:
        sigma = subparsers.add_parser(
            "generate-sigma",
            help="Generate Sigma detection rules from a SecureFlow gate report.",
        )
        sigma.add_argument("--report", required=True, help="Path to a SecureFlow gate report JSON.")
        sigma.add_argument("--out", required=True, help="Output directory for Sigma rules.")
        sigma.add_argument(
            "--format",
            dest="sigma_format",
            choices=("yaml", "json"),
            default="yaml",
            help="Output format for generated rules.",
        )
        sigma.set_defaults(func=_cmd_generate_sigma)

    if _FIREWALL_AVAILABLE:
        audit_fw = subparsers.add_parser("audit-firewall", help="Audit a firewall configuration export (read-only).")
        audit_fw.add_argument("--config", required=True, help="Path to the firewall configuration file.")
        audit_fw.add_argument("--vendor", default="pfsense", choices=["pfsense"], help="Firewall vendor.")
        audit_fw.add_argument("--report", help="Write the machine-readable JSON report to this path.")
        audit_fw.add_argument("--markdown", help="Write a human-readable Markdown report to this path.")
        audit_fw.add_argument(
            "--fail-on",
            choices=("fail", "unverified", "never"),
            default="fail",
            help="Exit non-zero on FAIL, on FAIL or UNVERIFIED, or never.",
        )
        audit_fw.set_defaults(func=_cmd_audit_firewall)

        plan_fw = subparsers.add_parser("plan-firewall", help="Audit and generate a remediation plan (read-only).")
        plan_fw.add_argument("--config", required=True, help="Path to the firewall configuration file.")
        plan_fw.add_argument("--vendor", default="pfsense", choices=["pfsense"], help="Firewall vendor.")
        plan_fw.add_argument("--report", help="Write the machine-readable JSON report to this path.")
        plan_fw.add_argument("--markdown", help="Write a human-readable Markdown report to this path.")
        plan_fw.add_argument("--changes", help="Write proposed changes JSON to this path.")
        plan_fw.add_argument(
            "--fail-on",
            choices=("fail", "unverified", "never"),
            default="fail",
            help="Exit non-zero on FAIL, on FAIL or UNVERIFIED, or never.",
        )
        plan_fw.set_defaults(func=_cmd_plan_firewall)

        apply_fw = subparsers.add_parser("apply-firewall", help="Apply a remediation plan to a configuration file.")
        apply_fw.add_argument("--config", required=True, help="Path to the original firewall configuration file.")
        apply_fw.add_argument("--output", required=True, help="Path for the modified configuration file.")
        apply_fw.add_argument("--vendor", default="pfsense", choices=["pfsense"], help="Firewall vendor.")
        apply_fw.add_argument("--plan", help="JSON changes file produced by plan-firewall.")
        apply_fw.add_argument("--backup", help="Path for the backup of the original configuration.")
        apply_fw.add_argument("--confirm", action="store_true", help="Confirm that the plan has been reviewed and should be applied.")
        apply_fw.add_argument("--report", help="Write the machine-readable JSON report to this path.")
        apply_fw.add_argument("--markdown", help="Write a human-readable Markdown report to this path.")
        apply_fw.add_argument(
            "--fail-on",
            choices=("fail", "unverified", "never"),
            default="fail",
            help="Exit non-zero on FAIL, on FAIL or UNVERIFIED, or never.",
        )
        apply_fw.set_defaults(func=_cmd_apply_firewall)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (GateError, PolicyError, ClaimsError, RulePackError, ReportError, ChangeError, IncidentError, OSError, ValueError) as exc:
        print("secureflow-gate: %s" % exc, file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("secureflow-gate: interrupted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
