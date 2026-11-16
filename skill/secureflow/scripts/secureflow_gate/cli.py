"""Command line interface for SecureFlow Gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import POLICY_SCHEMA, __version__
from .claims import ClaimsError
from .engine import GateError, exit_code_for, run_scan
from .policy import PolicyError
from .report import ReportError, verify_report, write_json, write_markdown
from .rules import RulePackError, explain_rule, load_profile


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
    _print_summary(report)
    if args.report:
        print("Report: %s" % Path(args.report).resolve())
    if args.markdown:
        print("Markdown: %s" % Path(args.markdown).resolve())
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


def _cmd_version(_args: argparse.Namespace) -> int:
    print("secureflow-gate %s" % __version__)
    return 0


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

    version = subparsers.add_parser("version", help="Print the gate version.")
    version.set_defaults(func=_cmd_version)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (GateError, PolicyError, ClaimsError, RulePackError, ReportError, OSError, ValueError) as exc:
        print("secureflow-gate: %s" % exc, file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("secureflow-gate: interrupted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
