"""Scan orchestration and report construction."""

from __future__ import annotations

import datetime as _dt
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import __version__, REPORT_SCHEMA
from .analyzers import (
    analyze_authentication,
    analyze_authorization,
    analyze_injection,
    analyze_input_validation,
    analyze_secrets,
    analyze_security_logging,
)
from .claims import ClaimsError, audit_claims, load_claims
from .csharp import parse_csharp
from .globs import matches_any
from .model import (
    Check,
    ControlOutcome,
    Evidence,
    Finding,
    ScanFile,
    Status,
    snippet_hash,
    worst_status,
)
from .detections.coverage import build_coverage
from .policy import PolicyError, apply_policy, load_policy
from .redact import redact_snippet
from .report import finalize_report
from .rules import ControlDef, Profile, Rule, load_profile
from .scanner import inventory_sha256, scan_tree


class GateError(ValueError):
    pass


_LIMITATIONS = [
    "Static analysis only. The gate does not execute target code, exploit findings, or prove the absence of vulnerabilities.",
    "The C# parser is intentionally small. Unusual syntax, generated code, and custom frameworks may not be recognized.",
    "Explicit [AllowAnonymous] mutating endpoints are treated as intentional exposure and are not reported as authorization failures.",
    "Object-level authorization and IDOR are not assessed beyond route or controller requirements.",
    "Secret detection is pattern based. Encoded, encrypted, split, or dynamically assembled secrets may be missed.",
    "Only the C# / ASP.NET Core profile is deeply implemented. Other ecosystems need additional rule packs and analyzers.",
    "Policy suppressions are explicit, reasoned, and time bounded, but they still hide an active finding from the gate status.",
    "Claims are validated against current file lines. A claim never changes a gate status.",
    "The optional dotnet build adapter compiles the project and may execute build targets. It is not a sandbox.",
]


def _language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".cs": "csharp",
        ".json": "json",
        ".xml": "xml",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".ps1": "powershell",
        ".sh": "shell",
        ".fs": "fsharp",
        ".vb": "vbnet",
    }.get(suffix, "text")


def _line_starts(text: str) -> List[int]:
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _run_regex_rules(files: Sequence[ScanFile], profile: Profile, warnings: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for file in files:
        language = _language(file.relpath)
        starts = _line_starts(file.text)
        for rule in profile.rules:
            if rule.kind != "regex" or rule.regex is None:
                continue
            if rule.include and not matches_any(file.relpath, rule.include):
                continue
            if rule.exclude and matches_any(file.relpath, rule.exclude):
                continue
            matches: List[Tuple[int, int]] = []
            for index, line in enumerate(file.text.splitlines()):
                if rule.allow_regex is not None and rule.allow_regex.search(line):
                    continue
                for match in rule.regex.finditer(line):
                    position = starts[index] + match.start()
                    matches.append((position, match.end()))
                    if len(matches) >= 500:
                        warnings.append("Rule %s produced more than 500 matches in %s" % (rule.id, file.relpath))
                        break
                if len(matches) >= 500:
                    break
            if len(matches) < rule.min_matches:
                continue
            for position, _ in matches:
                line_number = file.text.count("\n", 0, position) + 1
                last_newline = file.text.rfind("\n", 0, position)
                column = position - last_newline
                key = (rule.id, file.relpath, line_number, column)
                if key in seen:
                    continue
                seen.add(key)
                raw_line = file.line(line_number)
                snippet = raw_line.strip()
                if rule.control == "secrets-management":
                    snippet = redact_snippet(snippet)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        control=rule.control,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        result=Status.FAIL if rule.mode == "finding" else Status.UNVERIFIED,
                        message=rule.message,
                        remediation=rule.remediation,
                        cwe=list(rule.cwe),
                        asvs=list(rule.asvs),
                        owasp=list(rule.owasp),
                        mitre_attack=list(rule.mitre_attack),
                        telemetry_sources=list(rule.telemetry_sources),
                        evidence=Evidence(
                            path=file.relpath,
                            line=line_number,
                            column=column,
                            snippet=snippet,
                            snippet_sha256=snippet_hash(snippet),
                            language=language,
                        ),
                    )
                )
    return findings


def _run_analyzers(
    files: Sequence[ScanFile],
    profile: Profile,
    regex_findings: Sequence[Finding],
) -> List[ControlOutcome]:
    rules = profile.rules_by_id()
    secret_findings = [finding for finding in regex_findings if finding.control == "secrets-management"]
    model = parse_csharp(files)
    outcomes: List[ControlOutcome] = []
    for control in [profile.controls[key] for key in sorted(profile.controls)]:
        if "secrets" in control.analyzers:
            outcome = analyze_secrets(files, secret_findings, rules)
        elif "input-validation" in control.analyzers:
            outcome = analyze_input_validation(model, rules)
        elif "authentication" in control.analyzers:
            outcome = analyze_authentication(model, rules)
        elif "authorization" in control.analyzers:
            outcome = analyze_authorization(model, rules)
        elif "injection" in control.analyzers:
            outcome = analyze_injection(files, rules)
        elif "security-logging" in control.analyzers:
            outcome = analyze_security_logging(model, files, rules)
        else:
            other = [finding for finding in regex_findings if finding.control == control.id]
            if other:
                checks = [
                    Check(
                        id="regex-findings",
                        title="Rule findings",
                        status=Status.FAIL if any(f.result == Status.FAIL for f in other) else Status.UNVERIFIED,
                        detail="%d finding(s) from rule packs." % len(other),
                        evidence=[finding.evidence for finding in other],
                        rule_ids=sorted({finding.rule_id for finding in other}),
                    )
                ]
                outcome = ControlOutcome(
                    status=checks[0].status,
                    reason="Rule-pack findings were detected.",
                    checks=checks,
                    findings=other,
                )
            else:
                outcome = ControlOutcome(
                    status=Status.NOT_APPLICABLE,
                    reason="No analyzer or finding surface is implemented for this control in the selected profile.",
                    checks=[
                        Check(
                            id="analyzer-availability",
                            title="Analyzer availability",
                            status=Status.NOT_APPLICABLE,
                            detail="No analyzer is registered for this profile.",
                        )
                    ],
                )
        outcomes.append(outcome)
    return outcomes


def _control_reports(profile: Profile, outcomes: Sequence[ControlOutcome]) -> List[Dict[str, Any]]:
    controls = [profile.controls[key] for key in sorted(profile.controls)]
    result = []
    for outcome, control in zip(outcomes, controls):
        result.append(
            {
                "id": control.id,
                "title": control.title,
                "status": outcome.status.value,
                "reason": outcome.reason,
                "checks": [check.to_dict() for check in outcome.checks],
            }
        )
    return result


def _pick_build_target(files: Sequence[ScanFile]) -> Optional[str]:
    solutions = sorted(file.relpath for file in files if file.relpath.lower().endswith(".sln"))
    if solutions:
        return solutions[0]
    projects = sorted(
        (file.relpath for file in files if file.relpath.lower().endswith(".csproj")),
        key=lambda path: (path.count("/"), path),
    )
    return projects[0] if projects else None


def _run_dotnet_build(root: str, files: Sequence[ScanFile]) -> Dict[str, Any]:
    target = _pick_build_target(files)
    if target is None:
        return {
            "enabled": True,
            "status": Status.UNVERIFIED.value,
            "exit_code": None,
            "target": None,
            "output": "No .sln or .csproj file was found in the scan inventory.",
        }
    dotnet = shutil.which("dotnet")
    if not dotnet:
        return {
            "enabled": True,
            "status": Status.UNVERIFIED.value,
            "exit_code": None,
            "target": target,
            "output": "The dotnet executable was not found on PATH.",
        }
    command = [dotnet, "build", target, "--nologo", "-v:q"]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "enabled": True,
            "status": Status.FAIL.value,
            "exit_code": None,
            "target": target,
            "output": "dotnet build timed out after 180 seconds.",
        }
    except OSError as exc:
        return {
            "enabled": True,
            "status": Status.UNVERIFIED.value,
            "exit_code": None,
            "target": target,
            "output": "dotnet build could not start: %s" % exc,
        }
    output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
    if len(output) > 4000:
        output = output[-4000:]
    output = redact_snippet(output)
    return {
        "enabled": True,
        "status": Status.PASS.value if completed.returncode == 0 else Status.FAIL.value,
        "exit_code": completed.returncode,
        "target": target,
        "output": output,
    }


def _build_control(adapter: Mapping[str, Any]) -> ControlOutcome:
    status = Status.parse(str(adapter.get("status", "UNVERIFIED")))
    detail = "dotnet build target: %s; exit: %s" % (adapter.get("target"), adapter.get("exit_code"))
    evidence: List[Evidence] = []
    return ControlOutcome(
        status=status,
        reason=detail,
        checks=[
            Check(
                id="dotnet-build",
                title="dotnet build",
                status=status,
                detail=detail,
                evidence=evidence,
                rule_ids=[],
            )
        ],
    )


def run_scan(
    root: str,
    profile_name: str = "csharp-aspnetcore",
    report_path: Optional[str] = None,
    markdown_path: Optional[str] = None,
    claims_path: Optional[str] = None,
    policy_path: Optional[str] = None,
    build: bool = False,
) -> Dict[str, Any]:
    root_path = Path(root)
    if not root_path.is_dir():
        raise GateError("Scan root is not a directory: %s" % root)
    try:
        profile = load_profile(profile_name)
    except Exception as exc:  # RulePackError
        raise GateError(str(exc)) from exc

    root_resolved = str(root_path.resolve())
    extra_excludes: List[str] = []
    for candidate in (report_path, markdown_path):
        if not candidate:
            continue
        try:
            relative = Path(candidate).resolve().relative_to(root_path.resolve()).as_posix()
        except ValueError:
            continue
        extra_excludes.append(relative)

    started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    files, skipped, excludes = scan_tree(root_resolved, extra_excludes=tuple(extra_excludes))
    warnings: List[str] = []
    regex_findings = _run_regex_rules(files, profile, warnings)
    outcomes = _run_analyzers(files, profile, regex_findings)

    policy = None
    if policy_path:
        try:
            policy = load_policy(policy_path)
        except PolicyError as exc:
            raise GateError(str(exc)) from exc
    outcomes, suppressed, policy_warnings = apply_policy(outcomes, policy)
    warnings.extend(policy_warnings)
    outcome_by_control = dict(zip(sorted(profile.controls), outcomes))

    adapters: Dict[str, Any] = {"dotnet_build": {"enabled": False, "status": "NOT_APPLICABLE"}}
    if build:
        adapter = _run_dotnet_build(root_resolved, files)
        adapters["dotnet_build"] = adapter
        outcome_by_control["build-integrity"] = _build_control(adapter)
        profile_controls = dict(profile.controls)
        profile_controls["build-integrity"] = ControlDef(
            id="build-integrity",
            title="Build integrity",
            description="dotnet build adapter",
            analyzers=[],
        )
    else:
        profile_controls = dict(profile.controls)
    outcomes = [outcome_by_control[key] for key in sorted(profile_controls)]
    controls = _control_reports(Profile(profile.name, profile.packs, profile_controls, profile.rules), outcomes)

    statuses = [outcome.status for outcome in outcomes]
    overall = worst_status(statuses) if statuses else Status.UNVERIFIED
    active_findings = sorted(
        [finding for outcome in outcomes for finding in outcome.findings],
        key=lambda finding: (finding.evidence.path, finding.evidence.line, finding.evidence.column, finding.rule_id),
    )
    suppressed = sorted(
        suppressed,
        key=lambda finding: (finding.evidence.path, finding.evidence.line, finding.evidence.column, finding.rule_id),
    )

    control_statuses = {control["id"]: Status.parse(control["status"]) for control in controls}
    claims_audit = None
    if claims_path:
        try:
            claims_data = load_claims(claims_path)
            files_by_relpath = {file.relpath: file for file in files}
            claims_audit = audit_claims(claims_data, root_resolved, files_by_relpath, control_statuses, claims_path)
        except ClaimsError as exc:
            raise GateError(str(exc)) from exc

    finished = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    status_counts = {status.value: sum(1 for item in controls if item["status"] == status.value) for status in Status}
    severity_counts: Dict[str, int] = {}
    for finding in active_findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    report: Dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "tool": {
            "name": "secureflow-gate",
            "version": __version__,
        },
        "scan": {
            "root": root_resolved,
            "profile": profile.name,
            "packs": list(profile.packs),
            "started_at": started,
            "finished_at": finished,
            "files_scanned": len(files),
            "files_skipped": len(skipped),
            "skipped": [{"path": item.relpath, "reason": item.reason} for item in skipped],
            "excludes": list(excludes),
            "warnings": warnings,
        },
        "summary": {
            "overall_status": overall.value,
            "status_counts": status_counts,
            "finding_count": len(active_findings),
            "unverified_count": sum(1 for finding in active_findings if finding.result == Status.UNVERIFIED),
            "suppressed_count": len(suppressed),
            "severity_counts": severity_counts,
            "claims_contradictions": (
                claims_audit.get("summary", {}).get("contradictions", 0) if claims_audit else 0
            ),
        },
        "controls": controls,
        "findings": [finding.to_dict() for finding in active_findings],
        "suppressed_findings": [finding.to_dict() for finding in suppressed],
        "claims_audit": claims_audit,
        "adapters": adapters,
        "limitations": list(_LIMITATIONS),
        "integrity": {
            "algorithm": "sha256",
            "files": [{"path": file.relpath, "sha256": file.sha256, "size": file.size} for file in files],
            "inventory_sha256": inventory_sha256(files),
        },
        "detections": build_coverage(
            [finding.to_dict() for finding in active_findings],
            sorted(profile_controls),
        ),
    }
    return finalize_report(report)


def exit_code_for(report: Mapping[str, Any], fail_on: str = "fail") -> int:
    overall = str(report.get("summary", {}).get("overall_status", "UNVERIFIED"))
    if fail_on == "never":
        return 0
    if overall == Status.FAIL.value:
        return 1
    if overall == Status.UNVERIFIED.value and fail_on == "unverified":
        return 2
    return 0
