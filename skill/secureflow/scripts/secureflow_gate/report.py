"""Report serialization, integrity hashing, Markdown rendering, and verification."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import REPORT_SCHEMA
from .model import Status
from .scanner import scan_tree


class ReportError(ValueError):
    pass


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _without_report_hash(report: Dict[str, Any]) -> Dict[str, Any]:
    clone = copy.deepcopy(report)
    integrity = clone.get("integrity")
    if isinstance(integrity, dict):
        integrity.pop("report_sha256", None)
    return clone


def compute_report_sha256(report: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_without_report_hash(report)).encode("utf-8")).hexdigest()


def finalize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    integrity = report.setdefault("integrity", {})
    integrity.setdefault("algorithm", "sha256")
    integrity["report_sha256"] = compute_report_sha256(report)
    return report


def write_json(report: Dict[str, Any], path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False) + "\n", encoding="utf-8")


def _safe_target(root: Path, relpath: Any) -> Optional[Path]:
    """Resolve a report-relative path without allowing escape from the scan root."""
    if not isinstance(relpath, str) or not relpath:
        return None
    candidate = Path(relpath)
    if candidate.is_absolute() or any(part in ("..", "") for part in candidate.parts):
        return None
    try:
        target = (root / candidate).resolve()
        target.relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return target


def _status_badge(status: str) -> str:
    return "`%s`" % status


def render_markdown(report: Dict[str, Any]) -> str:
    scan = report.get("scan", {})
    summary = report.get("summary", {})
    lines: List[str] = []
    lines.append("# SecureFlow Gate Report")
    lines.append("")
    lines.append("**Overall status:** %s" % _status_badge(str(summary.get("overall_status", "UNVERIFIED"))))
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append("| Profile | `%s` |" % scan.get("profile", ""))
    lines.append("| Root | `%s` |" % scan.get("root", ""))
    lines.append("| Files scanned | %s |" % scan.get("files_scanned", 0))
    lines.append("| Files skipped | %s |" % scan.get("files_skipped", 0))
    lines.append("| Started | %s |" % scan.get("started_at", ""))
    lines.append("| Finished | %s |" % scan.get("finished_at", ""))
    lines.append("")
    lines.append("> This report is the output of a static gate. PASS means the detected surface met the configured checks; it is not a proof that the application is secure.")
    lines.append("")

    controls = report.get("controls", [])
    lines.append("## Controls")
    lines.append("")
    lines.append("| Control | Status | Reason |")
    lines.append("| --- | --- | --- |")
    for control in controls:
        lines.append(
            "| %s | %s | %s |"
            % (control.get("title", control.get("id", "")), _status_badge(str(control.get("status", ""))), control.get("reason", ""))
        )
    lines.append("")

    for control in controls:
        checks = control.get("checks", [])
        if not checks:
            continue
        lines.append("### %s checks" % control.get("title", control.get("id", "")))
        lines.append("")
        lines.append("| Check | Status | Detail |")
        lines.append("| --- | --- | --- |")
        for check in checks:
            lines.append(
                "| %s | %s | %s |"
                % (check.get("title", check.get("id", "")), _status_badge(str(check.get("status", ""))), check.get("detail", ""))
            )
        lines.append("")

    findings = report.get("findings", [])
    lines.append("## Findings and unresolved checks")
    lines.append("")
    if not findings:
        lines.append("No active findings or unresolved checks were recorded.")
        lines.append("")
    for finding in findings:
        evidence = finding.get("evidence", {})
        lines.append("### %s — %s" % (finding.get("rule_id", ""), finding.get("title", "")))
        lines.append("")
        lines.append("- Result: %s" % _status_badge(str(finding.get("result", ""))))
        lines.append("- Control: `%s`" % finding.get("control", ""))
        lines.append("- Severity: `%s` / confidence `%s`" % (finding.get("severity", ""), finding.get("confidence", "")))
        lines.append("- Location: `%s:%s:%s`" % (evidence.get("path", ""), evidence.get("line", ""), evidence.get("column", "")))
        lines.append("- Message: %s" % finding.get("message", ""))
        lines.append("- Remediation: %s" % finding.get("remediation", ""))
        if finding.get("cwe"):
            lines.append("- CWE: %s" % ", ".join(finding["cwe"]))
        if finding.get("asvs"):
            lines.append("- ASVS: %s" % ", ".join(finding["asvs"]))
        if finding.get("owasp"):
            lines.append("- OWASP: %s" % ", ".join(finding["owasp"]))
        if evidence.get("snippet"):
            lines.append("")
            lines.append("```text")
            lines.append(str(evidence["snippet"]))
            lines.append("```")
        lines.append("")

    suppressed = report.get("suppressed_findings", [])
    if suppressed:
        lines.append("## Policy-suppressed findings")
        lines.append("")
        lines.append("Suppressed findings remain visible. They do not affect control status while the suppression is valid.")
        lines.append("")
        for finding in suppressed:
            suppression = finding.get("suppression", {})
            lines.append(
                "- `%s` at `%s:%s` until `%s`: %s"
                % (
                    finding.get("rule_id", ""),
                    finding.get("evidence", {}).get("path", ""),
                    finding.get("evidence", {}).get("line", ""),
                    suppression.get("expires", ""),
                    suppression.get("reason", ""),
                )
            )
        lines.append("")

    claims = report.get("claims_audit")
    if claims:
        lines.append("## Claims audit")
        lines.append("")
        lines.append("Claims are untrusted annotations. They never change a gate status.")
        lines.append("")
        counts = claims.get("summary", {})
        lines.append(
            "Accepted: %s · Rejected: %s · Contradictions: %s · Unverified: %s"
            % (
                counts.get("accepted", 0),
                counts.get("rejected", 0),
                counts.get("contradictions", 0),
                counts.get("unverified", 0),
            )
        )
        lines.append("")
        for claim in claims.get("claims", []):
            lines.append(
                "- `%s`: claimed `%s`, gate `%s`, verdict `%s`. %s"
                % (
                    claim.get("control", ""),
                    claim.get("claimed_status", ""),
                    claim.get("gate_status", ""),
                    claim.get("verdict", ""),
                    claim.get("reason", ""),
                )
            )
        lines.append("")

    adapters = report.get("adapters", {})
    if adapters:
        lines.append("## Adapters")
        lines.append("")
        build = adapters.get("dotnet_build")
        if build:
            if build.get("enabled"):
                lines.append("- `dotnet build`: %s (exit %s)" % (_status_badge(str(build.get("status", ""))), build.get("exit_code", "")))
            else:
                lines.append("- `dotnet build`: not requested")
        lines.append("")

    limitations = report.get("limitations", [])
    if limitations:
        lines.append("## Limitations")
        lines.append("")
        for limitation in limitations:
            lines.append("- %s" % limitation)
        lines.append("")

    integrity = report.get("integrity", {})
    lines.append("## Integrity")
    lines.append("")
    lines.append("- Algorithm: `%s`" % integrity.get("algorithm", "sha256"))
    lines.append("- Inventory SHA-256: `%s`" % integrity.get("inventory_sha256", ""))
    lines.append("- Report SHA-256: `%s`" % integrity.get("report_sha256", ""))
    lines.append("- Files bound to this report: %d" % len(integrity.get("files", [])))
    lines.append("")
    return "\n".join(lines)


def write_markdown(report: Dict[str, Any], path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown(report), encoding="utf-8")


@dataclass
class VerificationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    report: Optional[Dict[str, Any]] = None


def verify_report(path: str, root_override: Optional[str] = None) -> VerificationResult:
    report_path = Path(path)
    if not report_path.is_file():
        return VerificationResult(False, ["Report not found: %s" % path])
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return VerificationResult(False, ["Report is not valid JSON: %s" % exc])
    if not isinstance(report, dict) or report.get("schema_version") != REPORT_SCHEMA:
        return VerificationResult(False, ["Report schema_version must be %s" % REPORT_SCHEMA])

    integrity = report.get("integrity", {})
    if not isinstance(integrity, dict):
        return VerificationResult(False, ["Report integrity section is missing"], report=report)
    stored_hash = integrity.get("report_sha256", "")
    computed_hash = compute_report_sha256(report)
    errors: List[str] = []
    warnings: List[str] = []
    if not stored_hash:
        errors.append("Report has no report_sha256")
    elif stored_hash != computed_hash:
        errors.append("Report SHA-256 does not match the report content")

    scan = report.get("scan", {})
    root_value = root_override or scan.get("root")
    if not root_value:
        errors.append("Report has no scan root")
        return VerificationResult(False, errors, warnings, report)
    root = Path(root_value)
    if not root.is_dir():
        errors.append("Scan root does not exist: %s" % root_value)
        return VerificationResult(False, errors, warnings, report)

    listed = integrity.get("files", [])
    if not isinstance(listed, list):
        errors.append("integrity.files is not a list")
        listed = []
    inventory_entries: List[List[Any]] = []
    listed_paths = set()
    for item in listed:
        if not isinstance(item, dict):
            errors.append("integrity.files contains a non-object entry")
            continue
        relpath = item.get("path", "")
        if relpath in listed_paths:
            errors.append("Duplicate file entry in report: %s" % relpath)
            continue
        listed_paths.add(relpath)
        inventory_entries.append([relpath, item.get("sha256"), item.get("size")])
        target = _safe_target(root, relpath)
        if target is None:
            errors.append("File path is not a safe relative path: %s" % relpath)
            continue
        if not target.is_file():
            errors.append("File is missing: %s" % relpath)
            continue
        data = target.read_bytes()
        if hashlib.sha256(data).hexdigest() != item.get("sha256"):
            errors.append("File content changed: %s" % relpath)
        if len(data) != item.get("size"):
            errors.append("File size changed: %s" % relpath)

    expected_inventory = hashlib.sha256(
        json.dumps(inventory_entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if integrity.get("inventory_sha256") != expected_inventory:
        errors.append("Inventory SHA-256 does not match the listed files")

    excludes = scan.get("excludes", [])
    if not isinstance(excludes, list):
        excludes = []
    report_rel = None
    try:
        report_rel = report_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        report_rel = None
    extra_excludes = list(excludes)
    if report_rel:
        extra_excludes.append(report_rel)
    try:
        current_files, _, _ = scan_tree(str(root), extra_excludes=tuple(extra_excludes))
    except Exception as exc:  # noqa: BLE001 - verification must report, not crash
        errors.append("Could not rescan root: %s" % exc)
        current_files = []
    current_paths = {file.relpath for file in current_files}
    for relpath in sorted(current_paths - listed_paths):
        errors.append("File was added after the report was produced: %s" % relpath)
    for relpath in sorted(listed_paths - current_paths):
        if relpath in listed_paths and not (root / Path(relpath)).is_file():
            continue
        errors.append("File is excluded from the current scan but bound to the report: %s" % relpath)

    return VerificationResult(not errors, errors, warnings, report)
