"""Report construction for firewall audits.

The firewall report uses a separate schema version from the application-security
gate report.  It reuses the same integrity primitives (canonical JSON and SHA-256)
so that report verification remains deterministic and reproducible.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from ..model import ControlOutcome, Finding, Status, worst_status
from ..report import canonical_json, finalize_report
from .model import FirewallConfig


FIREWALL_REPORT_SCHEMA = "secureflow.firewall.report/v1"


_LIMITATIONS = [
    "Static XML analysis only. The auditor does not connect to a live firewall or execute remote commands.",
    "Only pfSense XML configuration exports are deeply implemented. Other vendors need vendor-specific parsers.",
    "Rule conflict detection is based on simple field matching; complex aliases, schedules and floating rules may not be evaluated.",
    "Administration exposure on non-WAN interfaces is not assessed beyond rule inspection.",
    "VPN cryptographic details are not parsed beyond phase-1 mode and OpenVPN topology.",
    "IPv6 firewall posture is inferred from interface and rule presence, not proven.",
    "Report hashes are tamper-evident but not cryptographically signed.",
]


def _status_badge(status: str) -> str:
    return "`%s`" % status


def _inventory_sha256(path: str, sha256: str, size: int) -> str:
    payload = json.dumps([[path, sha256, size]], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_report(
    config: FirewallConfig,
    outcomes: Sequence[Tuple[str, ControlOutcome]],
    operation: str = "audit",
    proposed_changes: Optional[List[Dict[str, Any]]] = None,
    applied_changes: Optional[List[Dict[str, Any]]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    controls: List[Dict[str, Any]] = []
    active_findings: List[Finding] = []
    for control_id, outcome in outcomes:
        controls.append(
            {
                "id": control_id,
                "title": outcome.checks[0].title if outcome.checks else control_id,
                "status": outcome.status.value,
                "reason": outcome.reason,
                "checks": [check.to_dict() for check in outcome.checks],
            }
        )
        active_findings.extend(outcome.findings)

    active_findings = sorted(
        active_findings,
        key=lambda finding: (finding.evidence.path, finding.evidence.line, finding.evidence.column, finding.rule_id),
    )

    statuses = [outcome.status for _, outcome in outcomes]
    overall = worst_status(statuses) if statuses else Status.NOT_APPLICABLE
    status_counts = {status.value: sum(1 for c in controls if c["status"] == status.value) for status in Status}
    severity_counts: Dict[str, int] = {}
    for finding in active_findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    hostname = config.find("./system/hostname")
    domain = config.find("./system/domain")

    report: Dict[str, Any] = {
        "schema_version": FIREWALL_REPORT_SCHEMA,
        "tool": {"name": "secureflow-gate", "version": __version__},
        "device": {
            "vendor": config.vendor,
            "version": config.version,
            "hostname": (hostname.text or "").strip() if hostname is not None else "",
            "domain": (domain.text or "").strip() if domain is not None else "",
        },
        "config": {
            "path": config.abspath,
            "sha256": config.sha256,
            "size": config.size,
        },
        "operation": operation,
        "started_at": started,
        "finished_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "overall_status": overall.value,
            "status_counts": status_counts,
            "finding_count": len(active_findings),
            "severity_counts": severity_counts,
        },
        "controls": controls,
        "findings": [finding.to_dict() for finding in active_findings],
        "proposed_changes": proposed_changes or [],
        "applied_changes": applied_changes or [],
        "verification": verification,
        "limitations": list(_LIMITATIONS),
        "integrity": {
            "algorithm": "sha256",
            "files": [{"path": config.abspath, "sha256": config.sha256, "size": config.size}],
            "inventory_sha256": _inventory_sha256(config.abspath, config.sha256, config.size),
        },
    }
    return finalize_report(report)


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report.get("summary", {})
    device = report.get("device", {})
    config = report.get("config", {})
    lines: List[str] = []
    lines.append("# SecureFlow Firewall Report")
    lines.append("")
    lines.append("**Overall status:** %s" % _status_badge(str(summary.get("overall_status", "UNVERIFIED"))))
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append("| Vendor | `%s` |" % device.get("vendor", ""))
    lines.append("| Version | `%s` |" % (device.get("version") or "unknown"))
    lines.append("| Hostname | `%s` |" % device.get("hostname", ""))
    lines.append("| Config | `%s` |" % config.get("path", ""))
    lines.append("| Operation | `%s` |" % report.get("operation", "audit"))
    lines.append("| Started | `%s` |" % report.get("started_at", ""))
    lines.append("| Finished | `%s` |" % report.get("finished_at", ""))
    lines.append("")
    lines.append(
        "> PASS means the inspected configuration met the configured checks. "
        "It is not a proof that the device is secure or that the running state matches the exported XML."
    )
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

    findings = report.get("findings", [])
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No active findings were recorded.")
        lines.append("")
    for finding in findings:
        evidence = finding.get("evidence", {})
        lines.append("### %s — %s" % (finding.get("rule_id", ""), finding.get("title", "")))
        lines.append("")
        lines.append("- Result: %s" % _status_badge(str(finding.get("result", ""))))
        lines.append("- Control: `%s`" % finding.get("control", ""))
        lines.append("- Severity: `%s`" % finding.get("severity", ""))
        lines.append("- Location: `%s:%s`" % (evidence.get("path", ""), evidence.get("line", "")))
        lines.append("- Message: %s" % finding.get("message", ""))
        lines.append("- Remediation: %s" % finding.get("remediation", ""))
        if evidence.get("snippet"):
            lines.append("")
            lines.append("```xml")
            lines.append(str(evidence["snippet"]))
            lines.append("```")
        lines.append("")

    proposed = report.get("proposed_changes", [])
    if proposed:
        lines.append("## Proposed changes")
        lines.append("")
        for change in proposed:
            lines.append("- **%s**: %s" % (change.get("action", "change"), change.get("description", "")))
        lines.append("")

    applied = report.get("applied_changes", [])
    if applied:
        lines.append("## Applied changes")
        lines.append("")
        for change in applied:
            lines.append("- **%s**: %s" % (change.get("action", "change"), change.get("description", "")))
        lines.append("")

    verification = report.get("verification")
    if verification:
        lines.append("## Verification")
        lines.append("")
        lines.append("- Status: %s" % _status_badge(str(verification.get("status", "UNVERIFIED"))))
        lines.append("- Reason: %s" % verification.get("reason", ""))
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
    lines.append("- Config SHA-256: `%s`" % config.get("sha256", ""))
    lines.append("- Report SHA-256: `%s`" % integrity.get("report_sha256", ""))
    lines.append("")
    return "\n".join(lines)


def write_json(report: Dict[str, Any], path: str) -> None:
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_markdown(report: Dict[str, Any], path: str) -> None:
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown(report), encoding="utf-8")
