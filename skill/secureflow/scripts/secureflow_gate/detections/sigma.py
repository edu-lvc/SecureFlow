"""Sigma rule generation from SecureFlow findings.

The generated rules are experimental stubs. They contain a justified logsource,
MITRE tags, a reference to the original evidence, and a placeholder detection
block that must be replaced with real event logic before deployment.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


_LOGSOURCE_MAP: Dict[str, Dict[str, str]] = {
    "web_server_logs": {"category": "webserver"},
    "sysmon": {"product": "sysmon"},
    "windows_security": {"product": "windows"},
    "wazuh": {"product": "wazuh"},
    "sentinel": {"product": "azure"},
    "elastic": {"product": "elastic"},
    "splunk": {"product": "splunk"},
    "okta": {"product": "okta"},
    "azure_ad": {"product": "azure"},
    "network_ids": {"category": "network_connection"},
    "endpoint_files": {"category": "file_event"},
}


_SEVERITY_TO_LEVEL = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _escape_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    return '"%s"' % _escape_string(text)


def _yaml_value(value: Any, indent: int = 0) -> str:
    prefix = "  " * indent
    if isinstance(value, dict):
        if not value:
            return prefix + "{}"
        lines: List[str] = []
        for key, item in value.items():
            rendered = _yaml_value(item, indent + 1)
            first_line, *rest = rendered.split("\n")
            lines.append("%s%s: %s" % (prefix, key, first_line.lstrip()))
            lines.extend(rest)
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return prefix + "[]"
        lines = []
        for item in value:
            rendered = _yaml_value(item, indent + 1)
            first_line, *rest = rendered.split("\n")
            lines.append("%s- %s" % (prefix, first_line.lstrip()))
            lines.extend(rest)
        return "\n".join(lines)
    return prefix + _yaml_scalar(value)


def _tag_for_tactic(tactic: str) -> str:
    return "attack." + re.sub(r"[^a-z0-9]", "_", tactic.lower())


def _logsource_for_source(source: str) -> Dict[str, str]:
    return dict(_LOGSOURCE_MAP.get(source, {"category": "application"}))


def generate_sigma(
    finding: Dict[str, Any],
    technique_id: str,
    technique: Dict[str, Any],
    source: str,
) -> Dict[str, Any]:
    severity = finding.get("severity", "medium").lower()
    level = _SEVERITY_TO_LEVEL.get(severity, "medium")
    evidence = finding.get("evidence", {})
    path = evidence.get("path", "")
    line = evidence.get("line", 0)
    snippet = evidence.get("snippet", "")
    fingerprint = finding.get("fingerprint", "")

    tags: List[str] = ["attack.%s" % technique_id]
    for tactic in technique.get("tactics", []):
        tags.append(_tag_for_tactic(tactic))

    title = "SecureFlow: %s [%s]" % (finding.get("title", "Finding"), technique_id)
    description = finding.get("message", "") or finding.get("title", "")

    rule: Dict[str, Any] = {
        "title": title,
        "id": "secureflow-%s-%s-%s" % (finding.get("rule_id", "unknown"), technique_id, source),
        "status": "experimental",
        "description": description,
        "logsource": _logsource_for_source(source),
        "detection": {
            "selection": {
                "secureflow_finding": [
                    {
                        "rule_id": finding.get("rule_id", ""),
                        "control": finding.get("control", ""),
                        "evidence_path": path,
                        "evidence_line": line,
                    }
                ]
            },
            "condition": "selection",
        },
        "falsepositives": ["Replace this placeholder with product-specific event logic."],
        "level": level,
        "tags": tags,
        "references": ["file://%s#%d" % (path, line) if path else "evidence: %s" % snippet],
        "metadata": {
            "secureflow.rule_id": finding.get("rule_id", ""),
            "secureflow.control": finding.get("control", ""),
            "secureflow.fingerprint": fingerprint,
            "secureflow.technique": technique_id,
            "secureflow.source": source,
            "secureflow.evidence.path": path,
            "secureflow.evidence.line": line,
        },
    }
    return rule


def sigma_to_yaml(rule: Dict[str, Any]) -> str:
    return _yaml_value(rule)


def sigma_to_json(rule: Dict[str, Any]) -> str:
    return json.dumps(rule, indent=2, sort_keys=True, ensure_ascii=False)
