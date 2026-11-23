"""Plan and apply firewall configuration changes.

All mutations are explicit, logged and require a backup.  APPLY mode is the only
mode that writes a new configuration file; AUDIT and PLAN are read-only.
"""

from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..model import Status
from .model import FirewallConfig, FirewallError
from .pfsense import analyze_pfsense, control_ids, parse_pfsense, redact_config_snippet
from .reports import build_report


class ChangeError(FirewallError):
    pass


@dataclass
class Change:
    action: str  # set_text, set_attribute, append, remove
    xpath: str
    description: str
    value: str = ""
    attribute: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "xpath": self.xpath,
            "description": self.description,
            "value": self.value,
            "attribute": self.attribute,
            "rationale": self.rationale,
        }


def _parent_map(root: ET.Element) -> Dict[ET.Element, Optional[ET.Element]]:
    mapping: Dict[ET.Element, Optional[ET.Element]] = {root: None}
    for parent in root.iter():
        for child in parent:
            mapping[child] = parent
    return mapping


def _element_index_path(root: ET.Element, element: ET.Element) -> str:
    parents = _parent_map(root)
    parts: List[str] = []
    node: Optional[ET.Element] = element
    while node is not None and node != root:
        parent = parents.get(node)
        if parent is None:
            break
        index = 1
        for sibling in parent:
            if sibling is node:
                break
            if sibling.tag == node.tag:
                index += 1
        parts.append("%s[%d]" % (node.tag, index))
        node = parent
    parts.reverse()
    return "./" + "/".join(parts)


def _finding_to_change(config: FirewallConfig, finding: Any) -> Optional[Change]:
    rule_id = finding.rule_id
    evidence = finding.evidence
    xpath = evidence.path  # We store the absolute path in evidence.path currently.
    # Evidence path is the file path, not an XPath. Derive an XPath from the element when possible.
    # The original element is not kept in Finding; plan generation is therefore heuristic.
    # For robust planning we map rule IDs to known configuration locations.
    # Context-aware findings must not auto-generate destructive changes:
    # low/medium sensitive-port findings describe legitimate internal access.
    if rule_id == "FW-RULE-003" and finding.severity not in ("critical", "high"):
        return None
    if rule_id == "FW-LOG-003":
        if config.find("./ntp/timeservers") is not None:
            return Change(
                action="set_text",
                xpath="./ntp/timeservers",
                value="0.pool.ntp.org 1.pool.ntp.org",
                description="Configure NTP time servers.",
                rationale=finding.remediation,
            )
        if config.find("./system/timeservers") is not None:
            return Change(
                action="set_text",
                xpath="./system/timeservers",
                value="0.pool.ntp.org 1.pool.ntp.org",
                description="Configure NTP time servers under <system> (pfSense >= 24.0).",
                rationale=finding.remediation,
            )
    if rule_id == "FW-LOG-004":
        # pfSense >= 24.0 keeps time servers under <system>.
        if config.find("./system/timeservers") is not None:
            return Change(
                action="set_text",
                xpath="./system/timeservers",
                value="0.pool.ntp.org 1.pool.ntp.org",
                description="Configure NTP time servers under <system> (pfSense >= 24.0).",
                rationale=finding.remediation,
            )
        if config.find("system") is not None:
            return Change(
                action="append",
                xpath="./system",
                value="<timeservers>0.pool.ntp.org 1.pool.ntp.org</timeservers>",
                description="Configure NTP time servers under <system> (pfSense >= 24.0).",
                rationale=finding.remediation,
            )
    mapping: Dict[str, Dict[str, Any]] = {
        "FW-ADMIN-001": {
            "action": "set_text",
            "xpath": "./system/webgui/protocol",
            "value": "https",
            "description": "Change WebGUI protocol to HTTPS.",
        },
        "FW-ADMIN-003": {
            "action": "remove",
            "xpath": "./filter/rule[interface='wan' and (dstport='22' or dstport='any') and type='pass']",
            "description": "Remove or restrict the WAN SSH allow rule.",
        },
        "FW-RULE-001": {
            "action": "remove",
            "xpath": "./filter/rule[interface='wan' and type='pass' and protocol='any']",
            "description": "Remove the overly permissive WAN allow rule.",
        },
        "FW-RULE-002": {
            "action": "remove",
            "xpath": "./filter/rule[type='pass' and protocol='any']",
            "description": "Remove or restrict the any-to-internal allow rule.",
        },
        "FW-RULE-003": {
            "action": "remove",
            "xpath": "./filter/rule[type='pass' and dstport]/descr",
            "description": "Remove or restrict the rule exposing a sensitive administrative port.",
        },
        "FW-NAT-001": {
            "action": "remove",
            "xpath": "./nat/rule[local-port]/descr",
            "description": "Remove the port forward to a sensitive administrative port.",
        },
        "FW-LOG-001": {
            "action": "set_text",
            "xpath": "./syslog/remoteserver",
            "value": "SET_YOUR_SIEM_IP",
            "description": "Configure a remote syslog server (replace placeholder with real collector).",
        },
        "FW-LOG-003": {
            "action": "set_text",
            "xpath": "./ntp/timeservers",
            "value": "0.pool.ntp.org 1.pool.ntp.org",
            "description": "Configure NTP time servers.",
        },
        "FW-LOG-004": {
            "action": "append",
            "xpath": ".",
            "value": "<ntp><timeservers>0.pool.ntp.org 1.pool.ntp.org</timeservers><enabled>enabled</enabled></ntp>",
            "description": "Add NTP configuration with reliable time servers.",
        },
        "FW-VPN-001": {
            "action": "set_text",
            "xpath": "./ipsec/phase1/mode",
            "value": "main",
            "description": "Change IPsec phase 1 mode from aggressive to main.",
        },
    }
    if rule_id not in mapping:
        return None
    data = mapping[rule_id]
    return Change(
        action=data["action"],
        xpath=data["xpath"],
        description=data["description"],
        value=data.get("value", ""),
        attribute=data.get("attribute", ""),
        rationale=finding.remediation,
    )


def plan_changes(config: FirewallConfig, outcomes: List[Tuple[str, Any]]) -> List[Change]:
    """Generate a conservative change set from analyzer findings."""
    changes: List[Change] = []
    seen: set = set()
    for _control_id, outcome in outcomes:
        for finding in outcome.findings:
            change = _finding_to_change(config, finding)
            if change is None:
                continue
            key = (change.action, change.xpath, change.value)
            if key in seen:
                continue
            seen.add(key)
            changes.append(change)
    return changes


def _find_element(root: ET.Element, xpath: str) -> Optional[ET.Element]:
    # ElementTree supports limited XPath. For the simple xpaths we generate this is enough.
    if not xpath.startswith("./"):
        xpath = "." + xpath
    try:
        return root.find(xpath)
    except SyntaxError:
        return None


def _find_parent(root: ET.Element, element: ET.Element) -> Optional[ET.Element]:
    for parent in root.iter():
        for child in parent:
            if child is element:
                return parent
    return None


def apply_changes(
    input_path: str,
    changes: List[Change],
    output_path: str,
    backup_path: Optional[str] = None,
    confirm: bool = False,
) -> Tuple[List[Dict[str, Any]], str]:
    """Apply changes to a pfSense XML file.

    Returns the list of applied changes and the path to the written file.
    If confirm is False, no file is written and ChangeError is raised.
    """
    if not confirm:
        raise ChangeError(
            "Changes were not applied. Use --confirm to apply after reviewing the plan."
        )

    config_path = Path(input_path)
    out_path = Path(output_path)
    if not config_path.is_file():
        raise ChangeError("Input configuration not found: %s" % input_path)

    if backup_path:
        backup_target = Path(backup_path)
    else:
        backup_target = out_path.with_suffix(out_path.suffix + ".bak")
    backup_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(config_path), str(backup_target))

    text = config_path.read_text(encoding="utf-8", errors="replace")
    root = ET.fromstring(text)
    applied: List[Dict[str, Any]] = []

    for change in changes:
        element = _find_element(root, change.xpath)
        if element is None and change.action != "append":
            applied.append(
                {
                    **change.to_dict(),
                    "status": "skipped",
                    "reason": "Target element not found.",
                }
            )
            continue

        if change.action == "set_text":
            element.text = change.value
        elif change.action == "set_attribute":
            element.attrib[change.attribute] = change.value
        elif change.action == "append":
            parent = _find_element(root, change.xpath) if change.xpath != "." else root
            if parent is None:
                applied.append({**change.to_dict(), "status": "skipped", "reason": "Parent not found."})
                continue
            try:
                new_elem = ET.fromstring(change.value)
            except ET.ParseError as exc:
                applied.append({**change.to_dict(), "status": "skipped", "reason": "Invalid XML value: %s" % exc})
                continue
            parent.append(new_elem)
        elif change.action == "remove":
            parent = _find_parent(root, element)
            if parent is None:
                applied.append({**change.to_dict(), "status": "skipped", "reason": "Cannot determine parent."})
                continue
            parent.remove(element)
        else:
            applied.append({**change.to_dict(), "status": "skipped", "reason": "Unknown action."})
            continue

        applied.append({**change.to_dict(), "status": "applied"})

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_pretty_xml(root), encoding="utf-8")
    return applied, str(out_path.resolve())


def _pretty_xml(root: ET.Element) -> str:
    # Minimal pretty printing without external dependencies.
    ET.indent(root, space="  ")
    declaration = '<?xml version="1.0" encoding="utf-8"?>'
    return declaration + "\n" + ET.tostring(root, encoding="unicode") + "\n"


def audit_and_plan(config_path: str) -> Tuple[FirewallConfig, List[Tuple[str, Any]], List[Change]]:
    config = parse_pfsense(config_path)
    outcomes = analyze_pfsense(config)
    changes = plan_changes(config, outcomes)
    return config, outcomes, changes


def apply_plan_and_verify(
    input_path: str,
    changes: List[Change],
    output_path: str,
    backup_path: Optional[str] = None,
    confirm: bool = False,
) -> Tuple[List[Dict[str, Any]], str, Dict[str, Any]]:
    """Apply a plan and re-audit the resulting configuration.

    Returns (applied_changes, output_path, verification_report).
    """
    applied, written_path = apply_changes(input_path, changes, output_path, backup_path, confirm)
    new_config = parse_pfsense(written_path)
    new_outcomes = analyze_pfsense(new_config)
    new_report = build_report(new_config, new_outcomes, operation="verify")
    return applied, written_path, new_report
