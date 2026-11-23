"""Detection coverage ledger.

Builds a lightweight mapping between SecureFlow controls, MITRE techniques, and
Sigma rules. A control is considered covered only when at least one of its
findings maps to a MITRE technique and a telemetry source, and a Sigma rule was
generated for that pair.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Set

from .mitre import applicable_sources_for_finding, load_mapping
from .sigma import generate_sigma
from .telemetry import load_sources


def build_coverage(
    findings: Sequence[Dict[str, Any]],
    control_ids: Sequence[str],
) -> Dict[str, Any]:
    mapping = load_mapping()
    sources_meta = load_sources()

    covered_controls: Set[str] = set()
    uncovered_controls: Set[str] = set(control_ids)
    techniques: Dict[str, Any] = {}
    sigma_rules: List[Dict[str, Any]] = []
    missing_justifications: List[str] = []

    for finding in findings:
        control = finding.get("control", "")
        pairs = applicable_sources_for_finding(finding, mapping)
        if not pairs:
            if finding.get("mitre_attack"):
                missing_justifications.append(
                    "%s maps to MITRE but has no supported telemetry source for any technique."
                    % finding.get("rule_id", "unknown")
                )
            continue

        for pair in pairs:
            technique_id = pair["technique_id"]
            technique = pair["technique"]
            source = pair["source"]
            sigma_rules.append(generate_sigma(finding, technique_id, technique, source))
            covered_controls.add(control)
            uncovered_controls.discard(control)
            if technique_id not in techniques:
                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "name": technique.get("name", ""),
                    "tactics": list(technique.get("tactics", [])),
                    "sources": set(),
                }
            techniques[technique_id]["sources"].add(source)

    # Summarise sources per technique as sorted lists.
    for technique_id in techniques:
        techniques[technique_id]["sources"] = sorted(techniques[technique_id]["sources"])

    return {
        "covered_controls": sorted(covered_controls),
        "uncovered_controls": sorted(uncovered_controls),
        "mitre_techniques": list(techniques.values()),
        "sigma_rules_generated": len(sigma_rules),
        "sigma_rules": sigma_rules,
        "missing_detection_justifications": missing_justifications,
    }
