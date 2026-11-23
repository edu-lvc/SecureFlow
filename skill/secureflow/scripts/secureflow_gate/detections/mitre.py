"""MITRE ATT&CK helpers for detection engineering."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


PACKAGE = Path(__file__).resolve().parents[1]
DATA_FILE = PACKAGE / "data" / "mitre-mapping.json"

_TECHNIQUE_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


def validate_technique_id(value: str) -> bool:
    return bool(_TECHNIQUE_RE.match(value))


def load_mapping(path: Optional[Path] = None) -> Dict[str, Any]:
    data_path = path or DATA_FILE
    with data_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("schema_version") != "secureflow.mitre-mapping/v1":
        raise ValueError("MITRE mapping schema must be secureflow.mitre-mapping/v1")
    return data.get("techniques", {})


def technique_tactics(technique: Dict[str, Any]) -> List[str]:
    return list(technique.get("tactics", []))


def applicable_sources_for_finding(
    finding: Dict[str, Any],
    mapping: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Return (technique_id, source) pairs that are justified for a finding."""
    results: List[Dict[str, Any]] = []
    finding_sources = set(finding.get("telemetry_sources", []))
    for technique_id in finding.get("mitre_attack", []):
        technique = mapping.get(technique_id)
        if not technique:
            continue
        if finding.get("control") not in technique.get("applicable_controls", []):
            continue
        for source in technique.get("telemetry_sources", []):
            if source in finding_sources:
                results.append({"technique_id": technique_id, "technique": technique, "source": source})
    return results
