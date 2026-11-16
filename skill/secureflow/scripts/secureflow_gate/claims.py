"""Audit of agent-authored security claims.

The gate treats claims as untrusted annotations. A claim can be confirmed,
contradicted, or rejected, but it can never change a control status. Evidence is
checked against the scanned tree, including line content and optional hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import CLAIMS_SCHEMA
from .model import Status, snippet_hash


class ClaimsError(ValueError):
    pass


_VERDICTS = (
    "confirmed",
    "contradiction_overstated",
    "contradiction_understated",
    "unverified",
    "rejected",
)


def load_claims(path: str) -> Dict[str, Any]:
    claims_path = Path(path)
    if not claims_path.is_file():
        raise ClaimsError("Claims file not found: %s" % path)
    try:
        data = json.loads(claims_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ClaimsError("Claims file is not valid JSON: %s" % exc) from exc
    if not isinstance(data, dict) or data.get("schema_version") != CLAIMS_SCHEMA:
        raise ClaimsError("Claims schema_version must be %s" % CLAIMS_SCHEMA)
    if not isinstance(data.get("claims"), list):
        raise ClaimsError("Claims file must contain a claims list")
    return data


def _verdict(claimed: Status, actual: Status) -> Tuple[str, str]:
    if claimed == actual:
        return "confirmed", "The claim matches the gate result."
    if claimed == Status.PASS:
        if actual == Status.UNVERIFIED:
            return "unverified", "The claim asserts PASS, but the gate could not verify the control."
        return "contradiction_overstated", "The claim asserts PASS, but the gate result is %s." % actual.value
    if claimed == Status.FAIL:
        return "contradiction_understated", "The claim asserts FAIL, but the gate result is %s." % actual.value
    if claimed == Status.UNVERIFIED:
        return "contradiction_understated", "The claim asserts UNVERIFIED, but the gate result is %s." % actual.value
    if actual == Status.FAIL:
        return "contradiction_understated", "The claim asserts NOT_APPLICABLE, but the gate found a failure."
    return "contradiction_overstated", "The claim asserts NOT_APPLICABLE, but the gate result is %s." % actual.value


def _validate_evidence(
    root: Path,
    files_by_relpath: Mapping[str, Any],
    evidence: Any,
    claim_index: int,
    evidence_index: int,
) -> Tuple[bool, List[str], Optional[Dict[str, Any]]]:
    label = "claims[%d].evidence[%d]" % (claim_index, evidence_index)
    errors: List[str] = []
    if not isinstance(evidence, dict):
        return False, ["%s is not an object" % label], None
    relpath = evidence.get("path")
    line = evidence.get("line")
    snippet = evidence.get("snippet")
    digest = evidence.get("sha256", "")
    if not isinstance(relpath, str) or not relpath.strip():
        errors.append("%s.path must be a non-empty string" % label)
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        errors.append("%s.line must be a positive integer" % label)
    if not isinstance(snippet, str) or not snippet.strip():
        errors.append("%s.snippet must be a non-empty string" % label)
    if not isinstance(digest, str):
        errors.append("%s.sha256 must be a string" % label)
    if errors:
        return False, errors, None

    if Path(relpath).is_absolute() or relpath.startswith(("/", "\\")):
        return False, ["%s.path must be relative to the scan root" % label], None
    normalized = relpath.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("../") or "/../" in normalized or normalized in ("..", "."):
        return False, ["%s.path escapes the scan root" % label], None

    root_resolved = root.resolve()
    candidate = (root_resolved / normalized).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return False, ["%s.path resolves outside the scan root" % label], None
    if not candidate.is_file():
        return False, ["%s.path does not exist: %s" % (label, normalized)], None

    scanned = files_by_relpath.get(normalized)
    if scanned is not None:
        text = scanned.text
    else:
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return False, ["%s.path could not be read: %s" % (label, exc)], None

    lines = text.splitlines()
    if line > len(lines):
        return False, ["%s.line %d is outside the file (%d lines)" % (label, line, len(lines))], None
    actual = lines[line - 1]
    if actual.strip() != snippet.strip():
        return False, [
            "%s.snippet does not match %s:%d" % (label, normalized, line)
        ], None
    computed = snippet_hash(actual)
    if digest and digest.strip().lower() != computed:
        return False, ["%s.sha256 does not match the evidence line" % label], None
    return True, [], {
        "path": normalized,
        "line": line,
        "snippet": snippet.strip(),
        "sha256": computed,
    }


def audit_claims(
    data: Dict[str, Any],
    root: str,
    files_by_relpath: Mapping[str, Any],
    control_statuses: Mapping[str, Status],
    source: str = "",
) -> Dict[str, Any]:
    root_path = Path(root)
    claims = data.get("claims", [])
    audited: List[Dict[str, Any]] = []
    counts = {"accepted": 0, "rejected": 0, "contradictions": 0, "unverified": 0}
    warnings: List[str] = []

    for index, claim in enumerate(claims):
        entry: Dict[str, Any] = {
            "index": index,
            "control": None,
            "claimed_status": None,
            "gate_status": None,
            "verdict": "rejected",
            "summary": "",
            "reason": "",
            "evidence": [],
            "errors": [],
        }
        if not isinstance(claim, dict):
            entry["errors"].append("claim is not an object")
            counts["rejected"] += 1
            audited.append(entry)
            continue

        control = claim.get("control")
        status_value = claim.get("status")
        summary = claim.get("summary", "")
        evidence_entries = claim.get("evidence", [])
        entry["control"] = control
        entry["summary"] = summary if isinstance(summary, str) else ""

        if not isinstance(control, str) or control not in control_statuses:
            entry["errors"].append("unknown or missing control")
        if not isinstance(status_value, str):
            entry["errors"].append("status must be a string")
            claimed = None
        else:
            try:
                claimed = Status.parse(status_value)
            except ValueError:
                claimed = None
                entry["errors"].append("status must be PASS, FAIL, UNVERIFIED, or NOT_APPLICABLE")
        entry["claimed_status"] = claimed.value if claimed is not None else None
        if claimed in (Status.PASS, Status.FAIL) and not evidence_entries:
            entry["errors"].append("PASS and FAIL claims require evidence")
        if not isinstance(evidence_entries, list):
            entry["errors"].append("evidence must be a list")
            evidence_entries = []

        checked_evidence: List[Dict[str, Any]] = []
        if isinstance(evidence_entries, list):
            for evidence_index, evidence in enumerate(evidence_entries):
                ok, errors, checked = _validate_evidence(
                    root_path, files_by_relpath, evidence, index, evidence_index
                )
                entry["errors"].extend(errors)
                if checked is not None:
                    checked_evidence.append(checked)
        entry["evidence"] = checked_evidence

        if entry["errors"]:
            entry["verdict"] = "rejected"
            entry["reason"] = "; ".join(entry["errors"])
            counts["rejected"] += 1
            audited.append(entry)
            continue

        assert claimed is not None
        actual = control_statuses[control]
        entry["gate_status"] = actual.value
        verdict, reason = _verdict(claimed, actual)
        entry["verdict"] = verdict
        entry["reason"] = reason
        audited.append(entry)
        if verdict == "confirmed":
            counts["accepted"] += 1
        elif verdict == "unverified":
            counts["unverified"] += 1
        elif verdict.startswith("contradiction"):
            counts["contradictions"] += 1
        else:
            counts["rejected"] += 1

    if counts["contradictions"]:
        warnings.append(
            "%d claim(s) contradict the gate result. Claims never change control status."
            % counts["contradictions"]
        )
    if counts["rejected"]:
        warnings.append("%d claim(s) were rejected because evidence was invalid." % counts["rejected"])

    return {
        "schema_version": CLAIMS_SCHEMA,
        "source": source,
        "claims": audited,
        "summary": counts,
        "warnings": warnings,
    }
