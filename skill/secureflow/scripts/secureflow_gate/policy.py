"""Policy loading and suppression handling.

Suppressions are explicit, reasoned, and time bounded. They never delete
evidence: a suppressed finding is reported separately with its justification.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import POLICY_SCHEMA
from .globs import matches_any
from .model import ControlOutcome, Finding, Status


class PolicyError(ValueError):
    pass


@dataclass
class Suppression:
    rule_id: str
    path: str
    reason: str
    expires: str
    owner: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "reason": self.reason,
            "expires": self.expires,
            "owner": self.owner,
        }

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id != self.rule_id:
            return False
        return matches_any(finding.evidence.path, [self.path])


@dataclass
class Policy:
    suppressions: List[Suppression] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def match(self, finding: Finding) -> Optional[Suppression]:
        for suppression in self.suppressions:
            if suppression.matches(finding):
                return suppression
        return None


def _parse_date(value: str) -> Optional[_dt.date]:
    try:
        return _dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def load_policy(path: str, today: Optional[_dt.date] = None) -> Policy:
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyError("Policy file not found: %s" % path)
    try:
        data = json.loads(policy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError("Policy file is not valid JSON: %s" % exc) from exc
    if not isinstance(data, dict) or data.get("schema_version") != POLICY_SCHEMA:
        raise PolicyError("Policy schema_version must be %s" % POLICY_SCHEMA)
    entries = data.get("suppressions", [])
    if not isinstance(entries, list):
        raise PolicyError("Policy suppressions must be a list")

    current = today or _dt.date.today()
    policy = Policy()
    for index, entry in enumerate(entries):
        label = "suppressions[%d]" % index
        if not isinstance(entry, dict):
            policy.warnings.append("%s is not an object and was ignored" % label)
            continue
        rule_id = entry.get("rule_id")
        match_path = entry.get("path")
        reason = entry.get("reason")
        expires = entry.get("expires")
        if not all(isinstance(value, str) and value.strip() for value in (rule_id, match_path, reason, expires)):
            policy.warnings.append("%s is missing rule_id, path, reason, or expires and was ignored" % label)
            continue
        expiry = _parse_date(expires)
        if expiry is None:
            policy.warnings.append("%s has an invalid expires date and was ignored" % label)
            continue
        if expiry < current:
            policy.warnings.append("%s expired on %s and was ignored" % (label, expires))
            continue
        policy.suppressions.append(
            Suppression(
                rule_id=rule_id.strip(),
                path=match_path.strip(),
                reason=reason.strip(),
                expires=expires,
                owner=str(entry.get("owner", "") or ""),
            )
        )
    return policy


def _aggregate(checks: Sequence) -> Status:
    if any(check.status == Status.FAIL for check in checks):
        return Status.FAIL
    if any(check.status == Status.UNVERIFIED for check in checks):
        return Status.UNVERIFIED
    if checks and all(check.status == Status.NOT_APPLICABLE for check in checks):
        return Status.NOT_APPLICABLE
    return Status.PASS


def apply_policy(outcomes: Sequence[ControlOutcome], policy: Optional[Policy]) -> Tuple[List[ControlOutcome], List[Finding], List[str]]:
    """Remove suppressed findings from control status and return an audit list."""

    suppressed: List[Finding] = []
    warnings: List[str] = []
    if policy is None:
        return list(outcomes), suppressed, warnings

    for outcome in outcomes:
        active: List[Finding] = []
        suppressed_rule_ids = set()
        for finding in outcome.findings:
            suppression = policy.match(finding)
            if suppression is None:
                active.append(finding)
                continue
            finding.suppression = suppression.to_dict()
            suppressed.append(finding)
            suppressed_rule_ids.add(finding.rule_id)
            warnings.append(
                "Suppressed %s at %s:%d until %s: %s"
                % (
                    finding.rule_id,
                    finding.evidence.path,
                    finding.evidence.line,
                    suppression.expires,
                    suppression.reason,
                )
            )
        active_rule_ids = {finding.rule_id for finding in active}
        outcome.findings = active

        notes = []
        for check in outcome.checks:
            if check.status != Status.FAIL:
                continue
            if not check.rule_ids:
                continue
            if any(rule_id in active_rule_ids for rule_id in check.rule_ids):
                continue
            if not any(rule_id in suppressed_rule_ids for rule_id in check.rule_ids):
                continue
            check.status = Status.PASS
            check.detail += " Suppressed by policy with an expiry date."
            notes.append(check.id)

        previous_status = outcome.status
        outcome.status = _aggregate(outcome.checks)
        if notes:
            outcome.reason += " Policy suppressions applied to: %s." % ", ".join(sorted(notes))
        if outcome.status == Status.PASS and previous_status == Status.FAIL:
            outcome.reason = "All active findings for this control were suppressed by policy until their expiry date."

    return list(outcomes), suppressed, warnings
