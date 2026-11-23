"""Core data model for SecureFlow Gate."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNVERIFIED = "UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"

    @classmethod
    def parse(cls, value: str) -> "Status":
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError("invalid status: %s" % value) from exc


STATUS_ORDER = {
    Status.NOT_APPLICABLE: 0,
    Status.PASS: 1,
    Status.UNVERIFIED: 2,
    Status.FAIL: 3,
}


def worst_status(statuses: List[Status]) -> Status:
    if not statuses:
        return Status.NOT_APPLICABLE
    return max(statuses, key=lambda item: STATUS_ORDER[item])


def snippet_hash(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


@dataclass
class Evidence:
    path: str
    line: int
    column: int
    snippet: str
    snippet_sha256: str
    language: str = "text"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "snippet_sha256": self.snippet_sha256,
            "language": self.language,
        }


@dataclass
class Check:
    id: str
    title: str
    status: Status
    detail: str
    evidence: List[Evidence] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status.value,
            "detail": self.detail,
            "rule_ids": list(self.rule_ids),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class Finding:
    rule_id: str
    control: str
    title: str
    severity: str
    confidence: str
    result: Status
    message: str
    remediation: str
    cwe: List[str]
    asvs: List[str]
    owasp: List[str]
    evidence: Evidence
    suppression: Optional[Dict[str, Any]] = None
    mitre_attack: List[str] = field(default_factory=list)
    telemetry_sources: List[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        raw = "|".join(
            [
                self.rule_id,
                self.evidence.path,
                str(self.evidence.line),
                str(self.evidence.column),
                self.evidence.snippet_sha256,
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self, include_suppression: bool = True) -> Dict[str, Any]:
        data = {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "control": self.control,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "result": self.result.value,
            "message": self.message,
            "remediation": self.remediation,
            "cwe": list(self.cwe),
            "asvs": list(self.asvs),
            "owasp": list(self.owasp),
            "mitre_attack": list(self.mitre_attack),
            "telemetry_sources": list(self.telemetry_sources),
            "evidence": self.evidence.to_dict(),
        }
        if include_suppression and self.suppression:
            data["suppression"] = dict(self.suppression)
        return data


@dataclass
class ControlResult:
    id: str
    title: str
    status: Status
    reason: str
    checks: List[Check] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status.value,
            "reason": self.reason,
            "checks": [item.to_dict() for item in self.checks],
        }


@dataclass
class ControlOutcome:
    status: Status
    reason: str
    checks: List[Check] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScanFile:
    relpath: str
    abspath: str
    text: str
    sha256: str
    size: int

    def line(self, number: int) -> str:
        lines = self.text.splitlines()
        if number < 1 or number > len(lines):
            return ""
        return lines[number - 1]

    @property
    def line_count(self) -> int:
        return len(self.text.splitlines())


@dataclass
class SkippedFile:
    relpath: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.relpath, "reason": self.reason}
