"""Rule-pack loading and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import RULEPACK_SCHEMA

RULEPACK_DIR = Path(__file__).resolve().parent / "rulepacks"

PROFILES = {
    "base": ["base"],
    "csharp-aspnetcore": ["base", "csharp-aspnetcore"],
}

SEVERITIES = {"critical", "high", "medium", "low", "info"}
CONFIDENCES = {"high", "medium", "low"}
MODES = {"finding", "review"}
KINDS = {"regex", "analyzer"}


class RulePackError(RuntimeError):
    """Raised when a rule pack or profile is invalid."""


@dataclass
class ControlDef:
    id: str
    title: str
    description: str
    analyzers: List[str] = field(default_factory=list)


@dataclass
class Rule:
    id: str
    control: str
    title: str
    kind: str
    mode: str
    severity: str
    confidence: str
    include: List[str]
    exclude: List[str]
    pattern: Optional[str]
    allow_pattern: Optional[str]
    flags: str
    message: str
    remediation: str
    cwe: List[str]
    asvs: List[str]
    owasp: List[str]
    min_matches: int = 1
    regex: Optional[re.Pattern[str]] = field(default=None, repr=False)
    allow_regex: Optional[re.Pattern[str]] = field(default=None, repr=False)

    def public_dict(self) -> dict:
        return {
            "id": self.id,
            "control": self.control,
            "title": self.title,
            "kind": self.kind,
            "mode": self.mode,
            "severity": self.severity,
            "confidence": self.confidence,
            "include": list(self.include),
            "exclude": list(self.exclude),
            "pattern": self.pattern,
            "allow_pattern": self.allow_pattern,
            "flags": self.flags,
            "message": self.message,
            "remediation": self.remediation,
            "cwe": list(self.cwe),
            "asvs": list(self.asvs),
            "owasp": list(self.owasp),
            "min_matches": self.min_matches,
        }


@dataclass
class Profile:
    name: str
    packs: List[str]
    controls: Dict[str, ControlDef]
    rules: List[Rule]

    def rules_by_id(self) -> Dict[str, Rule]:
        return {rule.id: rule for rule in self.rules}

    def rules_for_control(self, control: str) -> List[Rule]:
        return [rule for rule in self.rules if rule.control == control]


def available_profiles() -> List[str]:
    return sorted(PROFILES)


def _read_pack(name: str) -> dict:
    path = RULEPACK_DIR / (name + ".json")
    if not path.is_file():
        raise RulePackError("rule pack not found: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RulePackError("cannot read rule pack %s: %s" % (path, exc)) from exc
    if data.get("schema_version") != RULEPACK_SCHEMA:
        raise RulePackError("unsupported rule pack schema in %s" % path)
    return data


def _compile_flags(flags: str) -> int:
    value = 0
    for flag in flags or "":
        if flag == "i":
            value |= re.IGNORECASE
        elif flag == "m":
            value |= re.MULTILINE
        elif flag == "s":
            value |= re.DOTALL
        elif flag:
            raise RulePackError("unsupported regex flag: %s" % flag)
    return value


def _string_list(data: dict, key: str, rule_id: str) -> List[str]:
    value = data.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise RulePackError("rule %s must define a non-empty string list for %s" % (rule_id, key))
    return list(value)


def _parse_rule(data: dict, controls: Dict[str, ControlDef]) -> Rule:
    if not isinstance(data, dict):
        raise RulePackError("rule entry must be an object")
    rule_id = str(data.get("id", "")).strip()
    if not re.match(r"^SF-[A-Z]+-[0-9]{3}$", rule_id):
        raise RulePackError("invalid rule id: %r" % rule_id)
    control = str(data.get("control", "")).strip()
    if control not in controls:
        raise RulePackError("rule %s references unknown control %s" % (rule_id, control))
    kind = data.get("kind", "regex")
    mode = data.get("mode", "finding")
    severity = data.get("severity")
    confidence = data.get("confidence")
    if kind not in KINDS:
        raise RulePackError("rule %s has invalid kind %s" % (rule_id, kind))
    if mode not in MODES:
        raise RulePackError("rule %s has invalid mode %s" % (rule_id, mode))
    if severity not in SEVERITIES:
        raise RulePackError("rule %s has invalid severity %s" % (rule_id, severity))
    if confidence not in CONFIDENCES:
        raise RulePackError("rule %s has invalid confidence %s" % (rule_id, confidence))

    include = data.get("include", [])
    exclude = data.get("exclude", [])
    if not isinstance(include, list) or not all(isinstance(item, str) for item in include):
        raise RulePackError("rule %s include must be a string list" % rule_id)
    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        raise RulePackError("rule %s exclude must be a string list" % rule_id)

    pattern = data.get("pattern")
    allow_pattern = data.get("allow_pattern")
    flags = data.get("flags", "")
    regex = None
    allow_regex = None
    if kind == "regex":
        if not include:
            raise RulePackError("regex rule %s must define include globs" % rule_id)
        if not isinstance(pattern, str) or not pattern:
            raise RulePackError("regex rule %s must define a pattern" % rule_id)
        try:
            regex = re.compile(pattern, _compile_flags(flags))
            if allow_pattern:
                allow_regex = re.compile(allow_pattern, _compile_flags(flags))
        except re.error as exc:
            raise RulePackError("rule %s has an invalid regex: %s" % (rule_id, exc)) from exc
    elif pattern or allow_pattern:
        raise RulePackError("analyzer rule %s cannot define a regex pattern" % rule_id)

    message = data.get("message")
    remediation = data.get("remediation")
    if not isinstance(message, str) or not message.strip():
        raise RulePackError("rule %s must define a message" % rule_id)
    if not isinstance(remediation, str) or not remediation.strip():
        raise RulePackError("rule %s must define a remediation" % rule_id)

    min_matches = data.get("min_matches", 1)
    if not isinstance(min_matches, int) or min_matches < 1:
        raise RulePackError("rule %s min_matches must be a positive integer" % rule_id)

    return Rule(
        id=rule_id,
        control=control,
        title=str(data.get("title", "")).strip() or rule_id,
        kind=kind,
        mode=mode,
        severity=severity,
        confidence=confidence,
        include=include,
        exclude=exclude,
        pattern=pattern,
        allow_pattern=allow_pattern,
        flags=flags,
        message=message,
        remediation=remediation,
        cwe=_string_list(data, "cwe", rule_id),
        asvs=_string_list(data, "asvs", rule_id),
        owasp=_string_list(data, "owasp", rule_id),
        min_matches=min_matches,
        regex=regex,
        allow_regex=allow_regex,
    )


def load_profile(name: str) -> Profile:
    if name not in PROFILES:
        raise RulePackError(
            "unknown profile %r; available: %s" % (name, ", ".join(available_profiles()))
        )
    pack_names = list(PROFILES[name])
    controls: Dict[str, ControlDef] = {}
    rules: List[Rule] = []
    seen_rules = set()

    for pack_name in pack_names:
        pack = _read_pack(pack_name)
        for entry in pack.get("controls", []):
            if not isinstance(entry, dict):
                raise RulePackError("control entry must be an object in pack %s" % pack_name)
            control_id = str(entry.get("id", "")).strip()
            if not control_id:
                raise RulePackError("control without id in pack %s" % pack_name)
            existing = controls.get(control_id)
            analyzers = entry.get("analyzers", existing.analyzers if existing else [])
            if not isinstance(analyzers, list) or not all(isinstance(item, str) for item in analyzers):
                raise RulePackError("control %s analyzers must be a string list" % control_id)
            controls[control_id] = ControlDef(
                id=control_id,
                title=str(entry.get("title", existing.title if existing else control_id)),
                description=str(
                    entry.get("description", existing.description if existing else "")
                ),
                analyzers=list(analyzers),
            )
        for entry in pack.get("rules", []):
            rule = _parse_rule(entry, controls)
            if rule.id in seen_rules:
                raise RulePackError("duplicate rule id: %s" % rule.id)
            seen_rules.add(rule.id)
            rules.append(rule)

    if not controls:
        raise RulePackError("profile %s has no controls" % name)

    ordered_controls = {key: controls[key] for key in sorted(controls)}
    rules.sort(key=lambda item: item.id)
    return Profile(name=name, packs=pack_names, controls=ordered_controls, rules=rules)


def explain_rule(profile: Profile, rule_id: str) -> Optional[dict]:
    for rule in profile.rules:
        if rule.id == rule_id:
            return rule.public_dict()
    return None
