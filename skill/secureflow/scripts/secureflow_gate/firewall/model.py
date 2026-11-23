"""Core data model for firewall audits.

Reuses the Status/Evidence/Finding/Check/ControlOutcome classes from the gate
model.  This module adds a lightweight, line-aware XML wrapper that works with
the Python standard library.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.parsers import expat

from ..model import Evidence, Status


class FirewallError(ValueError):
    pass


class ConfigParseError(FirewallError):
    pass


_SENSITIVE_TAGS = (
    "password",
    "secret",
    "priv",
    "key",
    "sharedkey",
    "pre-shared-key",
    "psk",
    "token",
    "apikey",
    "api_key",
    "privatekey",
    "bcrypt-hash",
)


def redact_config_snippet(snippet: str) -> str:
    """Mask sensitive tag contents in XML snippets."""
    for tag in _SENSITIVE_TAGS:
        snippet = re.sub(
            r"(<%s\b[^>]*>).*?(</%s>)" % (tag, tag),
            r"\1***REDACTED***\2",
            snippet,
            flags=re.IGNORECASE | re.DOTALL,
        )
    return snippet


@dataclass
class FirewallConfig:
    """Parsed firewall configuration with evidence helpers."""

    path: str
    text: str
    root: ET.Element
    vendor: str
    version: Optional[str]
    _line_index: Optional[Dict[str, int]] = field(default=None, repr=False)

    @property
    def abspath(self) -> str:
        return str(Path(self.path).resolve())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    @property
    def size(self) -> int:
        return len(self.text.encode("utf-8"))

    def find(self, path: str) -> Optional[ET.Element]:
        return self.root.find(path)

    def findall(self, path: str) -> List[ET.Element]:
        return self.root.findall(path)

    def text_of(self, element: Optional[ET.Element], default: str = "") -> str:
        if element is None:
            return default
        return (element.text or "").strip() or default

    def bool_of(self, element: Optional[ET.Element]) -> bool:
        if element is None:
            return False
        if element.text:
            return element.text.strip().lower() in ("1", "true", "enabled", "yes")
        # Empty tag such as <enable/> is truthy.
        return True

    def tag_path(self, element: ET.Element) -> str:
        parts: List[str] = []
        node: Optional[ET.Element] = element
        while node is not None and node != self.root:
            parts.append(node.tag)
            node = self._parent_of(node)
        parts.reverse()
        return "/".join(parts)

    def _parent_of(self, element: ET.Element) -> Optional[ET.Element]:
        for parent in self.root.iter():
            for child in parent:
                if child is element:
                    return parent
        return None

    def _build_line_index(self) -> Dict[str, int]:
        """Map every element path (with sibling indices) to its opening line.

        A single expat pass records the source line of each start tag.  Paths
        are built from the same sibling-index convention used by
        :meth:`_path_with_index`, so lookups are exact regardless of how often
        (or how little) ``evidence()`` is called for repeated tags such as
        ``<rule>``.
        """
        index: Dict[str, int] = {}
        stack: List[str] = []
        counters: List[Dict[str, int]] = [{}]
        parser = expat.ParserCreate()

        def _start(name: str, _attrs: Dict[str, str]) -> None:
            counter = counters[-1]
            seen = counter.get(name, 0)
            counter[name] = seen + 1
            component = name if seen == 0 else "%s[%d]" % (name, seen)
            stack.append(component)
            counters.append({})
            path = "/".join(stack)
            if path not in index:
                index[path] = parser.CurrentLineNumber

        def _end(_name: str) -> None:
            if stack:
                stack.pop()
            if counters:
                counters.pop()

        parser.StartElementHandler = _start
        parser.EndElementHandler = _end
        parser.Parse(self.text, True)
        return index

    def _path_with_index(self, element: ET.Element) -> str:
        parts: List[str] = []
        node: Optional[ET.Element] = element
        while node is not None:
            parent = self._parent_of(node)
            if parent is None:
                parts.append(node.tag)
                break
            index = 0
            for sibling in parent:
                if sibling is node:
                    break
                if sibling.tag == node.tag:
                    index += 1
            parts.append(node.tag if index == 0 else "%s[%d]" % (node.tag, index))
            node = parent
        parts.reverse()
        return "/".join(parts)

    def _line_for_element(self, element: ET.Element) -> int:
        if self._line_index is None:
            try:
                self._line_index = self._build_line_index()
            except expat.ExpatError:
                # The tree was already parsed by ElementTree; if expat cannot
                # re-parse the text, fall back to signature search below.
                self._line_index = {}
        line = self._line_index.get(self._path_with_index(element))
        if line is not None:
            return line
        # Fallback: first occurrence of the opening signature.
        signature = self._opening_signature(element)
        idx = self.text.find(signature) if signature else -1
        if idx < 0:
            return 1
        return self.text[:idx].count("\n") + 1

    def _opening_signature(self, element: ET.Element) -> str:
        if not element.attrib:
            return "<%s" % element.tag
        # Use the first attribute to disambiguate repeated tags.
        attr_name = sorted(element.attrib.keys())[0]
        return '<%s %s="%s"' % (element.tag, attr_name, element.attrib[attr_name])

    def _snippet(self, element: ET.Element, max_length: int = 300) -> str:
        raw = ET.tostring(element, encoding="unicode")
        raw = raw.replace("\n", " ")
        if len(raw) > max_length:
            raw = raw[: max_length - 3] + "..."
        return raw

    def evidence(self, element: ET.Element, snippet: Optional[str] = None) -> Evidence:
        raw = snippet if snippet is not None else self._snippet(element)
        redacted = redact_config_snippet(raw)
        return Evidence(
            path=self.path,
            line=self._line_for_element(element),
            column=1,
            snippet=redacted,
            snippet_sha256=hashlib.sha256(redacted.strip().encode("utf-8")).hexdigest(),
            language="xml",
        )

    def evidence_at_path(self, path: str, snippet: Optional[str] = None) -> Optional[Evidence]:
        element = self.find(path)
        if element is None:
            return None
        return self.evidence(element, snippet=snippet)


@dataclass
class FirewallFinding:
    """Firewall-specific finding before conversion to the shared Finding model."""

    rule_id: str
    control: str
    title: str
    severity: str
    confidence: str
    result: Status
    message: str
    remediation: str
    evidence: Evidence
    cwe: List[str] = field(default_factory=list)
    asvs: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)

    def to_finding(self) -> Any:
        from ..model import Finding

        return Finding(
            rule_id=self.rule_id,
            control=self.control,
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            result=self.result,
            message=self.message,
            remediation=self.remediation,
            cwe=list(self.cwe),
            asvs=list(self.asvs),
            owasp=list(self.owasp),
            evidence=self.evidence,
        )
