"""Redaction of credential-like values in snippets and command output."""

from __future__ import annotations

import re

REDACTED = "***REDACTED***"

_KEY = (
    r"password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key|jwt[_-]?key|signing[_-]?key|"
    r"auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token"
)

_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>\b(?:" + _KEY + r")\b)(?P<keyquote>[\"']?)(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>[\"']?)(?P<value>[^\"'\s,;]{4,})(?P=quote)"
)

_CONNECTION = re.compile(
    r"(?i)(?P<key>\b(?:password|pwd)\b)(?P<sep>\s*=\s*)"
    r"(?P<quote>[\"']?)(?P<value>[^;\"'\s]{3,})(?P=quote)"
)

_TOKEN = re.compile(
    r"(?i)\b("
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk_live_[A-Za-z0-9]{10,}|"
    r"sk-[A-Za-z0-9]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)

_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def redact_snippet(text: str) -> str:
    """Mask credential values while leaving the key and location readable."""

    if not text:
        return text

    def assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        if value in (REDACTED, "***", "..."):
            return match.group(0)
        return "%s%s%s%s%s%s" % (
            match.group("key"),
            match.group("keyquote"),
            match.group("sep"),
            match.group("quote"),
            REDACTED,
            match.group("quote"),
        )

    def connection(match: re.Match[str]) -> str:
        return "%s%s%s%s" % (
            match.group("key"),
            match.group("sep"),
            "***REDACTED***",
            match.group("quote"),
        )

    result = _TOKEN.sub(REDACTED, text)
    result = _PEM.sub("-----BEGIN ***REDACTED*** PRIVATE KEY-----", result)
    result = _ASSIGNMENT.sub(assignment, result)
    result = _CONNECTION.sub(connection, result)
    return result
