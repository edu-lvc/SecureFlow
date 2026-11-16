"""Small, dependency-free glob matching used by rules and scanning."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, List, Sequence


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")


@lru_cache(maxsize=1024)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a portable glob.

    Supports ``**`` (any path segments), ``*`` (within one segment), ``?`` and
    character classes. Matching is case-sensitive on POSIX and case-insensitive
    on Windows, matching normal filesystem expectations.
    """

    pattern = normalize_path(pattern)
    out: List[str] = ["^"]
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if index + 1 < length and pattern[index + 1] == "*":
                index += 2
                if index < length and pattern[index] == "/":
                    index += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = pattern.find("]", index + 1)
            if end == -1:
                out.append(r"\[")
            else:
                content = pattern[index + 1 : end]
                if content.startswith("!"):
                    content = "^" + content[1:]
                out.append("[" + content + "]")
                index = end
        else:
            out.append(re.escape(char))
        index += 1
    out.append("$")
    flags = re.IGNORECASE if _is_windows() else 0
    return re.compile("".join(out), flags)


def _is_windows() -> bool:
    import os

    return os.name == "nt"


def matches_any(path: str, patterns: Sequence[str]) -> bool:
    normalized = normalize_path(path)
    return any(compile_glob(pattern).match(normalized) for pattern in patterns)


def filter_includes(path: str, include: Sequence[str], exclude: Sequence[str]) -> bool:
    normalized = normalize_path(path)
    if include and not any(compile_glob(pattern).match(normalized) for pattern in include):
        return False
    if exclude and any(compile_glob(pattern).match(normalized) for pattern in exclude):
        return False
    return True


def unique_preserving_order(items: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
