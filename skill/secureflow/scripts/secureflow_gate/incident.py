"""Incident response template helpers.

Templates live in ``data/incident/`` inside the package so they are available
after ``pip install``. If the package data is missing, the module falls back to
the skill's ``assets/`` directory when running from the source tree.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence


class IncidentError(RuntimeError):
    pass


_TEMPLATES = (
    "incident-response-template.md",
    "ioc-template.md",
    "timeline-template.md",
)


def _template_dir() -> Path:
    package_dir = Path(__file__).resolve().parent
    candidate = package_dir / "data" / "incident"
    if candidate.is_dir() and any(candidate.iterdir()):
        return candidate
    # Fallback for source-tree execution when package data is not installed.
    fallback = package_dir.parents[2] / "assets"
    if fallback.is_dir():
        return fallback
    raise IncidentError("Incident response templates are not installed")


def init_incident(output_dir: str, force: bool = False) -> Sequence[Path]:
    """Copy the incident response templates into *output_dir*.

    Returns the list of files written.
    """

    source = _template_dir()
    destination = Path(output_dir).resolve()
    if destination.exists() and not force:
        raise IncidentError(
            "Destination already exists: %s (use --force to overwrite)" % destination
        )
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in _TEMPLATES:
        src = source / name
        if src.is_file():
            dst = destination / name
            shutil.copy2(str(src), str(dst))
            written.append(dst)
    if not written:
        raise IncidentError("No incident response templates were found in %s" % source)
    return written
