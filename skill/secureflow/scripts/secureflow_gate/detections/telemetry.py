"""Telemetry source registry for detection engineering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


PACKAGE = Path(__file__).resolve().parents[1]
DATA_FILE = PACKAGE / "data" / "telemetry-sources.json"


def load_sources(path: Optional[Path] = None) -> Dict[str, Any]:
    data_path = path or DATA_FILE
    with data_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("schema_version") != "secureflow.telemetry-sources/v1":
        raise ValueError("Telemetry sources schema must be secureflow.telemetry-sources/v1")
    return data.get("sources", {})


def source_products(source: Dict[str, Any]) -> str:
    return ", ".join(source.get("products", ["unknown"]))
