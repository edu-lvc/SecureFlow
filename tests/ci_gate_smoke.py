#!/usr/bin/env python3
"""CI smoke test: verify the reference examples produce the expected gate exits."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "skill" / "secureflow" / "scripts" / "secureflow-gate.py"


def run(*args: str) -> int:
    completed = subprocess.run(
        [sys.executable, str(GATE), *args],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.stderr:
        sys.stderr.write(completed.stderr.decode("utf-8", "replace"))
    return completed.returncode


def main() -> int:
    secure = ROOT / "examples" / "csharp-secure" / "SecureOrders.Api"
    vulnerable = ROOT / "examples" / "csharp-vulnerable" / "VulnerableOrders.Api"
    failures = []

    secure_exit = run("scan", "--root", str(secure))
    if secure_exit != 0:
        failures.append("secure example expected exit 0, got %d" % secure_exit)

    vulnerable_exit = run("scan", "--root", str(vulnerable))
    if vulnerable_exit != 1:
        failures.append("vulnerable example expected exit 1, got %d" % vulnerable_exit)

    with tempfile.TemporaryDirectory(prefix="secureflow-ci-") as directory:
        report = Path(directory) / "report.json"
        scan_exit = run("scan", "--root", str(secure), "--report", str(report))
        if scan_exit != 0:
            failures.append("secure report scan expected exit 0, got %d" % scan_exit)
        if report.is_file():
            verify_exit = run("verify-report", "--report", str(report))
            if verify_exit != 0:
                failures.append("report verification expected exit 0, got %d" % verify_exit)
        else:
            failures.append("report was not written")

    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("CI gate smoke test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
