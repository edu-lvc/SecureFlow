#!/usr/bin/env python3
"""Zero-install launcher for SecureFlow Gate.

Run directly from the skill directory:
    python scripts/secureflow-gate.py scan --root . --profile csharp-aspnetcore
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from secureflow_gate.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
