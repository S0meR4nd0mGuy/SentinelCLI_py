"""Compatibility entry point for SentinelCliPy.

The implementation lives in ``src.sentinel.cli``; this module keeps direct
script execution and the historical ``import sentinelcli`` API working.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sentinel.cli import __dict__ as _cli_namespace
from sentinel.cli import main

for _name, _value in _cli_namespace.items():
    if not _name.startswith("__") or _name in {"__version__"}:
        globals()[_name] = _value

__all__ = [name for name in globals() if not name.startswith("_") or name == "__version__"]


if __name__ == "__main__":
    raise SystemExit(main())
