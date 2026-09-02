"""CLI and UI launch dispatch."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "sentinel.core"

from ..modules.auth.operations import *
from ..modules.crypto.operations import *
from ..modules.dns.operations import *
from ..modules.files.operations import *
from ..modules.network.operations import *
from ..modules.secrets.operations import *
from ..modules.tls.operations import *
from ..modules.utilities.operations import *
from .common import *
from .parser import build_parser


def _run_operator_repl(parser: argparse.ArgumentParser) -> int:
    from sentinel.core.repl import OperatorRepl

    return OperatorRepl(parser).run()

def _run_textual_app(parser: argparse.ArgumentParser) -> int:
    from sentinel.app import SentinelApp

    SentinelApp(parser).run()
    return 0

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return 130
    except ToolkitError as exc:
        eprint(f"error: {exc}")
        return 2
    except OSError as exc:
        eprint(f"error: {exc}")
        return 2

