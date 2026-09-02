"""Compatibility facade for parsing commands through the legacy argparse tree."""

from __future__ import annotations

import argparse


def execute(parser: argparse.ArgumentParser, argv: list[str]) -> int:
    """Parse and execute one command without changing existing handlers."""
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if not hasattr(arguments, "func"):
        parser.print_help()
        return 0
    return int(arguments.func(arguments) or 0)