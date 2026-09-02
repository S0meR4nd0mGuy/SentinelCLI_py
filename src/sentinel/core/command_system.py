"""Command metadata and execution facade used by all UI surfaces."""

from __future__ import annotations

import argparse

from .command_parser import execute
from .registry import CommandRegistry


class CommandSystem:
    def __init__(self, parser: argparse.ArgumentParser):
        self.parser = parser
        self.registry = CommandRegistry(parser)

    def run(self, argv: list[str]) -> int:
        return execute(self.parser, argv)