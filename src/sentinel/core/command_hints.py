"""Autocomplete and argument documentation for command input widgets."""

from __future__ import annotations

import argparse
import ipaddress
import shlex
import urllib.parse
from dataclasses import dataclass

from .registry import CommandRegistry


@dataclass(frozen=True)
class FlagHint:
    option: str
    description: str
    value_type: str
    default: str
    choices: str
    required: bool
    input_required: bool
    nargs: str
    format_hint: str = ""

    def as_text(self) -> str:
        details = []
        if self.choices:
            details.append(f"values: {self.choices}")
        if self.default not in {"", "None"}:
            details.append(f"default: {self.default}")
        if self.required:
            details.append("required")
        suffix = ", ".join(details)
        input_text = f"input: {self.value_type}"
        if self.format_hint:
            input_text += f", format: {self.format_hint}"
        if self.nargs not in {"", "None"}:
            input_text += f" x{self.nargs}"
        details.insert(0, input_text)
        return f"{self.option:<24} {self.description} ({', '.join(details)})"

    def validate(self, value: str) -> str | None:
        if not value and self.input_required:
            return f"{self.option} requires a {self.value_type} value."
        if not value:
            return None
        if self.choices and value not in self.choices.split(", "):
            return f"{self.option} must be one of: {self.choices}."
        format_error = _validate_format(value, self.format_hint)
        if format_error:
            return f"{self.option} {format_error}"
        try:
            if self.value_type == "int":
                int(value)
            elif self.value_type == "float":
                float(value)
        except ValueError:
            return f"{self.option} requires a {self.value_type} value."
        return None


@dataclass(frozen=True)
class PositionalHint:
    name: str
    description: str
    value_type: str
    required: bool
    nargs: str
    format_hint: str = ""

    @property
    def input_required(self) -> bool:
        return self.required

    def as_text(self) -> str:
        requirement = "required" if self.required else "optional"
        count = f", x{self.nargs}" if self.nargs not in {"", "None"} else ""
        input_text = f"input: {self.value_type}"
        if self.format_hint:
            input_text += f", format: {self.format_hint}"
        return f"{self.name:<24} {self.description} ({input_text}{count}, {requirement})"

    def validate(self, value: str) -> str | None:
        if not value and self.required:
            return f"{self.name} requires a {self.value_type} value."
        format_error = _validate_format(value, self.format_hint)
        if format_error:
            return f"{self.name} {format_error}"
        try:
            if value and self.value_type == "int":
                int(value)
            elif value and self.value_type == "float":
                float(value)
        except ValueError:
            return f"{self.name} requires a {self.value_type} value."
        return None


def _validate_format(value: str, format_hint: str) -> str | None:
    if not value or not format_hint:
        return None
    if format_hint == "IPv4/IPv6 address":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return "must be a valid IPv4/IPv6 address."
    elif format_hint == "URL":
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "must be a valid http:// or https:// URL."
    return None


def _format_hint(name: str, parser: argparse.ArgumentParser) -> str:
    if name in {"address", "ip"} or (name == "host" and parser.prog.endswith(" ping")):
        return "IPv4/IPv6 address"
    if name in {"url", "uri"}:
        return "URL"
    if name in {"file", "path", "output", "wordlist", "left_file", "right_file"}:
        return "filesystem path"
    return ""


def _subparser(parser: argparse.ArgumentParser, token: str) -> argparse.ArgumentParser | None:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(token)
    return None


def parser_for_command(parser: argparse.ArgumentParser, tokens: list[str]) -> argparse.ArgumentParser:
    current = parser
    for token in tokens:
        if token.startswith("-"):
            continue
        child = _subparser(current, token)
        if child is None:
            break
        current = child
    return current


def _flag_hint(action: argparse.Action, parser: argparse.ArgumentParser | None = None) -> FlagHint | None:
    if not action.option_strings:
        return None
    option = ", ".join(action.option_strings)
    if isinstance(action, argparse.BooleanOptionalAction):
        value_type = "boolean"
    elif action.type is not None:
        value_type = getattr(action.type, "__name__", str(action.type))
    elif action.nargs == 0:
        value_type = "switch"
    else:
        value_type = "string"
    choices = ", ".join(str(choice) for choice in action.choices) if action.choices is not None else ""
    default = "" if action.default is argparse.SUPPRESS else str(action.default)
    input_required = action.nargs != 0 and action.nargs != "?"
    nargs = "" if action.nargs is None else str(action.nargs)
    return FlagHint(option, action.help or "No description available.", value_type, default, choices, bool(action.required), input_required, nargs, _format_hint(action.dest, parser) if parser else "")


def flag_hints(parser: argparse.ArgumentParser, line: str) -> list[FlagHint]:
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    current = parser_for_command(parser, tokens)
    return [hint for action in current._actions if (hint := _flag_hint(action, current)) is not None]


def positional_hints(parser: argparse.ArgumentParser, line: str) -> list[PositionalHint]:
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    current = parser_for_command(parser, tokens)
    hints = []
    for action in current._actions:
        if action.option_strings or isinstance(action, argparse._SubParsersAction) or action.dest == "help":
            continue
        value_type = getattr(action.type, "__name__", "string") if action.type else "string"
        nargs = "" if action.nargs is None else str(action.nargs)
        hints.append(PositionalHint(action.dest, action.help or "Positional input.", value_type, action.nargs not in {"?", "*"}, nargs, _format_hint(action.dest, current)))
    return hints


def command_hints(parser: argparse.ArgumentParser, line: str, limit: int = 8) -> tuple[list[str], list[FlagHint]]:
    """Return fuzzy command completions and flags for the command under input."""
    stripped = line.strip()
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        tokens = stripped.split()
    registry = CommandRegistry(parser)
    suggestions: list[str] = []
    if tokens and not line.endswith(" ") and not tokens[-1].startswith("-"):
        partial = " ".join(tokens)
        suggestions = [item.name for item in registry.search(partial, limit=limit)]
    elif not tokens:
        suggestions = [item.name for item in registry.search("", limit=limit)]
    return suggestions, flag_hints(parser, line) if tokens else []


def format_command_hints(parser: argparse.ArgumentParser, line: str, limit: int = 8) -> str:
    suggestions, flags = command_hints(parser, line, limit)
    positionals = positional_hints(parser, line)
    sections: list[str] = []
    if suggestions:
        sections.append("Possible commands\n" + "\n".join(f"  {item}" for item in suggestions))
    if flags and len(line.split()) >= 2:
        sections.append("Available flags\n" + "\n".join(f"  {flag.as_text()}" for flag in flags))
    if positionals and len(line.split()) >= 1:
        sections.append("Required parameters\n" + "\n".join(f"  {item.as_text()}" for item in positionals))
    return "\n\n".join(sections) or "No matching commands or flags."
