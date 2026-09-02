"""Command discovery built from the existing argparse command tree."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from .fuzzy import fuzzy_score


@dataclass(frozen=True)
class CommandInfo:
    name: str
    category: str
    description: str
    usage: str = ""
    examples: tuple[str, ...] = field(default_factory=tuple)
    aliases: tuple[str, ...] = field(default_factory=tuple)

    @property
    def search_text(self) -> str:
        return " ".join((self.name, self.category, self.description, *self.aliases, *self.examples)).lower()


class CommandRegistry:
    """Discover commands from argparse, so legacy registrations remain authoritative."""

    def __init__(self, parser: argparse.ArgumentParser):
        self.parser = parser
        self.commands = self._discover(parser)

    @staticmethod
    def _discover(parser: argparse.ArgumentParser) -> list[CommandInfo]:
        entries: list[CommandInfo] = []

        def visit(current: argparse.ArgumentParser, path: list[str], category: str) -> None:
            actions = getattr(current, "_actions", ())
            sub_action = next((action for action in actions if isinstance(action, argparse._SubParsersAction)), None)
            if sub_action is None and path:
                command = " ".join(path)
                entries.append(CommandInfo(
                    name=command,
                    category=category.title(),
                    description=current.description or getattr(current, "_sentinel_help", "No description available."),
                    usage=current.format_usage().strip(),
                    aliases=tuple(getattr(current, "_aliases", ())),
                ))
                return
            if sub_action is None:
                return
            help_by_name = {action.dest: action.help or "No description available." for action in sub_action._choices_actions}
            for name, child in sub_action.choices.items():
                if name in getattr(child, "_aliases", ()):
                    continue
                next_category = path[0] if path else name
                child._sentinel_help = help_by_name.get(name, "No description available.")
                visit(child, [*path, name], next_category)

        visit(parser, [], "utilities")
        return sorted(entries, key=lambda item: item.name)

    def search(self, query: str, limit: int = 30) -> list[CommandInfo]:
        needle = query.strip().lower()
        if not needle:
            return self.commands[:limit]

        def score(item: CommandInfo) -> tuple[float, str]:
            name = item.name.lower()
            rank = fuzzy_score(needle, name, item.search_text)
            return rank, item.name

        return sorted(self.commands, key=score, reverse=True)[:limit]

    def categories(self) -> list[str]:
        return sorted({item.category for item in self.commands})

    def by_category(self, category: str) -> list[CommandInfo]:
        return [item for item in self.commands if item.category.lower() == category.lower()]

    def get(self, name: str) -> CommandInfo | None:
        normalized = name.strip().lower()
        return next((item for item in self.commands if item.name.lower() == normalized or normalized in item.aliases), None)

    def help_text(self, name: str) -> str:
        item = self.get(name)
        if item is None:
            return "Command not found."
        aliases = ", ".join(item.aliases) or "none"
        examples = "\n".join(item.examples) or "No examples registered."
        return f"{item.description}\n\nUsage\n{item.usage}\n\nAliases\n{aliases}\n\nExamples\n{examples}"