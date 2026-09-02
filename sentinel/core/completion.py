"""Context-aware prompt-toolkit completion for registry commands and options."""

from __future__ import annotations

import shlex

from prompt_toolkit.completion import Completer, Completion

from .registry import CommandRegistry


class SentinelCompleter(Completer):
    def __init__(self, registry: CommandRegistry):
        self.registry = registry

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        try:
            words = shlex.split(text)
        except ValueError:
            words = text.split()
        current = words[-1] if words else ""
        prefix = text[: len(text) - len(current)]
        if len(words) <= 1:
            for item in self.registry.search(current):
                yield Completion(item.name, start_position=-len(current), display=item.name, display_meta=item.description)
            return
        command_prefix = " ".join(words[:-1])
        for item in self.registry.search(command_prefix):
            if item.name.startswith(command_prefix) and item.name != command_prefix:
                remainder = item.name[len(command_prefix):].lstrip()
                yield Completion(remainder, start_position=-len(current), display=remainder, display_meta=item.description)

        parser = self.registry.parser
        try:
            action = parser.parse_known_args(words[:-1])[0]
        except SystemExit:
            return
        del action, prefix