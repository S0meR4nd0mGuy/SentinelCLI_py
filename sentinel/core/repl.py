"""Prompt-toolkit operator REPL backed by the legacy parser."""

from __future__ import annotations

import shlex
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .completion import SentinelCompleter
from .notifications import NotificationCenter
from .registry import CommandRegistry
from .workspace import WorkspaceStore


class OperatorRepl:
    def __init__(self, parser, *, history_path: Path | None = None):
        self.parser = parser
        self.registry = CommandRegistry(parser)
        self.console = Console()
        self.notifications = NotificationCenter()
        self.workspaces = WorkspaceStore()
        self.workspace = self.workspaces.load("default")
        history_path = history_path or Path.home() / ".sentinelclipy" / "history"
        history_path.parent.mkdir(parents=True, exist_ok=True)
        self.session = PromptSession(
            "sentinel> ", history=FileHistory(str(history_path)),
            auto_suggest=AutoSuggestFromHistory(), completer=SentinelCompleter(self.registry),
            complete_while_typing=True, key_bindings=self._bindings(),
        )

    def _bindings(self):
        bindings = KeyBindings()

        @bindings.add("c-p")
        def palette(event):
            query = event.app.prompt("palette> ")
            matches = self.registry.search(query)
            if matches:
                event.app.current_buffer.text = matches[0].name

        @bindings.add("c-l")
        def clear(event):
            event.app.renderer.clear()

        @bindings.add("f1")
        def help_hint(event):
            self.console.print(Panel("Type a command, Ctrl-P for palette, or help <term> for search.", title="Sentinel help"))

        return bindings

    def show_palette(self, query: str = "") -> None:
        table = Table("Command", "Category", "Description", title="Command Palette")
        for item in self.registry.search(query):
            table.add_row(item.name, item.category, item.description)
        self.console.print(table)

    def execute(self, line: str) -> int:
        words = shlex.split(line)
        if not words:
            return 0
        if words[0] in {"help", "?"}:
            self.show_palette(" ".join(words[1:]))
            return 0
        self.workspace.recent_commands.insert(0, line)
        self.workspace.recent_commands = self.workspace.recent_commands[:100]
        self.workspaces.save(self.workspace)
        try:
            args = self.parser.parse_args(words)
            return int(args.func(args) or 0) if hasattr(args, "func") else 0
        except SystemExit:
            return 2
        except Exception as exc:
            self.notifications.add(str(exc))
            self.console.print(f"[red]error:[/red] {exc}")
            return 2

    def run(self) -> int:
        self.console.print(Panel("SentinelCliPy operator console", subtitle="Ctrl-P palette | Ctrl-R history | F1 help"))
        while True:
            try:
                line = self.session.prompt()
            except (EOFError, KeyboardInterrupt):
                self.workspaces.save(self.workspace)
                return 0
            if line.strip().lower() in {"exit", "quit"}:
                return 0
            self.execute(line)