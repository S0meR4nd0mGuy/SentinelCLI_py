"""Non-blocking command execution for the Textual application."""

from __future__ import annotations

import contextlib
import io

from .tasks import Task, TaskManager


class CommandExecutor:
    def __init__(self, command_system, tasks: TaskManager | None = None):
        self.command_system = command_system
        self.tasks = tasks or TaskManager()

    def execute(self, argv: list[str], label: str | None = None) -> Task:
        def run() -> str:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                code = self.command_system.run(argv)
            return f"exit={code}\n{output.getvalue()}"

        return self.tasks.start(label or " ".join(argv), run)