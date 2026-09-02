"""Textual application entry point for the Sentinel operator workstation."""

from __future__ import annotations

import shlex

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, Static, TabbedContent, TabPane

from .core.command_executor import CommandExecutor
from .core.command_system import CommandSystem
from .core.notification_manager import NotificationManager
from .core.search_engine import SearchEngine
from .core.workspace_manager import WorkspaceManager


class SentinelApp(App):
    TITLE = "SentinelCliPy Operator Console"
    CSS = """
    Screen { layout: vertical; }
    #body { height: 1fr; }
    #modules { width: 25; border: solid $accent; }
    #main { width: 1fr; padding: 1 2; }
    #context { width: 32; border: solid $accent; padding: 1; }
    #search { margin-bottom: 1; }
    #output { height: 1fr; border: solid $surface; padding: 1; overflow-y: auto; }
    """
    BINDINGS = [
        ("ctrl+p", "focus_palette", "Command palette"),
        ("ctrl+shift+p", "focus_everywhere", "Search everywhere"),
        ("ctrl+w", "switch_workspace", "Workspace"),
        ("ctrl+t", "show_tasks", "Tasks"),
        ("ctrl+n", "show_notifications", "Notifications"),
        ("f5", "refresh", "Refresh"),
        ("f1", "show_help", "Help"),
    ]

    def __init__(self, parser):
        super().__init__()
        self.commands = CommandSystem(parser)
        self.search_engine = SearchEngine(self.commands.registry)
        self.executor = CommandExecutor(self.commands)
        self.workspaces = WorkspaceManager()
        self.notifications = NotificationManager()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield ListView(*(ListItem(Label(category)) for category in self.commands.registry.categories()), id="modules")
            with Vertical(id="main"):
                yield Input(placeholder="Search commands, modules, notes, targets...", id="search")
                yield Static("Select a command from the palette or module explorer.", id="output")
            yield Static("No command selected", id="context")
        with TabbedContent(initial="logs-pane"):
            yield TabPane("Logs", Static("Ready", id="logs"), id="logs-pane")
            yield TabPane("Notifications", Static("No notifications", id="notifications"), id="notifications-pane")
            yield TabPane("Tasks", Static("No running tasks", id="tasks"), id="tasks-pane")
            yield TabPane("Results", Static("No results", id="results"), id="results-pane")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(0.25, self.refresh_tasks)

    def action_focus_palette(self) -> None:
        self.query_one("#search", Input).focus()

    def action_focus_everywhere(self) -> None:
        self.action_focus_palette()

    def action_refresh(self) -> None:
        self.refresh_tasks()

    def action_show_help(self) -> None:
        self.query_one("#output", Static).update("Ctrl-P palette | Ctrl-Shift-P search everywhere | Ctrl-W workspace | Ctrl-T tasks")

    def action_switch_workspace(self) -> None:
        self.query_one("#output", Static).update("Workspace: " + self.workspaces.current.name + "\nAvailable: " + ", ".join(self.workspaces.store.names()))

    def action_show_tasks(self) -> None:
        self.refresh_tasks()
        self.query_one("#tasks-pane Static", Static).update(self.task_text())

    def action_show_notifications(self) -> None:
        text = "\n".join(f"{item.level.value}: {item.message}" for item in self.notifications.items) or "No notifications"
        self.query_one("#notifications-pane Static", Static).update(text)

    def on_input_changed(self, event: Input.Changed) -> None:
        matches = self.search_engine.search(event.value, self.workspaces.current)
        text = "\n\n".join(f"{name}  [{category}]\n{description}" for name, category, description in matches[:15])
        self.query_one("#output", Static).update(text or "No matches")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        command = event.value.strip()
        if not command:
            return
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            self.notifications.notify(str(exc))
            return
        task = self.executor.execute(argv)
        self.workspaces.current.recent_commands.insert(0, command)
        self.workspaces.current.recent_commands = self.workspaces.current.recent_commands[:100]
        self.workspaces.save()
        self.query_one("#output", Static).update(f"Started task {task.task_id}: {task.label}")

    def on_key(self, event) -> None:
        if event.key == "enter" and self.focused is not self.query_one("#search", Input):
            self.action_focus_palette()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        category = str(event.item.query_one(Label).render())
        matches = self.commands.registry.by_category(str(category))
        self.query_one("#output", Static).update("\n".join(f"{item.name}\n  {item.description}" for item in matches))

    def task_text(self) -> str:
        return "\n".join(f"{task.task_id}  {task.status.value}  {task.label}" for task in self.executor.tasks.snapshot()) or "No tasks"

    def refresh_tasks(self) -> None:
        self.query_one("#tasks-pane Static", Static).update(self.task_text())
        completed = [task for task in self.executor.tasks.snapshot() if task.future and task.future.done()]
        if completed:
            latest = completed[-1]
            output = latest.result if latest.error is None else latest.error
            self.query_one("#results-pane Static", Static).update(str(output))