"""Textual application entry point for the Sentinel operator workstation."""

from __future__ import annotations

import shlex

from textual.app import App, ComposeResult
from textual.message import Message
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
    TabbedContent,
    TabPane,
)

from .core.command_executor import CommandExecutor
from .core.command_hints import _subparser, command_hints, format_command_hints, parser_for_command, positional_hints
from .core.command_system import CommandSystem
from .core.notification_manager import NotificationManager
from .core.search_engine import SearchEngine
from .core.workspace_manager import WorkspaceManager


class FlagItem(ListItem):
    class Select(Message):
        def __init__(self, item: "FlagItem"):
            super().__init__()
            self.item = item

    class Remove(Message):
        def __init__(self, item: "FlagItem"):
            super().__init__()
            self.item = item

    def on_mouse_down(self, event) -> None:
        if event.button == 3:
            self.post_message(self.Remove(self))
            event.stop()
        elif event.button == 1:
            self.post_message(self.Select(self))
            event.stop()


class SentinelApp(App):
    TITLE = "SentinelCLI"
    CSS = """
    Screen { layout: vertical; }
    #body { height: 1fr; }
    #modules { width: 25; border: solid $accent; }
    #main { width: 1fr; padding: 1 2; }
    #context { width: 32; border: solid $accent; padding: 1; }
    #search { margin-bottom: 1; }
    #command { margin-bottom: 1; }
    #command-list { height: 8; }
    #flag-list { height: 1fr; border: solid $surface; }
    #flag-value { margin-top: 1; }
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
        self.flag_hints = []
        self.selected_command = ""
        self.selected_flag = None
        self.selected_positional = None
        self.selected_positional_value = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            yield ListView(*(ListItem(Label(category)) for category in self.commands.registry.categories()), id="modules")
            with Vertical(id="main"):
                yield Input(placeholder="Search commands, modules, notes, targets...", id="search")
                yield Input(placeholder="Run a command with flags, e.g. crypto hash --text hello", id="command")
                yield ListView(id="command-list")
                yield Static("Select a command from the palette or module explorer.", id="output")
            with Vertical(id="context"):
                yield Static("Command Builder", id="context-title")
                yield Static("Select a command to see its flags.", id="context-details")
                yield ListView(id="flag-list")
                yield Input(placeholder="Value for selected flag", id="flag-value")
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
        if event.input.id == "command":
            self._update_builder(event.value)
            return
        if event.input.id == "flag-value" and (self.selected_flag is not None or self.selected_positional is not None):
            self._sync_flag_value(event.value)
            return
        if event.input.id != "search":
            return
        matches = self.search_engine.search(event.value, self.workspaces.current)
        text = "\n\n".join(f"{name}  [{category}]\n{description}" for name, category, description in matches[:15])
        self.query_one("#output", Static).update(text or "No matches")

    def _update_builder(self, command: str) -> None:
        suggestions, flags = command_hints(self.commands.parser, command)
        positionals = positional_hints(self.commands.parser, command)
        self.flag_hints = flags
        command_list = self.query_one("#command-list", ListView)
        command_list.clear()
        if suggestions:
            command_list.mount(*(ListItem(Label(item), name=item) for item in suggestions))
        self._show_flags(flags, positionals)
        self.query_one("#output", Static).update(format_command_hints(self.commands.parser, command))

    def _show_flags(self, flags, positionals) -> None:
        flag_list = self.query_one("#flag-list", ListView)
        flag_list.clear()
        self.query_one("#context-details", Static).update(
            f"{self.selected_command or 'Command Builder'}\n\nClick a flag to add it. Right-click an active flag to remove it."
        )
        rows = [FlagItem(Label(item.as_text()), name=f"pos:{index}") for index, item in enumerate(positionals)]
        rows.extend(FlagItem(Label(item.as_text()), name=f"flag:{index}") for index, item in enumerate(flags))
        if rows:
            flag_list.mount(*rows)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "command-list":
            command = str(event.item.name or event.item.query_one(Label).render())
            self.selected_command = command
            self.query_one("#command", Input).value = command + " "
            self._update_builder(command + " ")
            self.query_one("#command", Input).focus()
            return
        if event.list_view.id == "flag-list":
            self._select_builder_item(event.item)
            return

        if event.list_view.id == "modules":
            category = str(event.item.query_one(Label).render())
            matches = self.commands.registry.by_category(category)
            self.query_one("#output", Static).update("\n".join(f"{item.name}\n  {item.description}" for item in matches))
            self.selected_command = matches[0].name if matches else ""
            self.query_one("#context-title", Static).update(f"Command Builder: {category}")
            return

    def on_flag_item_select(self, message: FlagItem.Select) -> None:
        self._select_builder_item(message.item)

    def _select_builder_item(self, item: FlagItem) -> None:
        kind, raw_index = (item.name or "flag:0").split(":", 1)
        index = int(raw_index)
        command_input = self.query_one("#command", Input)
        tokens = shlex.split(command_input.value)
        if kind == "pos":
            self.selected_flag = None
            self.selected_positional = positional_hints(self.commands.parser, command_input.value)[index]
            self.selected_positional_value = self._positional_value(tokens, index)
            value = self.selected_positional_value
            details = self.selected_positional.as_text() + "\n\nEnter a value, then press Enter to add it to the command bar."
        else:
            self.selected_positional = None
            flag = self.flag_hints[index]
            self.selected_flag = flag
            option = flag.option.split(", ")[0]
            if option not in tokens:
                command_input.value = command_input.value.rstrip() + " " + option + " "
            value = self._value_for_flag(shlex.split(command_input.value), option)
            details = flag.as_text() + "\n\nEnter a value, then press Enter to synchronize it."
        self.query_one("#flag-value", Input).value = value
        self.query_one("#context-details", Static).update(details)
        self.query_one("#flag-value", Input).focus()

    def on_flag_item_remove(self, message: FlagItem.Remove) -> None:
        command_input = self.query_one("#command", Input)
        tokens = shlex.split(command_input.value)
        kind, raw_index = (message.item.name or "flag:0").split(":", 1)
        if kind == "pos":
            positionals = positional_hints(self.commands.parser, command_input.value)
            if not positionals:
                return
            positionals[int(raw_index)]
            command_tokens = [token for token in tokens if token not in {self.selected_command}]
            if len(command_tokens) > 1:
                tokens.pop()
            command_input.value = " ".join(shlex.quote(token) for token in tokens) + (" " if tokens else "")
            self.selected_positional = None
            self.selected_positional_value = ""
            self.query_one("#flag-value", Input).value = ""
            command_input.focus()
            return
        if not self.flag_hints:
            return
        flag = self.flag_hints[int(raw_index)]
        option = flag.option.split(", ")[0]
        filtered = []
        index = 0
        while index < len(tokens):
            if tokens[index] == option:
                index += 1
                if flag.input_required and index < len(tokens):
                    index += 1
                continue
            filtered.append(tokens[index])
            index += 1
        command_input.value = " ".join(shlex.quote(token) for token in filtered) + (" " if filtered else "")
        self.selected_flag = None
        self.selected_positional = None
        self.selected_positional_value = ""
        self.query_one("#flag-value", Input).value = ""
        command_input.focus()

    @staticmethod
    def _value_for_flag(tokens: list[str], option: str) -> str:
        try:
            index = tokens.index(option) + 1
            return tokens[index] if index < len(tokens) and not tokens[index].startswith("-") else ""
        except ValueError:
            return ""

    def _positional_value(self, tokens: list[str], position: int) -> str:
        current = self.commands.parser
        command_end = 0
        for index, token in enumerate(tokens):
            child = _subparser(current, token)
            if child is None:
                break
            current = child
            command_end = index + 1
        option_actions = {
            option: action
            for action in current._actions
            for option in action.option_strings
        }
        positional_values = []
        index = 0
        index = command_end
        while index < len(tokens):
            token = tokens[index]
            action = option_actions.get(token)
            if action is not None:
                index += 1
                if action.nargs not in {0, "?"} and index < len(tokens):
                    index += 1
                continue
            positional_values.append(token)
            index += 1
        return positional_values[position] if position < len(positional_values) else ""

    def _sync_flag_value(self, value: str) -> None:
        if self.selected_positional is not None:
            error = self.selected_positional.validate(value)
            if error:
                self.query_one("#context-details", Static).update(self.selected_positional.as_text() + "\n\nInvalid input: " + error)
                return
            command_input = self.query_one("#command", Input)
            tokens = shlex.split(command_input.value)
            if self.selected_positional_value and self.selected_positional_value in tokens:
                tokens[tokens.index(self.selected_positional_value)] = value
            elif value:
                tokens.append(value)
            elif self.selected_positional_value in tokens:
                tokens.remove(self.selected_positional_value)
            self.selected_positional_value = value
            command_input.value = " ".join(shlex.quote(token) for token in tokens) + (" " if tokens else "")
            self.query_one("#context-details", Static).update(self.selected_positional.as_text() + "\n\nInput valid and synchronized.")
            return
        flag = self.selected_flag
        error = flag.validate(value)
        details = flag.as_text()
        if error:
            self.query_one("#context-details", Static).update(details + "\n\nInvalid input: " + error)
            return
        self.query_one("#context-details", Static).update(details + "\n\nInput valid and synchronized.")
        option = flag.option.split(", ")[0]
        tokens = shlex.split(self.query_one("#command", Input).value)
        try:
            index = tokens.index(option)
        except ValueError:
            return
        if flag.input_required:
            if len(tokens) > index + 1 and not tokens[index + 1].startswith("-"):
                tokens[index + 1] = value
            elif value:
                tokens.insert(index + 1, value)
        self.query_one("#command", Input).value = " ".join(shlex.quote(token) for token in tokens) + " "

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "flag-value":
            if self.selected_flag is not None or self.selected_positional is not None:
                self._sync_flag_value(event.value)
            self.query_one("#command", Input).focus()
            return
        if event.input.id != "command":
            return
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
        event.input.value = ""

    def on_key(self, event) -> None:
        if event.key == "enter" and self.focused is not self.query_one("#search", Input):
            self.action_focus_palette()

    def task_text(self) -> str:
        return "\n".join(f"{task.task_id}  {task.status.value}  {task.label}" for task in self.executor.tasks.snapshot()) or "No tasks"

    def refresh_tasks(self) -> None:
        self.query_one("#tasks-pane Static", Static).update(self.task_text())
        completed = [task for task in self.executor.tasks.snapshot() if task.future and task.future.done()]
        if completed:
            latest = completed[-1]
            output = latest.result if latest.error is None else latest.error
            self.query_one("#results-pane Static", Static).update(str(output))