"""Textual shell for browsing the same central command registry."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, Static

from sentinel.core.registry import CommandRegistry


class SentinelApp(App):
    CSS = """
    Screen { layout: horizontal; }
    #modules { width: 24; border: solid $accent; }
    #content { width: 1fr; padding: 1 2; }
    #search { dock: top; margin-bottom: 1; }
    """
    BINDINGS = [("ctrl+p", "focus_search", "Palette"), ("f5", "refresh", "Refresh")]

    def __init__(self, parser):
        super().__init__()
        self.registry = CommandRegistry(parser)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield ListView(*(ListItem(Label(category)) for category in self.registry.categories()), id="modules")
            with Vertical(id="content"):
                yield Input(placeholder="Search commands...", id="search")
                yield Static("Select a category or search the command registry.", id="details")
        yield Footer()

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        matches = self.registry.search(event.value, limit=12)
        self.query_one("#details", Static).update("\n".join(f"{item.name}  [{item.category}]\n  {item.description}" for item in matches))

    def action_refresh(self) -> None:
        self.query_one("#search", Input).value = ""