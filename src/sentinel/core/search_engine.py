"""Unified fuzzy search over commands and workspace records."""

from .fuzzy import fuzzy_score
from .registry import CommandRegistry


class SearchEngine:
    def __init__(self, registry: CommandRegistry):
        self.registry = registry

    def search(self, query: str, workspace=None) -> list[tuple[str, str, str]]:
        results = [(item.name, item.category, item.description) for item in self.registry.search(query)]
        if workspace is not None:
            needle = query.lower()
            for label, values in (("note", workspace.notes), ("target", workspace.targets), ("history", workspace.recent_commands)):
                for value in values:
                    if not needle or fuzzy_score(needle, value.lower(), value.lower()) > 0.5:
                        results.append((value, label.title(), f"Workspace {label}"))
        return results