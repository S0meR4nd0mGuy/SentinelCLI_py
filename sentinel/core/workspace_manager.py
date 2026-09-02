"""Named workspace state manager."""

from .workspace import Workspace, WorkspaceStore


class WorkspaceManager:
    def __init__(self, store: WorkspaceStore | None = None):
        self.store = store or WorkspaceStore()
        self.current = self.store.load("default")

    def switch(self, name: str) -> Workspace:
        self.store.save(self.current)
        self.current = self.store.load(name.strip().lower())
        return self.current

    def save(self) -> None:
        self.store.save(self.current)