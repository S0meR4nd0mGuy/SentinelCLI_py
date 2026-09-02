"""Persistent operator workspaces for history, notes, targets, and recency."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Workspace:
    name: str
    notes: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    recent_commands: list[str] = field(default_factory=list)


class WorkspaceStore:
    def __init__(self, root: Path | None = None):
        self.root = root or Path.home() / ".sentinelclipy" / "workspaces"
        self.root.mkdir(parents=True, exist_ok=True)

    def names(self) -> list[str]:
        return sorted(path.stem for path in self.root.glob("*.json"))

    def load(self, name: str) -> Workspace:
        path = self.root / f"{name}.json"
        if not path.exists():
            return Workspace(name)
        return Workspace(**json.loads(path.read_text(encoding="utf-8")))

    def save(self, workspace: Workspace) -> None:
        path = self.root / f"{workspace.name}.json"
        path.write_text(json.dumps(asdict(workspace), indent=2), encoding="utf-8")