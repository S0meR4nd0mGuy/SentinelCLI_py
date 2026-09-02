"""Small concurrent task manager for scans that should not hold the REPL."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Event
from uuid import uuid4


class TaskStatus(str, Enum):
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class Task:
    task_id: str
    label: str
    started_at: datetime
    status: TaskStatus = TaskStatus.RUNNING
    progress: float = 0.0
    result: object = None
    error: str | None = None
    stop_event: Event = field(default_factory=Event, repr=False)
    future: Future | None = field(default=None, repr=False)


class TaskManager:
    def __init__(self, workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sentinel-task")
        self.tasks: dict[str, Task] = {}

    def start(self, label: str, function, *args, **kwargs) -> Task:
        task = Task(uuid4().hex[:8], label, datetime.now(timezone.utc))
        self.tasks[task.task_id] = task

        def run():
            try:
                task.result = function(*args, **kwargs)
                task.progress = 1.0
                task.status = TaskStatus.STOPPED if task.stop_event.is_set() else TaskStatus.COMPLETE
            except Exception as exc:
                task.error = str(exc)
                task.status = TaskStatus.FAILED
            return task.result

        task.future = self.executor.submit(run)
        return task

    def stop(self, task_id: str) -> None:
        task = self.tasks[task_id]
        task.stop_event.set()
        if task.future and task.future.cancel():
            task.status = TaskStatus.STOPPED

    def snapshot(self) -> list[Task]:
        return list(self.tasks.values())