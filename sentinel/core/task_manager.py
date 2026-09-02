"""Application-facing alias for concurrent task management."""

from .tasks import Task, TaskManager

__all__ = ["Task", "TaskManager"]