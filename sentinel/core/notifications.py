"""In-memory notification center with durable access during a console session."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class NotificationType(str, Enum):
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Notification:
    level: NotificationType
    message: str
    created_at: datetime


class NotificationCenter:
    def __init__(self):
        self.items: list[Notification] = []

    def add(self, message: str, level: NotificationType = NotificationType.INFO) -> Notification:
        item = Notification(level, message, datetime.now(timezone.utc))
        self.items.append(item)
        return item

    def clear(self) -> None:
        self.items.clear()