"""Application-facing notification service."""

from .notifications import Notification, NotificationCenter, NotificationType


class NotificationManager(NotificationCenter):
    def notify(self, message: str, level: NotificationType = NotificationType.INFO) -> Notification:
        return self.add(message, level)