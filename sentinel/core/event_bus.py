"""Small synchronous event bus for UI and service coordination."""

from collections import defaultdict
from collections.abc import Callable


class EventBus:
    def __init__(self):
        self._listeners: dict[str, list[Callable[[object], None]]] = defaultdict(list)

    def subscribe(self, event: str, listener: Callable[[object], None]) -> None:
        self._listeners[event].append(listener)

    def publish(self, event: str, payload: object = None) -> None:
        for listener in self._listeners[event]:
            listener(payload)