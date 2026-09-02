"""Entry-point based plugin discovery for future external command modules."""

from importlib.metadata import entry_points


class PluginLoader:
    def load(self, group: str = "sentinelclipy.plugins") -> list[object]:
        loaded = []
        for plugin in entry_points().select(group=group):
            loaded.append(plugin.load())
        return loaded