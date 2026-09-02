import time
import unittest

import sentinelcli
from sentinel.core.command_system import CommandSystem
from sentinel.core.registry import CommandRegistry
from sentinel.core.search_engine import SearchEngine
from sentinel.core.task_manager import TaskManager
from sentinel.core.workspace import Workspace


class OperatorConsoleTests(unittest.TestCase):
    def setUp(self):
        self.registry = CommandRegistry(sentinelcli.build_parser())

    def test_registry_search_finds_command_and_category(self):
        self.assertEqual(self.registry.search("tls")[0].name, "tls")
        self.assertIn("Tls", self.registry.categories())

    def test_search_engine_includes_workspace_records(self):
        results = SearchEngine(self.registry).search("target", Workspace("audit", targets=["target.example"]))
        self.assertTrue(any(item[0] == "target.example" for item in results))

    def test_task_manager_runs_work_without_blocking_submission(self):
        manager = TaskManager(workers=1)
        task = manager.start("test", lambda: "done")
        self.assertIsNotNone(task.future)
        task.future.result(timeout=2)
        self.assertEqual(task.result, "done")

    def test_command_system_preserves_legacy_handler(self):
        self.assertEqual(CommandSystem(sentinelcli.build_parser()).registry.get("tls").name, "tls")


if __name__ == "__main__":
    unittest.main()