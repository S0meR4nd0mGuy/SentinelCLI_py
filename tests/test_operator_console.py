import time
import unittest

import sentinelcli
from sentinel.core.command_system import CommandSystem
from sentinel.core.command_hints import command_hints, positional_hints
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

    def test_command_hints_describe_and_validate_flags(self):
        suggestions, flags = command_hints(sentinelcli.build_parser(), "crypto encrypt ")
        self.assertFalse(suggestions)
        method = next(flag for flag in flags if "--method" in flag.option)
        self.assertTrue(method.input_required)
        self.assertEqual(method.value_type, "string")
        self.assertIsNotNone(method.validate(""))
        self.assertIsNone(method.validate("general.base64"))

    def test_command_hints_describe_required_positionals(self):
        hints = positional_hints(sentinelcli.build_parser(), "ping ")
        host = next(item for item in hints if item.name == "host")
        self.assertTrue(host.required)
        self.assertEqual(host.value_type, "string")
        self.assertIsNotNone(host.validate(""))
        self.assertIsNone(host.validate("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()