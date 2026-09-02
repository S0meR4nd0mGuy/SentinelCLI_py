# SentinelCliPy Architecture

The migration is incremental. `sentinelcli.py` remains the public module and
continues to own the tested command implementations and argparse contract.
New operator-console services consume that contract instead of duplicating
command logic.

## Current foundation

- `sentinel/core/registry.py` discovers leaf commands from `build_parser()`.
- `sentinel/app.py` is the Textual-first workstation shell with module
   explorer, context panel, search, bottom tabs, keybindings, and execution.
- `sentinel/core/repl.py` is retained only as a compatibility API for callers
   and existing tests; it is not the default user interface.
- `sentinel/core/workspace.py` persists notes, targets, and recent commands.
- `sentinel/core/tasks.py` provides a thread-backed task manager for long scans.
- `sentinel/core/notifications.py` retains session notifications.
- `sentinel/ui/app.py` provides an optional Textual registry explorer.

Run the operator console with `sentinelcli repl`. The old guided shell remains
available with `sentinelcli repl --legacy` during migration and can be removed
once downstream integrations stop importing `SentinelRepl`.

## Next migration slices

1. Move one stable command family at a time into `sentinel/commands/`, keeping
   thin compatibility functions in `sentinelcli.py`.
2. Add structured result objects and Rich renderers around high-volume scans.
3. Connect task progress callbacks to Textual workers and the notification
   center.
4. Load third-party command plugins through entry points after the registry
   metadata contract is stable.