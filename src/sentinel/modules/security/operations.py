"""Local log and SSH key auditing operations."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ...core.common import ToolkitError, print_json


def log_scan(args) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        raise ToolkitError(f"Log file not found: {path}")
    pattern = re.compile(args.pattern, re.IGNORECASE)
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if pattern.search(line):
            rows.append({"line": number, "text": line})
    rows = rows[-args.limit:]
    if args.json:
        print_json({"file": str(path), "pattern": args.pattern, "matches": rows})
    else:
        print(f"{path}: {len(rows)} matching lines")
        for row in rows:
            print(f"{row['line']}: {row['text']}")
    return 0


def ssh_key_audit(args) -> int:
    root = Path(args.path).expanduser()
    if not root.exists():
        raise ToolkitError(f"Path does not exist: {root}")
    candidates = [root] if root.is_file() else sorted(root.glob("*.pub"))
    rows = []
    for key in candidates:
        text = key.read_text(encoding="utf-8", errors="replace").strip()
        parts = text.split()
        rows.append({"file": str(key), "type": parts[0] if parts else "unknown", "valid_format": len(parts) >= 2 and parts[0].startswith("ssh-"), "comment": " ".join(parts[2:]) if len(parts) > 2 else ""})
    if args.json:
        print_json(rows)
    else:
        for row in rows:
            print(f"{row['file']}: {row['type']} ({'valid format' if row['valid_format'] else 'review format'})")
    return 0


def ssh_key_generate(args) -> int:
    destination = Path(args.output).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = ["ssh-keygen", "-t", args.type, "-f", str(destination), "-N", "", "-C", args.comment]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise ToolkitError(completed.stderr.strip() or "ssh-keygen failed")
    print(f"Generated {destination} and {destination}.pub")
    return 0
