"""Cross-platform system inspection operations."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path

from ...core.common import ToolkitError, print_json


def system_info(args) -> int:
    result = {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "hostname": platform.node(),
        "cpu_count": os.cpu_count(),
    }
    if args.json:
        print_json(result)
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0


def disk_usage(args) -> int:
    path = Path(args.path).expanduser()
    if not path.exists():
        raise ToolkitError(f"Path does not exist: {path}")
    usage = shutil.disk_usage(path)
    result = {"path": str(path), "total": usage.total, "used": usage.used, "free": usage.free, "used_percent": round(usage.used / usage.total * 100, 2)}
    if args.json:
        print_json(result)
    else:
        print(f"{path}: {result['used_percent']}% used, {usage.free} bytes free")
    return 0


def process_list(args) -> int:
    rows = []
    if platform.system() == "Windows":
        import subprocess
        completed = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, check=False)
        import csv
        for row in csv.reader(completed.stdout.splitlines()):
            if len(row) >= 2 and (not args.filter or args.filter.lower() in row[0].lower()):
                rows.append({"name": row[0], "pid": row[1], "memory": row[4] if len(row) > 4 else ""})
    else:
        for item in Path("/proc").glob("[0-9]*"):
            name = (item / "comm").read_text(errors="replace").strip()
            if not args.filter or args.filter.lower() in name.lower():
                rows.append({"name": name, "pid": item.name})
    rows = rows[: args.limit]
    if args.json:
        print_json(rows)
    else:
        for row in rows:
            print(f"{row['pid']:>8}  {row['name']}  {row.get('memory', '')}")
    return 0
