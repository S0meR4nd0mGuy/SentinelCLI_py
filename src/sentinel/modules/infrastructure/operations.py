"""Safe local infrastructure and configuration helpers."""

from __future__ import annotations

import configparser
import json
import os
from pathlib import Path

from ...core.common import ToolkitError, print_json


def config_validate(args) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        raise ToolkitError(f"Configuration file not found: {path}")
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="replace")
    result = {"file": str(path), "format": suffix or "text", "valid": True, "errors": []}
    try:
        if suffix == ".json":
            json.loads(text)
        elif suffix in {".ini", ".cfg", ".conf"}:
            configparser.ConfigParser().read_string(text)
        elif suffix in {".env", ".environment"}:
            for number, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if line and not line.startswith("#") and "=" not in line:
                    result["errors"].append(f"line {number}: expected KEY=VALUE")
        else:
            raise ToolkitError("Supported formats: .json, .ini, .cfg, .conf, and .env")
    except (json.JSONDecodeError, configparser.Error) as exc:
        result["valid"] = False
        result["errors"].append(str(exc))
    result["valid"] = not result["errors"]
    if args.json:
        print_json(result)
    else:
        print(f"{path}: {'valid' if result['valid'] else 'invalid'}")
        for error in result["errors"]:
            print(f"  error: {error}")
    return 0 if result["valid"] else 1


def cloud_context(args) -> int:
    result = {"aws_profile": os.environ.get("AWS_PROFILE", "default"), "aws_region": os.environ.get("AWS_DEFAULT_REGION", os.environ.get("AWS_REGION", "unset")), "kubeconfig": os.environ.get("KUBECONFIG", str(Path.home() / ".kube" / "config")), "azure_subscription": os.environ.get("AZURE_SUBSCRIPTION_ID", "unset")}
    if args.json:
        print_json(result)
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0
