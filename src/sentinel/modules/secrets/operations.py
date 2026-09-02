"""Secrets command implementations."""

from ...core.common import *
from ...core.common import _stdlib_secrets

@dataclass
class SecretFinding:
    file: str
    line: int
    pattern: str
    match: str
def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"
def iter_files(root: Path, include_hidden: bool, max_size: int) -> Iterable[Path]:
    for current_root, dirs, files in os.walk(root):
        if not include_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            files = [f for f in files if not f.startswith(".")]
        for name in files:
            path = Path(current_root) / name
            try:
                if path.stat().st_size <= max_size:
                    yield path
            except OSError:
                continue
def secrets_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        raise ToolkitError(f"Path does not exist: {root}")

    compiled = [(name, re.compile(pattern)) for name, pattern in SECRET_PATTERNS.items()]
    findings: list[SecretFinding] = []
    paths = [root] if root.is_file() else list(iter_files(root, args.hidden, args.max_size))
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    for name, pattern in compiled:
                        for match in pattern.finditer(line):
                            value = match.group(0).strip()
                            findings.append(
                                SecretFinding(str(path), line_number, name, value if args.reveal else mask_secret(value))
                            )
        except OSError:
            continue

    if args.json:
        print_json([finding.__dict__ for finding in findings])
    else:
        for finding in findings:
            print(f"{finding.file}:{finding.line}: {finding.pattern}: {finding.match}")
        print(f"{len(findings)} finding(s).")
    return 1 if findings and args.fail_on_findings else 0
def scan_secrets_path(path: str | Path, hidden: bool = False, max_size: int = 1024 * 1024, reveal: bool = False) -> list[dict[str, object]]:
    root = Path(path)
    if not root.exists():
        raise ToolkitError(f"Path does not exist: {root}")
    compiled = [(name, re.compile(pattern)) for name, pattern in SECRET_PATTERNS.items()]
    findings: list[dict[str, object]] = []
    paths = [root] if root.is_file() else list(iter_files(root, hidden, max_size))
    for item in paths:
        try:
            with item.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    for name, pattern in compiled:
                        for match in pattern.finditer(line):
                            value = match.group(0).strip()
                            findings.append(
                                {
                                    "file": str(item),
                                    "line": line_number,
                                    "pattern": name,
                                    "match": value if reveal else mask_secret(value),
                                }
                            )
        except OSError:
            continue
    return findings
class SecretsAPI:
    def scan(self, path: str | Path, hidden: bool = False, max_size: int = 1024 * 1024, reveal: bool = False) -> list[dict[str, object]]:
        return scan_secrets_path(path, hidden=hidden, max_size=max_size, reveal=reveal)
