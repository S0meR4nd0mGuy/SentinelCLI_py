"""Files command implementations."""

from ...core.common import *
from ...core.common import _stdlib_secrets

def file_hash(value: argparse.Namespace | str | Path, algorithm: str | None = None) -> int | str:
    if not isinstance(value, argparse.Namespace) and not hasattr(value, "file"):
        return hash_file_value(value, algorithm or "sha256")
    args = value
    selected_algorithm = getattr(args, "algorithm", algorithm or "sha256")
    algorithm = str(selected_algorithm).lower()
    if algorithm in CHECKSUM_METHODS:
        checksum_func = zlib.crc32 if algorithm == "crc32" else zlib.adler32
        checksum = 0
        with open(args.file, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                checksum = checksum_func(chunk, checksum)
        print(f"{checksum & 0xFFFFFFFF:08x}  {args.file}")
        return 0
    if algorithm not in hashlib.algorithms_available:
        raise ToolkitError(f"Unsupported hash algorithm: {selected_algorithm}")
    digest = hashlib.new(algorithm)
    with open(args.file, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    print(f"{digest.hexdigest()}  {args.file}")
    return 0
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    frequencies = [0] * 256
    for byte in data:
        frequencies[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in frequencies if count)
def entropy_cmd(args: argparse.Namespace) -> int:
    data = Path(args.file).read_bytes()
    value = entropy(data)
    print(f"{value:.4f} bits/byte")
    if value >= args.threshold:
        print("High entropy: file may be compressed, encrypted, or packed.")
    return 0
def detect_file_signature(data: bytes) -> str:
    for label, signature in FILE_SIGNATURES:
        if data.startswith(signature):
            return label
    return "unknown"
def find_embedded_indicators(data: bytes, limit: int) -> dict[str, list[str]]:
    text = data.decode("latin-1", errors="ignore")
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]{4,}", text)))[:limit]
    ipv4s = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    valid_ipv4s = []
    for candidate in ipv4s:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        valid_ipv4s.append(candidate)
        if len(valid_ipv4s) >= limit:
            break
    domains = sorted(
        set(
            match.lower()
            for match in re.findall(r"\b(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b", text)
            if not match.lower().startswith(("http.", "https."))
        )
    )[:limit]
    return {"urls": urls, "ipv4": valid_ipv4s, "domains": domains}
def file_inspect(value: argparse.Namespace | str | Path, hashes: str | Iterable[str] = "sha256", indicators: bool = False, scan_bytes: int = 1024 * 1024, indicator_limit: int = 20) -> int | dict[str, object]:
    if not isinstance(value, argparse.Namespace) and not hasattr(value, "file"):
        return inspect_file(value, hashes=hashes, indicators=indicators, scan_bytes=scan_bytes, indicator_limit=indicator_limit)
    args = value
    result = inspect_file(
        args.file,
        hashes=getattr(args, "hashes", hashes),
        indicators=getattr(args, "indicators", indicators),
        scan_bytes=getattr(args, "scan_bytes", scan_bytes),
        indicator_limit=getattr(args, "indicator_limit", indicator_limit),
    )
    if getattr(args, "json", False):
        print_json(result)
    else:
        print(f"{result['file']}")
        print(f"  size={result['size']} signature={result['signature']} mime={result['mime_guess'] or 'unknown'} entropy={result['entropy']}")
        for name, digest in result["hashes"].items():
            print(f"  {name}: {digest}")
        if getattr(args, "indicators", False):
            indicators = result["indicators"]
            for kind in ["urls", "ipv4", "domains"]:
                values = indicators.get(kind, [])
                print(f"  {kind}: {', '.join(values) if values else '-'}")
    return 0
def inspect_file(
    file: str | Path,
    hashes: str | Iterable[str] = "sha256",
    indicators: bool = False,
    scan_bytes: int = 1024 * 1024,
    indicator_limit: int = 20,
) -> dict[str, object]:
    path = Path(file)
    if not path.exists() or not path.is_file():
        raise ToolkitError(f"File not found: {file}")
    data = path.read_bytes()
    stat = path.stat()
    digest_map = {}
    hash_names = hashes.split(",") if isinstance(hashes, str) else list(hashes)
    for algorithm in hash_names:
        algorithm = algorithm.strip().lower()
        if not algorithm:
            continue
        if algorithm in CHECKSUM_METHODS:
            checksum = zlib.crc32(data) if algorithm == "crc32" else zlib.adler32(data)
            digest_map[algorithm] = f"{checksum & 0xFFFFFFFF:08x}"
        elif algorithm in hashlib.algorithms_available:
            digest_map[algorithm] = hashlib.new(algorithm, data).hexdigest()
        else:
            raise ToolkitError(f"Unsupported hash algorithm: {algorithm}")
    magic = detect_file_signature(data[:64])
    mime, encoding = mimetypes.guess_type(str(path))
    result = {
        "file": str(path),
        "size": stat.st_size,
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "extension": path.suffix.lower(),
        "mime_guess": mime,
        "encoding_guess": encoding,
        "signature": magic,
        "entropy": round(entropy(data), 4),
        "hashes": digest_map,
    }
    if indicators:
        result["indicators"] = find_embedded_indicators(data[:scan_bytes], indicator_limit)
    return result
def csv_from_findings(findings: list[dict[str, object]], output: str) -> None:
    with open(output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sorted(findings[0].keys()) if findings else [])
        if findings:
            writer.writeheader()
            writer.writerows(findings)
def hash_file_value(file: str | Path, algorithm: str = "sha256") -> str:
    name = algorithm.lower()
    if name in CHECKSUM_METHODS:
        checksum_func = zlib.crc32 if name == "crc32" else zlib.adler32
        checksum = 0
        with open(file, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                checksum = checksum_func(chunk, checksum)
        return f"{checksum & 0xFFFFFFFF:08x}"
    if name not in hashlib.algorithms_available:
        raise ToolkitError(f"Unsupported hash algorithm: {algorithm}")
    digest = hashlib.new(name)
    with open(file, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
class FileHashAPI:
    def hash(self, file: str | Path, algorithm: str = "sha256") -> str:
        return hash_file_value(file, algorithm)
class EntropyAPI:
    def calculate(self, data: bytes) -> float:
        return entropy(data)

    def file(self, file: str | Path) -> float:
        return entropy(Path(file).read_bytes())
class FileInspectAPI:
    def inspect(self, file: str | Path, hashes: str | Iterable[str] = "sha256", indicators: bool = False, scan_bytes: int = 1024 * 1024, indicator_limit: int = 20) -> dict[str, object]:
        return inspect_file(file, hashes=hashes, indicators=indicators, scan_bytes=scan_bytes, indicator_limit=indicator_limit)
class TimestampAPI:
    def utc(self) -> str:
        return datetime.now(timezone.utc).isoformat()
