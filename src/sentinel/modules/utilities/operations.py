"""Utilities command implementations."""

from ...core.common import *
from ...core.common import _stdlib_secrets

def timestamp_cmd(_: argparse.Namespace) -> int:
    print(datetime.now(timezone.utc).isoformat())
    return 0
def hash_text(text: str, algorithm: str = "oneway.sha256", length: int = 32) -> str:
    data = text.encode("utf-8")
    normalized = normalize_hash_algorithm(algorithm)
    if normalized == "crc32":
        return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
    if normalized == "adler32":
        return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")
    digest = hashlib.new(normalized, data)
    return digest.hexdigest(length) if normalized.startswith("shake_") else digest.hexdigest()
def hmac_digest(text: str, key: str, algorithm: str = "oneway.sha256") -> str:
    normalized = normalize_hash_algorithm(algorithm)
    if normalized in CHECKSUM_METHODS:
        raise ToolkitError("HMAC does not support non-cryptographic checksums (crc32/adler32).")
    if normalized.startswith("shake_"):
        raise ToolkitError("HMAC does not support SHAKE extendable-output hashes.")
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), normalized).hexdigest()
def generate_passwords(
    length: int = 24,
    count: int = 1,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> list[str]:
    alphabet = ""
    if lower:
        alphabet += string.ascii_lowercase
    if upper:
        alphabet += string.ascii_uppercase
    if digits:
        alphabet += string.digits
    if symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/|"
    if not alphabet:
        raise ToolkitError("Enable at least one character class.")
    return ["".join(_stdlib_secrets.choice(alphabet) for _ in range(length)) for _ in range(count)]
def audit_password(password: str) -> dict[str, object]:
    classes = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(c in string.punctuation for c in password),
    }
    score = min(100, len(password) * 4 + sum(10 for present in classes.values() if present))
    common = password.lower() in {
        "password",
        "password1",
        "admin",
        "qwerty",
        "letmein",
        "welcome",
        "changeme",
    }
    if common:
        score = min(score, 20)
    return {
        "length": len(password),
        "classes": classes,
        "common_password": common,
        "score": score,
        "verdict": "strong" if score >= 80 and not common else "moderate" if score >= 50 else "weak",
    }
class FilesAPI:
    def hash(self, file: str | Path, algorithm: str = "sha256") -> str:
        return file_hash_api.hash(file, algorithm)

    def inspect(self, file: str | Path, hashes: str | Iterable[str] = "sha256", indicators: bool = False, scan_bytes: int = 1024 * 1024, indicator_limit: int = 20) -> dict[str, object]:
        return file_inspect_api.inspect(file, hashes=hashes, indicators=indicators, scan_bytes=scan_bytes, indicator_limit=indicator_limit)

    def entropy(self, file: str | Path) -> float:
        return entropy_tools.file(file)
class UtilsAPI:
    def utc_timestamp(self) -> str:
        return timestamp.utc()

    def print_json(self, data: object) -> None:
        print_json(data)

    def decode_base64url_json(self, value: str) -> object:
        return decode_base64url_json(value)
