from __future__ import annotations

"""Shared constants and support used by command modules."""

import argparse
import json
import os
import secrets as _stdlib_secrets
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass
import base64
import binascii
import csv
import hashlib
import hmac
import html
import ipaddress
import math
import mimetypes
import re
import string
import zlib
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
from pathlib import Path

VERSION = "1.0.0"

DEFAULT_COMMON_PORTS = [
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    2376,
    3000,
    3306,
    3389,
    5000,
    5432,
    5601,
    5900,
    5985,
    5986,
    6379,
    8000,
    8080,
    8443,
    9200,
    9300,
    11211,
    27017,
]

__version__ = VERSION

SECRET_PATTERNS = {
    "AWS Access Key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "AWS Secret Key": r"(?i)\baws(.{0,20})?(secret|private)?(.{0,20})?['\"][0-9a-z/+]{40}['\"]",
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b",
    "GitLab Token": r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
    "Slack Token": r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
    "Stripe Key": r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}\b",
    "Private Key Header": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "JWT": r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
    "Generic API Key Assignment": r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HTTP Strict Transport Security",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

SECURITY_HEADER_GUIDANCE = {
    "strict-transport-security": "Ask browsers to require HTTPS after the first visit.",
    "content-security-policy": "Limit script, frame, image, and connection sources to reduce XSS impact.",
    "x-content-type-options": "Use nosniff to stop MIME confusion attacks.",
    "x-frame-options": "Deny or restrict framing to reduce clickjacking risk.",
    "referrer-policy": "Avoid leaking sensitive paths or query values via the Referer header.",
    "permissions-policy": "Disable browser features the site does not intentionally use.",
}

SUSPICIOUS_URL_KEYWORDS = {
    "account",
    "admin",
    "bank",
    "billing",
    "confirm",
    "download",
    "invoice",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "apikey",
    "api_key",
    "auth",
    "code",
    "key",
    "otp",
    "pass",
    "password",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
}

FILE_SIGNATURES = [
    ("MZ executable", b"MZ"),
    ("ELF executable", b"\x7fELF"),
    ("PDF document", b"%PDF-"),
    ("ZIP/JAR/APK/Office archive", b"PK\x03\x04"),
    ("RAR archive", b"Rar!\x1a\x07"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
    ("Gzip archive", b"\x1f\x8b"),
    ("PNG image", b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", b"\xff\xd8\xff"),
    ("GIF image", b"GIF8"),
    ("SQLite database", b"SQLite format 3\x00"),
    ("Windows shortcut", b"L\x00\x00\x00\x01\x14\x02\x00"),
]

class ToolkitError(Exception):
    """Raised for expected CLI errors."""

def eprint(message: str) -> None:
    print(message, file=sys.stderr)

def supports_color(stream: object | None = None) -> bool:
    stream = stream or sys.stdout
    try:
        return bool(getattr(stream, "isatty", lambda: False)())
    except Exception:
        return False

def ansi(code: str, text: str, *, stream: object | None = None) -> str:
    if not supports_color(stream):
        return text
    return f"\033[{code}m{text}\033[0m"

def print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))

def read_text_arg(value: str | None, file_path: str | None) -> str:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8", errors="replace")
    if value is None:
        if sys.stdin.isatty():
            raise ToolkitError("Provide --text, --file, or pipe data on stdin.")
        return sys.stdin.read()
    return value

def write_or_print(data: str | bytes, output: str | None) -> None:
    if output:
        mode = "wb" if isinstance(data, bytes) else "w"
        kwargs = {} if isinstance(data, bytes) else {"encoding": "utf-8"}
        with open(output, mode, **kwargs) as handle:
            handle.write(data)
        return
    if isinstance(data, bytes):
        sys.stdout.buffer.write(data)
        if not data.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
    else:
        print(data)

GENERAL_METHODS = {
    "base64",
    "base64url",
    "base32",
    "base16",
    "hex",
    "ascii85",
    "base85",
    "url",
    "html",
    "binary",
    "octal",
    "decimal",
}

CLASSICAL_METHODS = {
    "caesar",
    "rot13",
    "rot47",
    "atbash",
    "vigenere",
    "beaufort",
    "affine",
    "railfence",
    "bacon",
    "reverse",
    "trithemius",
    "keyword",
    "autokey",
    "columnar",
    "scytale",
    "playfair",
    "polybius",
    "hill",
}

CLASSICAL_DICTIONARY_METHODS = {"vigenere", "beaufort", "keyword", "autokey", "playfair", "columnar"}

MODERN_METHODS = {
    "xor",
    "fernet",
    "aesgcm",
    "aes256gcm",
    "aes256cbc",
    "aes256ctrhmac",
    "aes256cbchmac",
    "chacha20poly1305",
}

ONEWAY_METHODS = {
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha512-224",
    "sha512-256",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "blake2b",
    "blake2s",
    "shake-128",
    "shake-256",
    "crc32",
    "adler32",
}

HASHLIB_ALIASES = {
    "sha512-224": "sha512_224",
    "sha512-256": "sha512_256",
    "sha3-224": "sha3_224",
    "sha3-256": "sha3_256",
    "sha3-384": "sha3_384",
    "sha3-512": "sha3_512",
    "shake-128": "shake_128",
    "shake-256": "shake_256",
}

CHECKSUM_METHODS = {"crc32", "adler32"}

METHOD_GROUPS = {
    "general": GENERAL_METHODS,
    "classical": CLASSICAL_METHODS,
    "modern": MODERN_METHODS,
    "oneway": ONEWAY_METHODS,
}

METHOD_DESCRIPTIONS = {
    "general.base64": "Transport-safe encoding for binary data, not encryption.",
    "general.base64url": "URL-safe Base64 encoding, common in tokens and JWTs.",
    "general.base32": "Case-insensitive transport encoding, often used in OTP secrets.",
    "general.base16": "Hex-style binary-to-text encoding.",
    "general.hex": "Compact binary-to-text encoding for bytes and hashes.",
    "general.ascii85": "Dense ASCII armoring used by some document formats.",
    "general.base85": "Git-style Base85 binary-to-text encoding.",
    "general.url": "Percent-encoding for URL/query-string data.",
    "general.html": "HTML entity escaping/unescaping.",
    "general.binary": "8-bit binary byte representation.",
    "general.octal": "Octal byte representation.",
    "general.decimal": "Decimal byte representation.",
    "classical.caesar": "Educational shift cipher; useful for CTFs and simple puzzles.",
    "classical.rot13": "Caesar shift 13; common reversible text obfuscation.",
    "classical.atbash": "Educational substitution cipher reversing the alphabet.",
    "classical.vigenere": "Educational polyalphabetic cipher using a word key.",
    "classical.beaufort": "Educational polyalphabetic cipher; self-reciprocal, so encrypt and decrypt use the same operation.",
    "classical.affine": "Educational monoalphabetic cipher using ax+b mod 26.",
    "classical.railfence": "Educational transposition cipher.",
    "classical.bacon": "Educational Bacon's cipher using A/B groups.",
    "classical.reverse": "Simple string reversal for obfuscation/puzzles.",
    "classical.rot47": "ASCII-95 rotation cipher covering printable symbols, not just letters.",
    "classical.trithemius": "Educational progressive-shift cipher (shift grows by 1 each letter); no key needed.",
    "classical.keyword": "Educational monoalphabetic substitution cipher whose alphabet is built from a keyword.",
    "classical.autokey": "Educational polyalphabetic cipher whose keystream is extended by the plaintext itself.",
    "classical.columnar": "Educational columnar transposition cipher; a word key sets the column read-out order.",
    "classical.scytale": "Educational transposition cipher modeled on the ancient Greek scytale; key is a column count.",
    "classical.playfair": "Educational digraph substitution cipher using a 5x5 keyed grid (I/J combined); letters only.",
    "classical.polybius": "Educational cipher mapping letters to row/column coordinates in a 5x5 grid (I/J combined).",
    "classical.hill": "Educational polygraphic cipher using 2x2 matrix arithmetic mod 26; key is four integers 'a,b,c,d'.",
    "modern.xor": "Keyed byte XOR for labs/CTFs; not suitable for real security by itself.",
    "modern.fernet": "Authenticated symmetric encryption from cryptography; good general-purpose local choice.",
    "modern.aesgcm": "AES-256-GCM authenticated encryption; alias: aes256gcm.",
    "modern.aes256gcm": "AES-256-GCM authenticated encryption (same as aesgcm); recommended default for real AES-256 use.",
    "modern.aes256cbc": "AES-256-CBC encryption with PKCS7 padding; no built-in authentication, so prefer aes256cbchmac unless legacy interop requires plain CBC.",
    "modern.aes256ctrhmac": "AES-256-CTR with HMAC-SHA256 encrypt-then-MAC authentication for interop when GCM is unavailable.",
    "modern.aes256cbchmac": "AES-256-CBC with PKCS7 padding and HMAC-SHA256 authentication for safer CBC-mode interop.",
    "modern.chacha20poly1305": "ChaCha20-Poly1305 authenticated encryption; good modern symmetric encryption.",
}

ONEWAY_DESCRIPTIONS = {
    "oneway.crc32": "Fast 32-bit checksum for accidental-corruption detection; not cryptographically secure and trivially forgeable.",
    "oneway.adler32": "Fast 32-bit checksum, weaker than CRC32 for short data; not cryptographically secure.",
}

BACON_ALPHABET = {chr(ord("a") + i): format(i, "05b").replace("0", "A").replace("1", "B") for i in range(26)}

BACON_REVERSE = {value: key for key, value in BACON_ALPHABET.items()}

GROUP_SWEEP_METHODS = {
    "general": sorted(GENERAL_METHODS),
    "classical": sorted(CLASSICAL_METHODS),
    "modern": [name for name in sorted(MODERN_METHODS) if name != "aes256gcm"],
}

AUTHENTICATED_MODERN_METHODS = {"fernet", "aesgcm", "aes256gcm", "aes256ctrhmac", "aes256cbchmac", "chacha20poly1305"}

COMMON_ENGLISH_WORDS = {
    "the", "and", "that", "have", "for", "not", "with", "you", "this", "but", "his", "from",
    "they", "say", "her", "she", "will", "one", "all", "would", "there", "their", "what", "about",
    "which", "when", "make", "can", "like", "time", "just", "know", "take", "people", "into",
    "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look",
    "only", "come", "its", "over", "think", "also", "back", "after", "use", "two", "how", "our",
    "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give", "day",
}

MODERN_DICTIONARY_METHODS = {
    "fernet",
    "aesgcm",
    "aes256gcm",
    "aes256cbc",
    "aes256ctrhmac",
    "aes256cbchmac",
    "chacha20poly1305",
}

def check_http_headers(url: str, timeout: float = 5.0) -> dict[str, object]:
    request_url = url if "://" in url else f"https://{url}"
    request = urllib.request.Request(request_url, method="HEAD", headers={"User-Agent": f"SentinelCliPy/{VERSION}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            status = response.status
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        status = exc.code
    except urllib.error.URLError as exc:
        raise ToolkitError(f"HTTP request failed: {exc}") from exc
    rows = []
    for key, label in SECURITY_HEADERS.items():
        value = headers.get(key)
        issues = []
        if value is None:
            issues.append("missing")
        elif key == "x-content-type-options" and value.lower() != "nosniff":
            issues.append("expected nosniff")
        elif key == "x-frame-options" and value.lower() not in {"deny", "sameorigin"}:
            issues.append("unusual frame policy")
        elif key == "strict-transport-security" and "max-age=" not in value.lower():
            issues.append("missing max-age")
        rows.append({"header": label, "present": key in headers, "value": value, "guidance": SECURITY_HEADER_GUIDANCE[key], "issues": issues})
    score = max(0, 100 - sum(12 if not row["present"] else 4 * len(row["issues"]) for row in rows))
    return {"url": request_url, "status": status, "score": score, "headers": rows}

def inspect_tls_host(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, object]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as sock:
            cert = sock.getpeercert()
            cipher = sock.cipher()
            version = sock.version()
    result: dict[str, object] = {
        "host": host,
        "port": port,
        "tls_version": version,
        "cipher": cipher,
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"],
    }
    warnings = []
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = parsedate_to_datetime(not_after)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            days_remaining = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
            result["expires_at"] = expires.isoformat()
            result["days_remaining"] = days_remaining
            if days_remaining < 0:
                warnings.append("certificate is expired")
            elif days_remaining <= 14:
                warnings.append("certificate expires within 14 days")
            elif days_remaining <= 30:
                warnings.append("certificate expires within 30 days")
        except (TypeError, ValueError, OverflowError):
            warnings.append("could not parse certificate expiry")
    if version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        warnings.append(f"deprecated protocol negotiated: {version}")
    result["warnings"] = warnings
    return result

def resolve_host(host: str) -> list[str]:
    return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})

