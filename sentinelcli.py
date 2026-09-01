#!/usr/bin/env python3
"""
SentinelCliPy: a standard-library cybersecurity CLI toolkit.

The toolkit is intended for authorized defensive work: local auditing, basic
network inventory, crypto/hash utilities, and lightweight HTTP/TLS inspection.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import cmd
import csv
import hashlib
import hmac
import html
import ipaddress
import json
import math
import mimetypes
import os
import re
import secrets as _stdlib_secrets
import shlex
import socket
import ssl
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
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

__all__ = [
    "ToolkitError",
    "VERSION",
    "__version__",
    "crypto",
    "dns",
    "entropy",
    "entropy_tools",
    "file_hash",
    "file_inspect",
    "headers",
    "ip",
    "jwt",
    "network",
    "files",
    "auth",
    "utils",
    "password",
    "ports",
    "secrets",
    "timestamp",
    "tls",
    "url",
    "build_parser",
    "main",
    "decode_jwt_token",
    "validate_jwt_result",
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


def caesar_transform(text: str, shift: int, decrypt: bool = False) -> str:
    if decrypt:
        shift = -shift
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)


def vigenere_transform(text: str, key: str, decrypt: bool = False) -> str:
    key_nums = [ord(c.lower()) - ord("a") for c in key if c.isalpha()]
    if not key_nums:
        raise ToolkitError("Vigenere requires an alphabetic key.")
    result = []
    index = 0
    for char in text:
        if char.isalpha():
            shift = key_nums[index % len(key_nums)]
            if decrypt:
                shift = -shift
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
            index += 1
        else:
            result.append(char)
    return "".join(result)


def beaufort_transform(text: str, key: str) -> str:
    key_nums = [ord(c.lower()) - ord("a") for c in key if c.isalpha()]
    if not key_nums:
        raise ToolkitError("Beaufort requires an alphabetic key.")
    result = []
    index = 0
    for char in text:
        if char.isalpha():
            k = key_nums[index % len(key_nums)]
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            result.append(chr((k - x) % 26 + base))
            index += 1
        else:
            result.append(char)
    return "".join(result)


def rot47_transform(text: str) -> str:
    result = []
    for char in text:
        code = ord(char)
        if 33 <= code <= 126:
            result.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            result.append(char)
    return "".join(result)


def trithemius_transform(text: str, decrypt: bool = False) -> str:
    result = []
    index = 0
    for char in text:
        if char.isalpha():
            shift = index % 26
            if decrypt:
                shift = -shift
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
            index += 1
        else:
            result.append(char)
    return "".join(result)


def keyword_cipher_alphabet(key: str) -> str:
    seen: list[str] = []
    for char in key.lower():
        if char.isalpha() and char not in seen:
            seen.append(char)
    for char in string.ascii_lowercase:
        if char not in seen:
            seen.append(char)
    return "".join(seen)


def keyword_transform(text: str, key: str, decrypt: bool = False) -> str:
    if not any(c.isalpha() for c in key):
        raise ToolkitError("Keyword cipher requires an alphabetic key.")
    cipher_alphabet = keyword_cipher_alphabet(key)
    plain_alphabet = string.ascii_lowercase
    mapping = dict(zip(cipher_alphabet, plain_alphabet)) if decrypt else dict(zip(plain_alphabet, cipher_alphabet))
    result = []
    for char in text:
        if char.isalpha():
            mapped = mapping.get(char.lower(), char.lower())
            result.append(mapped.upper() if char.isupper() else mapped)
        else:
            result.append(char)
    return "".join(result)


def autokey_transform(text: str, key: str, decrypt: bool = False) -> str:
    key_letters = [c.lower() for c in key if c.isalpha()]
    if not key_letters:
        raise ToolkitError("Autokey cipher requires an alphabetic key.")
    keystream = list(key_letters)
    ks_index = 0
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            k = ord(keystream[ks_index]) - ord("a")
            ks_index += 1
            x = ord(char) - base
            if decrypt:
                p = (x - k) % 26
                keystream.append(chr(p + ord("a")))
                result.append(chr(p + base))
            else:
                c = (x + k) % 26
                keystream.append(char.lower())
                result.append(chr(c + base))
        else:
            result.append(char)
    return "".join(result)


def columnar_key_order(key: str) -> list[int]:
    letters = [c for c in key if c.isalnum()]
    if not letters:
        raise ToolkitError("Columnar transposition requires a key with at least one letter or digit.")
    indexed = sorted(range(len(letters)), key=lambda i: (letters[i].lower(), i))
    order = [0] * len(letters)
    for rank, i in enumerate(indexed):
        order[i] = rank
    return order


def columnar_encrypt(text: str, key: str) -> str:
    order = columnar_key_order(key)
    num_cols = len(order)
    columns: list[list[str]] = [[] for _ in range(num_cols)]
    for i, char in enumerate(text):
        columns[i % num_cols].append(char)
    col_by_rank = sorted(range(num_cols), key=lambda c: order[c])
    return "".join("".join(columns[c]) for c in col_by_rank)


def columnar_decrypt(text: str, key: str) -> str:
    order = columnar_key_order(key)
    num_cols = len(order)
    n = len(text)
    base_len, remainder = divmod(n, num_cols)
    col_lengths = [base_len + (1 if c < remainder else 0) for c in range(num_cols)]
    col_by_rank = sorted(range(num_cols), key=lambda c: order[c])
    cursor = 0
    columns: list[list[str]] = [[] for _ in range(num_cols)]
    for c in col_by_rank:
        length = col_lengths[c]
        columns[c] = list(text[cursor:cursor + length])
        cursor += length
    result = []
    for i in range(n):
        col = i % num_cols
        result.append(columns[col].pop(0))
    return "".join(result)


def scytale_encrypt(text: str, columns: int) -> str:
    if columns < 2:
        raise ToolkitError("Scytale requires --columns of at least 2.")
    cols: list[list[str]] = [[] for _ in range(columns)]
    for i, char in enumerate(text):
        cols[i % columns].append(char)
    return "".join("".join(col) for col in cols)


def scytale_decrypt(text: str, columns: int) -> str:
    if columns < 2:
        raise ToolkitError("Scytale requires --columns of at least 2.")
    n = len(text)
    base_len, remainder = divmod(n, columns)
    col_lengths = [base_len + (1 if c < remainder else 0) for c in range(columns)]
    cursor = 0
    cols: list[list[str]] = []
    for length in col_lengths:
        cols.append(list(text[cursor:cursor + length]))
        cursor += length
    result = []
    for i in range(n):
        result.append(cols[i % columns].pop(0))
    return "".join(result)


def playfair_grid(key: str) -> list[str]:
    letters: list[str] = []
    seen: set[str] = set()
    for char in key.upper():
        if char == "J":
            char = "I"
        if char.isalpha() and char not in seen:
            seen.add(char)
            letters.append(char)
    for char in string.ascii_uppercase:
        if char == "J":
            continue
        if char not in seen:
            seen.add(char)
            letters.append(char)
    return letters


def playfair_prepare(text: str) -> list[tuple[str, str]]:
    letters = [("I" if c.upper() == "J" else c.upper()) for c in text if c.isalpha()]
    pairs = []
    i = 0
    while i < len(letters):
        a = letters[i]
        b = letters[i + 1] if i + 1 < len(letters) else "X"
        if a == b:
            pairs.append((a, "X"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def playfair_transform(text: str, key: str, decrypt: bool = False) -> str:
    if not any(c.isalpha() for c in key):
        raise ToolkitError("Playfair requires an alphabetic key.")
    grid = playfair_grid(key)
    pos = {char: (idx // 5, idx % 5) for idx, char in enumerate(grid)}
    pairs = playfair_prepare(text)
    if not pairs:
        raise ToolkitError("Playfair requires alphabetic input text (non-letters are ignored).")
    shift = -1 if decrypt else 1
    result = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result.append(grid[ra * 5 + (ca + shift) % 5])
            result.append(grid[rb * 5 + (cb + shift) % 5])
        elif ca == cb:
            result.append(grid[((ra + shift) % 5) * 5 + ca])
            result.append(grid[((rb + shift) % 5) * 5 + cb])
        else:
            result.append(grid[ra * 5 + cb])
            result.append(grid[rb * 5 + ca])
    return "".join(result)


def polybius_grid(key: str = "") -> list[str]:
    letters: list[str] = []
    seen: set[str] = set()
    for char in (key or "").upper():
        if char == "J":
            char = "I"
        if char.isalpha() and char not in seen:
            seen.add(char)
            letters.append(char)
    for char in string.ascii_uppercase:
        if char == "J":
            continue
        if char not in seen:
            seen.add(char)
            letters.append(char)
    return letters


def polybius_encrypt(text: str, key: str = "") -> str:
    grid = polybius_grid(key)
    pos = {char: (idx // 5 + 1, idx % 5 + 1) for idx, char in enumerate(grid)}
    tokens = []
    for char in text:
        upper = "I" if char.upper() == "J" else char.upper()
        if upper.isalpha():
            row, col = pos[upper]
            tokens.append(f"{row}{col}")
        elif char == " ":
            tokens.append("/")
        else:
            tokens.append(char)
    return " ".join(tokens)


def polybius_decrypt(text: str, key: str = "") -> str:
    grid = polybius_grid(key)
    lookup = {f"{idx // 5 + 1}{idx % 5 + 1}": char for idx, char in enumerate(grid)}
    result = []
    for token in text.split():
        if token in lookup:
            result.append(lookup[token])
        elif token == "/":
            result.append(" ")
        else:
            result.append(token)
    return "".join(result)


def parse_hill_key(key: str) -> tuple[int, int, int, int]:
    parts = [p for p in re.split(r"[,\s]+", key.strip()) if p]
    if len(parts) != 4:
        raise ToolkitError("Hill cipher key must be four integers, e.g. --key '3,3,2,5' (matrix [[a,b],[c,d]]).")
    try:
        a, b, c, d = (int(p) for p in parts)
    except ValueError as exc:
        raise ToolkitError("Hill cipher key must be four integers, e.g. --key '3,3,2,5'.") from exc
    det = (a * d - b * c) % 26
    if math.gcd(det, 26) != 1:
        raise ToolkitError(f"Hill cipher matrix is not invertible mod 26 (determinant={det}). Choose different values.")
    return a, b, c, d


def hill_transform(text: str, key: str, decrypt: bool = False) -> str:
    a, b, c, d = parse_hill_key(key)
    if decrypt:
        det = (a * d - b * c) % 26
        inv_det = pow(det, -1, 26)
        a, b, c, d = (d * inv_det) % 26, (-b * inv_det) % 26, (-c * inv_det) % 26, (a * inv_det) % 26
    letters = [char for char in text if char.isalpha()]
    if not letters:
        raise ToolkitError("Hill cipher requires alphabetic input text.")
    if len(letters) % 2 == 1:
        letters.append("X")
    encoded = []
    for i in range(0, len(letters), 2):
        x = ord(letters[i].upper()) - ord("A")
        y = ord(letters[i + 1].upper()) - ord("A")
        new_x = (a * x + b * y) % 26
        new_y = (c * x + d * y) % 26
        encoded.append(chr(new_x + ord("A")))
        encoded.append(chr(new_y + ord("A")))
    it = iter(encoded)
    result = []
    for char in text:
        if char.isalpha():
            new_char = next(it)
            result.append(new_char.lower() if char.islower() else new_char)
        else:
            result.append(char)
    result.append("".join(it))
    return "".join(result)


def xor_bytes(data: bytes, key: str) -> bytes:
    if not key:
        raise ToolkitError("XOR requires a non-empty key.")
    key_bytes = key.encode("utf-8")
    return bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(data))


def require_fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise ToolkitError(
            "Fernet requires the optional 'cryptography' package. "
            "Install it with: python -m pip install cryptography"
        ) from exc
    return Fernet


def canonical_method(method: str) -> str:
    return method.lower().replace("_", "-")


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
# Classical methods keyed by a word/passphrase, so a --wordlist dictionary attack
# via 'crypto brute-force' makes sense for them (unlike numeric-key methods such
# as affine, scytale, or hill, whose small key spaces are brute-forced directly).
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
# Non-cryptographic checksums exposed under the oneway group for convenience.
# They are fast integrity checks, not secure hashes: no collision resistance,
# not suitable for HMAC, and trivially forgeable.
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


def method_group_for(name: str) -> str | None:
    for group, methods in METHOD_GROUPS.items():
        if name in methods:
            return group
    return None


def validate_method_group(group: str, name: str, original: str) -> None:
    if group not in METHOD_GROUPS:
        raise ToolkitError(f"Unknown method group: {group}. Use one of: {', '.join(METHOD_GROUPS)}")
    if name in METHOD_GROUPS[group]:
        return
    expected = method_group_for(name)
    if expected:
        raise ToolkitError(f"Method '{original}' is not valid; '{name}' belongs to '{expected}.{name}'.")
    raise ToolkitError(f"Unknown {group} method: {name}. Run: crypto methods --group {group}")


def split_method(method: str, default_group: str | None = None) -> tuple[str, str]:
    normalized = canonical_method(method)
    if "." in normalized:
        group, name = normalized.split(".", 1)
    else:
        name = normalized
        group = method_group_for(name)
        if group is None:
            if default_group:
                group = default_group
            else:
                raise ToolkitError(f"Unknown method: {method}. Run: crypto methods")
    if group == "hash":
        group = "oneway"
    validate_method_group(group, name, method)
    return group, name


def normalize_hash_algorithm(algorithm: str) -> str:
    group, name = split_method(algorithm, default_group="oneway")
    if group != "oneway":
        raise ToolkitError("Hash algorithms must use the oneway group, e.g. oneway.sha256.")
    if name in CHECKSUM_METHODS:
        return name
    normalized = HASHLIB_ALIASES.get(name, name)
    if normalized not in hashlib.algorithms_available:
        raise ToolkitError(f"Unsupported hash algorithm: {algorithm}")
    return normalized


def require_hazmat():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    except ImportError as exc:
        raise ToolkitError(
            "AES-GCM and ChaCha20-Poly1305 require the optional 'cryptography' package. "
            "Install it with: python -m pip install cryptography"
        ) from exc
    return AESGCM, ChaCha20Poly1305


def require_cbc():
    try:
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ToolkitError(
            "AES-256-CBC requires the optional 'cryptography' package. "
            "Install it with: python -m pip install cryptography"
        ) from exc
    return Cipher, algorithms, modes, sym_padding


def derive_32_byte_key(key: str) -> bytes:
    if not key:
        raise ToolkitError("This method requires --key. Generate one with: crypto aes256-key")
    try:
        decoded = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        if len(decoded) in {16, 24, 32}:
            return decoded.ljust(32, b"\0")[:32]
    except (binascii.Error, ValueError):
        pass
    return hashlib.sha256(key.encode("utf-8")).digest()


def derive_key_material(key: str, label: bytes, length: int = 64) -> bytes:
    if not key:
        raise ToolkitError("This method requires --key. Generate one with: crypto aes256-key")
    seed = derive_32_byte_key(key)
    blocks = []
    counter = 1
    while sum(len(block) for block in blocks) < length:
        blocks.append(hmac.new(seed, label + counter.to_bytes(1, "big"), hashlib.sha512).digest())
        counter += 1
    return b"".join(blocks)[:length]


def mac_then_compare(mac_key: bytes, label: bytes, *chunks: bytes, tag: bytes) -> None:
    digest = hmac.new(mac_key, label, hashlib.sha256)
    for chunk in chunks:
        digest.update(len(chunk).to_bytes(8, "big"))
        digest.update(chunk)
    expected = digest.digest()
    if not hmac.compare_digest(expected, tag):
        raise ToolkitError("Authentication tag verification failed; wrong key or modified ciphertext.")


def calculate_etm_tag(mac_key: bytes, label: bytes, *chunks: bytes) -> bytes:
    digest = hmac.new(mac_key, label, hashlib.sha256)
    for chunk in chunks:
        digest.update(len(chunk).to_bytes(8, "big"))
        digest.update(chunk)
    return digest.digest()


def derive_password_key(passphrase: str, salt: bytes, kdf: str, length: int, rounds: int) -> bytes:
    if not passphrase:
        raise ToolkitError("KDF requires a non-empty passphrase.")
    if length < 1:
        raise ToolkitError("KDF output length must be at least 1 byte.")
    if kdf == "pbkdf2-sha256":
        if rounds < 1:
            raise ToolkitError("PBKDF2 iterations must be at least 1.")
        return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, rounds, dklen=length)
    if kdf == "pbkdf2-sha512":
        if rounds < 1:
            raise ToolkitError("PBKDF2 iterations must be at least 1.")
        return hashlib.pbkdf2_hmac("sha512", passphrase.encode("utf-8"), salt, rounds, dklen=length)
    if kdf == "scrypt":
        n = max(2, rounds)
        if n & (n - 1):
            raise ToolkitError("scrypt --rounds must be a power of two, e.g. 16384.")
        return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=8, p=1, dklen=length)
    raise ToolkitError(f"Unsupported KDF: {kdf}")


def atbash_transform(text: str) -> str:
    result = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr(ord("z") - (ord(char) - ord("a"))))
        elif "A" <= char <= "Z":
            result.append(chr(ord("Z") - (ord(char) - ord("A"))))
        else:
            result.append(char)
    return "".join(result)


def affine_transform(text: str, a: int, b: int, decrypt: bool = False) -> str:
    if math.gcd(a, 26) != 1:
        raise ToolkitError("Affine key A must be coprime with 26. Common choices: 5, 7, 11, 17.")
    inv_a = pow(a, -1, 26)
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            x = ord(char) - base
            y = (inv_a * (x - b)) % 26 if decrypt else (a * x + b) % 26
            result.append(chr(y + base))
        else:
            result.append(char)
    return "".join(result)


def railfence_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ToolkitError("Rail fence requires --rails of at least 2.")
    rows = [list() for _ in range(rails)]
    row, direction = 0, 1
    for char in text:
        rows[row].append(char)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    return "".join("".join(row_chars) for row_chars in rows)


def railfence_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        raise ToolkitError("Rail fence requires --rails of at least 2.")
    pattern = []
    row, direction = 0, 1
    for _ in text:
        pattern.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    counts = [pattern.count(i) for i in range(rails)]
    rails_data = []
    cursor = 0
    for count in counts:
        rails_data.append(list(text[cursor:cursor + count]))
        cursor += count
    positions = [0] * rails
    result = []
    for rail in pattern:
        result.append(rails_data[rail][positions[rail]])
        positions[rail] += 1
    return "".join(result)


BACON_ALPHABET = {chr(ord("a") + i): format(i, "05b").replace("0", "A").replace("1", "B") for i in range(26)}
BACON_REVERSE = {value: key for key, value in BACON_ALPHABET.items()}


def bacon_encrypt(text: str) -> str:
    return " ".join(BACON_ALPHABET[char.lower()] for char in text if char.isalpha())


def bacon_decrypt(text: str) -> str:
    groups = re.findall(r"[ABab]{5}", text)
    return "".join(BACON_REVERSE.get(group.upper(), "?") for group in groups)


def encode_data(data: bytes, method: str) -> str:
    method = split_method(method, default_group="general")[1]
    if method == "base64":
        return base64.b64encode(data).decode("ascii")
    if method == "base64url":
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    if method == "base32":
        return base64.b32encode(data).decode("ascii")
    if method in {"base16", "hex"}:
        return binascii.hexlify(data).decode("ascii")
    if method == "ascii85":
        return base64.a85encode(data).decode("ascii")
    if method == "base85":
        return base64.b85encode(data).decode("ascii")
    if method == "url":
        return urllib.parse.quote_from_bytes(data)
    if method == "html":
        return html.escape(data.decode("utf-8", errors="replace"), quote=True)
    if method == "binary":
        return " ".join(format(byte, "08b") for byte in data)
    if method == "octal":
        return " ".join(format(byte, "03o") for byte in data)
    if method == "decimal":
        return " ".join(str(byte) for byte in data)
    raise ToolkitError(f"Unsupported encoding: {method}")


def decode_data(text: str, method: str) -> bytes:
    method = split_method(method, default_group="general")[1]
    value = text.strip()
    try:
        if method == "base64":
            return base64.b64decode(value, validate=True)
        if method == "base64url":
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if method == "base32":
            return base64.b32decode(value, casefold=True)
        if method in {"base16", "hex"}:
            return binascii.unhexlify(re.sub(r"\s+", "", value))
        if method == "ascii85":
            return base64.a85decode(value)
        if method == "base85":
            return base64.b85decode(value)
        if method == "url":
            return urllib.parse.unquote_to_bytes(value)
        if method == "html":
            return html.unescape(value).encode("utf-8")
        if method == "binary":
            return bytes(int(part, 2) for part in re.findall(r"[01]{8}", value))
        if method == "octal":
            return bytes(int(part, 8) for part in re.findall(r"[0-7]{3}", value))
        if method == "decimal":
            return bytes(int(part, 10) for part in re.findall(r"\d{1,3}", value))
    except (binascii.Error, ValueError) as exc:
        raise ToolkitError(f"Invalid {method} input: {exc}") from exc
    raise ToolkitError(f"Unsupported encoding: {method}")


def modern_encrypt(text: str, method: str, key: str, output_encoding: str) -> str:
    if method == "xor":
        encrypted = xor_bytes(text.encode("utf-8"), key)
        return encode_data(encrypted, output_encoding)
    if method == "fernet":
        if not key:
            raise ToolkitError("Fernet requires --key. Generate one with: crypto fernet-key")
        Fernet = require_fernet()
        return Fernet(key.encode("ascii")).encrypt(text.encode("utf-8")).decode("ascii")
    if method in {"aesgcm", "aes256gcm", "chacha20poly1305"}:
        AESGCM, ChaCha20Poly1305 = require_hazmat()
        nonce = _stdlib_secrets.token_bytes(12)
        key_bytes = derive_32_byte_key(key)
        cipher = ChaCha20Poly1305(key_bytes) if method == "chacha20poly1305" else AESGCM(key_bytes)
        return encode_data(nonce + cipher.encrypt(nonce, text.encode("utf-8"), None), "general.base64url")
    if method == "aes256cbc":
        if not key:
            raise ToolkitError("AES-256-CBC requires --key. Generate one with: crypto aes256-key")
        Cipher, algorithms, modes, sym_padding = require_cbc()
        key_bytes = derive_32_byte_key(key)
        iv = _stdlib_secrets.token_bytes(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(text.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return encode_data(iv + ciphertext, "general.base64url")
    if method == "aes256ctrhmac":
        Cipher, algorithms, modes, _ = require_cbc()
        material = derive_key_material(key, b"sentinelclipy/aes256ctrhmac")
        enc_key, mac_key = material[:32], material[32:]
        nonce = _stdlib_secrets.token_bytes(16)
        encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
        ciphertext = encryptor.update(text.encode("utf-8")) + encryptor.finalize()
        tag = calculate_etm_tag(mac_key, b"aes256ctrhmac-v1", nonce, ciphertext)
        return encode_data(nonce + ciphertext + tag, "general.base64url")
    if method == "aes256cbchmac":
        Cipher, algorithms, modes, sym_padding = require_cbc()
        material = derive_key_material(key, b"sentinelclipy/aes256cbchmac")
        enc_key, mac_key = material[:32], material[32:]
        iv = _stdlib_secrets.token_bytes(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(text.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        tag = calculate_etm_tag(mac_key, b"aes256cbchmac-v1", iv, ciphertext)
        return encode_data(iv + ciphertext + tag, "general.base64url")
    raise ToolkitError(f"Unsupported modern method: {method}")


def modern_decrypt(text: str, method: str, key: str, input_encoding: str) -> str:
    if method == "xor":
        encrypted = decode_data(text, input_encoding)
        return xor_bytes(encrypted, key).decode("utf-8", errors="replace")
    if method == "fernet":
        if not key:
            raise ToolkitError("Fernet requires --key.")
        Fernet = require_fernet()
        return Fernet(key.encode("ascii")).decrypt(text.strip().encode("ascii")).decode("utf-8", errors="replace")
    if method in {"aesgcm", "aes256gcm", "chacha20poly1305"}:
        AESGCM, ChaCha20Poly1305 = require_hazmat()
        blob = decode_data(text, "general.base64url")
        if len(blob) <= 12:
            raise ToolkitError("Ciphertext is too short; expected nonce + ciphertext tag.")
        nonce, ciphertext = blob[:12], blob[12:]
        key_bytes = derive_32_byte_key(key)
        cipher = ChaCha20Poly1305(key_bytes) if method == "chacha20poly1305" else AESGCM(key_bytes)
        return cipher.decrypt(nonce, ciphertext, None).decode("utf-8", errors="replace")
    if method == "aes256cbc":
        if not key:
            raise ToolkitError("AES-256-CBC requires --key. Generate one with: crypto aes256-key")
        Cipher, algorithms, modes, sym_padding = require_cbc()
        blob = decode_data(text, "general.base64url")
        if len(blob) <= 16 or (len(blob) - 16) % 16 != 0:
            raise ToolkitError("Ciphertext is malformed; expected a 16-byte IV followed by whole AES blocks.")
        iv, ciphertext = blob[:16], blob[16:]
        key_bytes = derive_32_byte_key(key)
        decryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise ToolkitError(f"Invalid padding while decrypting; the key is likely wrong. ({exc})") from exc
        return plaintext.decode("utf-8", errors="replace")
    if method == "aes256ctrhmac":
        Cipher, algorithms, modes, _ = require_cbc()
        blob = decode_data(text, "general.base64url")
        if len(blob) <= 48:
            raise ToolkitError("Ciphertext is malformed; expected a 16-byte nonce, ciphertext, and 32-byte tag.")
        nonce, ciphertext, tag = blob[:16], blob[16:-32], blob[-32:]
        material = derive_key_material(key, b"sentinelclipy/aes256ctrhmac")
        enc_key, mac_key = material[:32], material[32:]
        mac_then_compare(mac_key, b"aes256ctrhmac-v1", nonce, ciphertext, tag=tag)
        decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode("utf-8", errors="replace")
    if method == "aes256cbchmac":
        Cipher, algorithms, modes, sym_padding = require_cbc()
        blob = decode_data(text, "general.base64url")
        if len(blob) < 64 or (len(blob) - 16 - 32) % 16 != 0:
            raise ToolkitError("Ciphertext is malformed; expected a 16-byte IV, CBC blocks, and 32-byte tag.")
        iv, ciphertext, tag = blob[:16], blob[16:-32], blob[-32:]
        material = derive_key_material(key, b"sentinelclipy/aes256cbchmac")
        enc_key, mac_key = material[:32], material[32:]
        mac_then_compare(mac_key, b"aes256cbchmac-v1", iv, ciphertext, tag=tag)
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise ToolkitError(f"Invalid padding while decrypting; the key is likely wrong. ({exc})") from exc
        return plaintext.decode("utf-8", errors="replace")
    raise ToolkitError(f"Unsupported modern method: {method}")


def decrypt_single(group: str, method: str, text: str, args: argparse.Namespace) -> str:
    """Decrypt with one specific group.method, using whichever of args.key/shift/
    affine_a/affine_b/rails/input_encoding that method needs. Raises ToolkitError
    (or lets underlying crypto exceptions through) on failure."""
    if group == "general":
        return decode_data(text, method).decode("utf-8", errors="replace")
    if group == "classical":
        if method == "caesar":
            return caesar_transform(text, args.shift, decrypt=True)
        if method == "rot13":
            return caesar_transform(text, 13)
        if method == "atbash":
            return atbash_transform(text)
        if method == "vigenere":
            if not args.key:
                raise ToolkitError("vigenere requires --key.")
            return vigenere_transform(text, args.key, decrypt=True)
        if method == "beaufort":
            if not args.key:
                raise ToolkitError("beaufort requires --key.")
            return beaufort_transform(text, args.key)
        if method == "affine":
            return affine_transform(text, args.affine_a, args.affine_b, decrypt=True)
        if method == "railfence":
            return railfence_decrypt(text, args.rails)
        if method == "bacon":
            return bacon_decrypt(text)
        if method == "reverse":
            return text[::-1]
        if method == "rot47":
            return rot47_transform(text)
        if method == "trithemius":
            return trithemius_transform(text, decrypt=True)
        if method == "keyword":
            if not args.key:
                raise ToolkitError("keyword requires --key.")
            return keyword_transform(text, args.key, decrypt=True)
        if method == "autokey":
            if not args.key:
                raise ToolkitError("autokey requires --key.")
            return autokey_transform(text, args.key, decrypt=True)
        if method == "columnar":
            if not args.key:
                raise ToolkitError("columnar requires --key.")
            return columnar_decrypt(text, args.key)
        if method == "scytale":
            return scytale_decrypt(text, args.columns)
        if method == "playfair":
            if not args.key:
                raise ToolkitError("playfair requires --key.")
            return playfair_transform(text, args.key, decrypt=True)
        if method == "polybius":
            return polybius_decrypt(text, args.key)
        if method == "hill":
            if not args.key:
                raise ToolkitError("hill requires --key, e.g. --key '3,3,2,5'.")
            return hill_transform(text, args.key, decrypt=True)
        raise ToolkitError(f"Unsupported classical method: {method}")
    if group == "modern":
        return modern_decrypt(text, method, args.key, args.input_encoding)
    raise ToolkitError("One-way methods cannot be decrypted. Use: crypto hash --algorithm oneway.sha256")


# Methods tried by a "group.*" decrypt sweep, one candidate per group. aes256gcm is
# skipped here since it is byte-for-byte the same algorithm as aesgcm (an alias),
# so trying both would just duplicate work.
GROUP_SWEEP_METHODS = {
    "general": sorted(GENERAL_METHODS),
    "classical": sorted(CLASSICAL_METHODS),
    "modern": [name for name in sorted(MODERN_METHODS) if name != "aes256gcm"],
}


AUTHENTICATED_MODERN_METHODS = {"fernet", "aesgcm", "aes256gcm", "aes256ctrhmac", "aes256cbchmac", "chacha20poly1305"}


def group_decrypt_attempts(text: str, group: str, args: argparse.Namespace) -> list[dict[str, object]]:
    if group == "oneway":
        raise ToolkitError("One-way methods cannot be decrypted. Use: crypto hash --algorithm oneway.sha256")
    if group not in GROUP_SWEEP_METHODS:
        raise ToolkitError(f"Unknown method group: {group}. Use one of: general, classical, modern")
    results: list[dict[str, object]] = []
    for name in GROUP_SWEEP_METHODS[group]:
        full_name = f"{group}.{name}"
        try:
            plaintext = decrypt_single(group, name, text, args)
        except Exception as exc:
            results.append({"method": full_name, "ok": False, "error": str(exc)})
            continue
        # A successful decrypt of an AEAD/Fernet ciphertext cryptographically proves
        # the method+key are correct, so it always outranks a merely English-looking
        # result from an unauthenticated method (e.g. xor happening to look plausible).
        if group == "modern" and name in AUTHENTICATED_MODERN_METHODS:
            score = 999.0
        else:
            score = english_score(plaintext)
        results.append({"method": full_name, "ok": True, "score": score, "text": plaintext})
    results.sort(key=lambda r: (not r["ok"], -r.get("score", 0.0)))
    for rank, result in enumerate(results, start=1):
        result["rank"] = rank
    return results


def crypto_encrypt(args: argparse.Namespace) -> int:
    text = read_text_arg(args.text, args.file)
    group, method = split_method(args.method)
    if group == "general":
        write_or_print(encode_data(text.encode("utf-8"), method), args.output)
    elif group == "classical":
        if method == "caesar":
            result = caesar_transform(text, args.shift)
        elif method == "rot13":
            result = caesar_transform(text, 13)
        elif method == "atbash":
            result = atbash_transform(text)
        elif method == "vigenere":
            result = vigenere_transform(text, args.key)
        elif method == "beaufort":
            result = beaufort_transform(text, args.key)
        elif method == "affine":
            result = affine_transform(text, args.affine_a, args.affine_b)
        elif method == "railfence":
            result = railfence_encrypt(text, args.rails)
        elif method == "bacon":
            result = bacon_encrypt(text)
        elif method == "reverse":
            result = text[::-1]
        elif method == "rot47":
            result = rot47_transform(text)
        elif method == "trithemius":
            result = trithemius_transform(text)
        elif method == "keyword":
            result = keyword_transform(text, args.key)
        elif method == "autokey":
            result = autokey_transform(text, args.key)
        elif method == "columnar":
            if not args.key:
                raise ToolkitError("columnar requires --key.")
            result = columnar_encrypt(text, args.key)
        elif method == "scytale":
            result = scytale_encrypt(text, args.columns)
        elif method == "playfair":
            result = playfair_transform(text, args.key)
        elif method == "polybius":
            result = polybius_encrypt(text, args.key)
        elif method == "hill":
            if not args.key:
                raise ToolkitError("hill requires --key, e.g. --key '3,3,2,5'.")
            result = hill_transform(text, args.key)
        else:
            raise ToolkitError(f"Unsupported classical method: {method}")
        write_or_print(result, args.output)
    elif group == "modern":
        write_or_print(modern_encrypt(text, method, args.key, args.output_encoding), args.output)
    else:
        raise ToolkitError("One-way methods cannot be decrypted. Use: crypto hash --algorithm oneway.sha256")
    return 0


def crypto_decrypt(args: argparse.Namespace) -> int:
    text = read_text_arg(args.text, args.file)
    method_raw = canonical_method(args.method)
    wildcard = re.fullmatch(r"(general|classical|modern|oneway)\.\*", method_raw)
    if wildcard:
        group = wildcard.group(1)
        results = group_decrypt_attempts(text, group, args)
        if args.output:
            write_or_print(json.dumps(results, indent=2, sort_keys=True), args.output)
        elif args.json:
            print_json(results)
        else:
            for result in results:
                if result["ok"]:
                    print(f"[ok]   {result['method']:<24} score={result['score']:.1f}")
                    print(result["text"])
                else:
                    print(f"[fail] {result['method']:<24} {result['error']}")
                print()
        return 0
    group, method = split_method(args.method)
    write_or_print(decrypt_single(group, method, text, args), args.output)
    return 0


def crypto_hash(args: argparse.Namespace) -> int:
    data = read_text_arg(args.text, args.file).encode("utf-8")
    algorithm = normalize_hash_algorithm(args.algorithm)
    if algorithm == "crc32":
        print(format(zlib.crc32(data) & 0xFFFFFFFF, "08x"))
        return 0
    if algorithm == "adler32":
        print(format(zlib.adler32(data) & 0xFFFFFFFF, "08x"))
        return 0
    digest = hashlib.new(algorithm, data)
    if algorithm.startswith("shake_"):
        print(digest.hexdigest(args.length))
    else:
        print(digest.hexdigest())
    return 0


def crypto_hmac(args: argparse.Namespace) -> int:
    data = read_text_arg(args.text, args.file).encode("utf-8")
    algorithm = normalize_hash_algorithm(args.algorithm)
    if algorithm in CHECKSUM_METHODS:
        raise ToolkitError("HMAC does not support non-cryptographic checksums (crc32/adler32).")
    if algorithm.startswith("shake_"):
        raise ToolkitError("HMAC does not support SHAKE extendable-output hashes.")
    print(hmac.new(args.key.encode("utf-8"), data, algorithm).hexdigest())
    return 0


def crypto_random(args: argparse.Namespace) -> int:
    token = _stdlib_secrets.token_urlsafe(args.bytes) if args.urlsafe else _stdlib_secrets.token_hex(args.bytes)
    print(token)
    return 0


def crypto_fernet_key(_: argparse.Namespace) -> int:
    Fernet = require_fernet()
    print(Fernet.generate_key().decode("ascii"))
    return 0


def crypto_aes256_key(_: argparse.Namespace) -> int:
    # 32 random bytes, base64url-encoded so it round-trips cleanly through
    # derive_32_byte_key() and is safe to paste on a command line or into a file.
    print(base64.urlsafe_b64encode(_stdlib_secrets.token_bytes(32)).decode("ascii"))
    return 0


def crypto_kdf(args: argparse.Namespace) -> int:
    salt = decode_data(args.salt, args.salt_encoding) if args.salt else _stdlib_secrets.token_bytes(args.salt_bytes)
    key = derive_password_key(args.passphrase, salt, args.kdf, args.length, args.rounds)
    result = {
        "kdf": args.kdf,
        "length": args.length,
        "rounds": args.rounds,
        "salt": encode_data(salt, "general.base64url"),
        "key": encode_data(key, args.output_encoding),
    }
    if args.json:
        print_json(result)
    else:
        print(result["key"])
        print(f"salt={result['salt']}")
    return 0


def crypto_compare(args: argparse.Namespace) -> int:
    left = read_text_arg(args.left, args.left_file).strip()
    right = read_text_arg(args.right, args.right_file).strip()
    equal = hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    if args.json:
        print_json({"equal": equal, "left_length": len(left), "right_length": len(right)})
    else:
        print("equal" if equal else "different")
    return 0


def crypto_methods(args: argparse.Namespace) -> int:
    rows = []
    for full_name, description in sorted(METHOD_DESCRIPTIONS.items()):
        group, name = full_name.split(".", 1)
        if args.group and args.group != group:
            continue
        rows.append({"method": full_name, "group": group, "name": name, "use": description})
    for method in sorted(ONEWAY_METHODS):
        full_name = f"oneway.{method}"
        if full_name in METHOD_DESCRIPTIONS:
            continue
        if args.group and args.group != "oneway":
            continue
        use = ONEWAY_DESCRIPTIONS.get(full_name, "One-way digest; integrity/fingerprints, not encryption.")
        rows.append({"method": full_name, "group": "oneway", "name": method, "use": use})
    if args.json:
        print_json(rows)
    else:
        width = max(len(row["method"]) for row in rows) if rows else 0
        for row in rows:
            print(f"{row['method']:<{width}}  {row['use']}")
    return 0


def identify_text(value: str) -> list[dict[str, object]]:
    text = value.strip()
    compact = re.sub(r"\s+", "", text)
    candidates: list[dict[str, object]] = []

    def add(method: str, confidence: str, reason: str) -> None:
        candidates.append({"method": method, "confidence": confidence, "reason": reason})

    if re.fullmatch(r"[a-fA-F0-9]+", compact) and len(compact) % 2 == 0:
        add("general.hex", "high", "only hex characters with an even byte length")
        if len(compact) == 8:
            add("oneway.crc32/adler32", "low", "8 hex characters matches a CRC32/Adler-32 checksum length")
        elif len(compact) == 32:
            add("oneway.md5", "medium", "32 hex characters matches an MD5 digest length")
        elif len(compact) == 40:
            add("oneway.sha1", "medium", "40 hex characters matches a SHA-1 digest length")
        elif len(compact) == 56:
            add("oneway.sha224", "medium", "56 hex characters matches a SHA-224 digest length")
        elif len(compact) == 64:
            add("oneway.sha256/sha3-256/blake2s", "medium", "64 hex characters matches several 256-bit digest lengths")
        elif len(compact) == 96:
            add("oneway.sha384/sha3-384", "medium", "96 hex characters matches 384-bit digest lengths")
        elif len(compact) == 128:
            add("oneway.sha512/sha3-512/blake2b", "medium", "128 hex characters matches 512-bit digest lengths")
    if re.fullmatch(r"[A-Z2-7]+=*", compact) and len(compact) >= 8:
        add("general.base32", "medium", "matches Base32 alphabet")
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and len(compact) % 4 == 0 and len(compact) >= 8:
        add("general.base64", "medium", "matches padded Base64 alphabet and length")
    if re.fullmatch(r"[A-Za-z0-9_-]+", compact) and len(compact) >= 16:
        add("general.base64url", "low", "matches URL-safe Base64 alphabet")
        if not re.fullmatch(r"gAAAA[A-Za-z0-9_-]+={0,2}", compact):
            try:
                blob_len = len(decode_data(compact, "general.base64url"))
            except ToolkitError:
                blob_len = -1
            if blob_len >= 28:
                add(
                    "modern.aes256gcm/aes256cbc/chacha20poly1305",
                    "low",
                    "decodes to a byte blob long enough to be a nonce/IV + authenticated or CBC ciphertext; "
                    "try 'crypto decrypt' with each modern.* method and a candidate key",
                )
    if re.search(r"%[0-9A-Fa-f]{2}", text):
        add("general.url", "high", "contains percent-encoded bytes")
    if re.search(r"&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z]+);", text):
        add("general.html", "high", "contains HTML entity sequences")
    if re.fullmatch(r"(?:[01]{8}\s*)+", text):
        add("general.binary", "high", "contains groups of 8 binary digits")
    if re.fullmatch(r"(?:[0-7]{3}\s*)+", text):
        add("general.octal", "medium", "contains groups of octal byte values")
    if re.fullmatch(r"(?:\d{1,3}\s*)+", text):
        add("general.decimal", "low", "contains decimal-looking byte values")
    if re.fullmatch(r"gAAAA[A-Za-z0-9_-]+={0,2}", compact):
        add("modern.fernet", "high", "Fernet tokens usually start with gAAAA")
    if re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", compact):
        add("JWT", "high", "three Base64URL sections with a JSON-looking header")
    if re.fullmatch(r"[ABab\s]+", text) and len(re.findall(r"[ABab]", text)) % 5 == 0 and len(text) >= 5:
        add("classical.bacon", "medium", "A/B alphabet in groups compatible with Bacon's cipher")
    if text.isalpha():
        add(
            "classical.caesar/rot13/atbash/vigenere/beaufort/keyword/autokey/trithemius",
            "low",
            "alphabetic text can be produced by many classical substitution ciphers",
        )
    if re.fullmatch(r"(?:[1-5]{2}\s*)+", compact) or re.fullmatch(r"(?:[1-5]{2}(?:\s+|/)?)+", text.strip()):
        add("classical.polybius", "medium", "space-separated digit pairs in the 1-5 range match a Polybius square")
    return candidates


def crypto_identify(args: argparse.Namespace) -> int:
    text = read_text_arg(args.text, args.file)
    candidates = identify_text(text)
    if args.json:
        print_json(candidates)
    else:
        if not candidates:
            print("No strong pattern match. It may be binary data, compressed/encrypted data, or an unsupported format.")
        for candidate in candidates:
            print(f"{candidate['confidence']:<6} {candidate['method']}: {candidate['reason']}")
    return 0


def decode_base64url_json(part: str) -> object:
    try:
        data = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        return json.loads(data.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolkitError(f"JWT section is not valid Base64URL JSON: {exc}") from exc


def jwt_timestamp(value: object) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def validate_jwt_result(result: dict[str, object]) -> dict[str, object]:
    required = {"header", "payload", "signature_present", "timeline", "warnings", "parts"}
    missing = sorted(key for key in required if key not in result)
    if missing:
        raise ToolkitError(f"JWT result is missing required fields: {', '.join(missing)}")
    if not isinstance(result["header"], dict):
        raise ToolkitError("JWT header must be a JSON object.")
    if not isinstance(result["payload"], dict):
        raise ToolkitError("JWT payload must be a JSON object.")
    if not isinstance(result["timeline"], dict):
        raise ToolkitError("JWT timeline must be a dictionary.")
    if not isinstance(result["warnings"], list):
        raise ToolkitError("JWT warnings must be a list.")
    parts = result["parts"]
    if not isinstance(parts, list) or len(parts) != 3 or not all(isinstance(part, str) for part in parts):
        raise ToolkitError("JWT parts must be a three-element list of strings.")
    return result


def decode_jwt_token(token: str) -> dict[str, object]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ToolkitError("JWT must contain exactly three dot-separated sections.")
    header = decode_base64url_json(parts[0])
    payload = decode_base64url_json(parts[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ToolkitError("JWT header and payload must decode to JSON objects.")
    now = datetime.now(timezone.utc).timestamp()
    warnings: list[str] = []
    alg = str(header.get("alg", "")).lower()
    if alg in {"", "none"}:
        warnings.append("JWT uses no signing algorithm; never trust it without external validation.")
    if not parts[2]:
        warnings.append("JWT signature section is empty.")
    if "exp" in payload:
        exp = payload["exp"]
        if isinstance(exp, (int, float)) and exp < now:
            warnings.append("JWT is expired.")
    else:
        warnings.append("JWT has no exp claim.")
    if "nbf" in payload and isinstance(payload["nbf"], (int, float)) and payload["nbf"] > now:
        warnings.append("JWT is not valid yet according to nbf.")
    timeline = {
        claim: jwt_timestamp(payload.get(claim))
        for claim in ("iat", "nbf", "exp")
        if claim in payload
    }
    result = {
        "header": header,
        "payload": payload,
        "signature_present": bool(parts[2]),
        "timeline": timeline,
        "warnings": warnings,
        "parts": parts,
    }
    return validate_jwt_result(result)


def jwt_decode(args: argparse.Namespace) -> int:
    token = read_text_arg(args.text, args.file).strip()
    result = validate_jwt_result(decode_jwt_token(token))
    output = getattr(args, "output", None)
    if output:
        write_or_print(json.dumps(result, indent=2, sort_keys=True), output)
        return 0
    header = result["header"]
    payload = result["payload"]
    timeline = result["timeline"]
    warnings = result["warnings"]
    parts = result["parts"]
    if args.json:
        print_json(result)
    else:
        print("Header:")
        print(json.dumps(header, indent=2, sort_keys=True))
        print("Payload:")
        print(json.dumps(payload, indent=2, sort_keys=True))
        if timeline:
            print("Timeline:")
            for key, value in timeline.items():
                print(f"  {key}: {value}")
        for warning in warnings:
            print(f"warning: {warning}")
        print("Signature present: yes" if parts[2] else "Signature present: no")
    return 0


COMMON_ENGLISH_WORDS = {
    "the", "and", "that", "have", "for", "not", "with", "you", "this", "but", "his", "from",
    "they", "say", "her", "she", "will", "one", "all", "would", "there", "their", "what", "about",
    "which", "when", "make", "can", "like", "time", "just", "know", "take", "people", "into",
    "year", "your", "good", "some", "could", "them", "see", "other", "than", "then", "now", "look",
    "only", "come", "its", "over", "think", "also", "back", "after", "use", "two", "how", "our",
    "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give", "day",
}


def english_score(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for char in text if char in string.printable and char not in "\x0b\x0c") / len(text)
    letters_spaces = sum(1 for char in text if char.isalpha() or char.isspace()) / len(text)
    vowels = sum(1 for char in text.lower() if char in "aeiou") / max(1, sum(1 for char in text if char.isalpha()))
    words = re.findall(r"[A-Za-z]{2,}", text.lower())
    word_hits = sum(1 for word in words if word in COMMON_ENGLISH_WORDS)
    word_score = min(1.0, word_hits / max(1, len(words)) * 4)
    space_score = min(1.0, text.count(" ") / max(1, len(text)) * 8)
    punctuation_penalty = sum(1 for char in text if ord(char) < 32 and char not in "\r\n\t") / len(text)
    return round((printable * 35) + (letters_spaces * 25) + (word_score * 25) + (space_score * 10) + (min(vowels, 0.45) * 10) - (punctuation_penalty * 60), 3)


def add_brute_candidate(candidates: list[dict[str, object]], method: str, key: str, plaintext: str, contains: str | None) -> None:
    if contains and contains.lower() not in plaintext.lower():
        return
    candidates.append({"method": method, "key": key, "score": english_score(plaintext), "text": plaintext})


MODERN_DICTIONARY_METHODS = {
    "fernet",
    "aesgcm",
    "aes256gcm",
    "aes256cbc",
    "aes256ctrhmac",
    "aes256cbchmac",
    "chacha20poly1305",
}


def brute_force_candidates(
    text: str,
    method: str,
    max_attempts: int,
    contains: str | None = None,
    max_rails: int = 12,
    wordlist: list[str] | None = None,
) -> list[dict[str, object]]:
    if method in {"all", "classical.all"}:
        group, name = "classical", "all"
    else:
        group, name = split_method(method)
    if group == "modern" and name != "xor" and not wordlist:
        raise ToolkitError(
            "Brute forcing modern encryption without a wordlist is not supported (the key space is too large). "
            "Provide --wordlist with candidate passphrases/keys to run a dictionary attack, "
            "or use known keys with: crypto decrypt --method modern.<name> --key <key>."
        )
    if group == "modern" and name not in MODERN_DICTIONARY_METHODS and name != "xor":
        raise ToolkitError(f"Brute force is not supported for method: {method}")
    if group == "oneway":
        raise ToolkitError("One-way hashes cannot be decrypted. This command does not crack hashes.")
    if max_attempts < 1:
        raise ToolkitError("--max-attempts must be at least 1.")

    candidates: list[dict[str, object]] = []
    attempts = 0

    def can_try() -> bool:
        return attempts < max_attempts

    def record(method_name: str, key: str, plaintext: str) -> None:
        add_brute_candidate(candidates, method_name, key, plaintext, contains)

    methods_to_try = [name]
    if method in {"all", "classical.all"}:
        methods_to_try = [
            "caesar", "rot13", "rot47", "atbash", "affine", "railfence", "scytale",
            "trithemius", "polybius", "reverse", "bacon",
        ]
        if wordlist:
            methods_to_try += sorted(CLASSICAL_DICTIONARY_METHODS)
    elif method in {"xor", "modern.xor"}:
        methods_to_try = ["xor"]

    for item in methods_to_try:
        if not can_try():
            break
        if item == "caesar":
            for shift in range(26):
                if not can_try():
                    break
                attempts += 1
                record("classical.caesar", f"shift={shift}", caesar_transform(text, shift, decrypt=True))
        elif item == "rot13":
            attempts += 1
            record("classical.rot13", "shift=13", caesar_transform(text, 13))
        elif item == "atbash":
            attempts += 1
            record("classical.atbash", "alphabet=reversed", atbash_transform(text))
        elif item == "affine":
            for a in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
                for b in range(26):
                    if not can_try():
                        break
                    attempts += 1
                    record("classical.affine", f"a={a},b={b}", affine_transform(text, a, b, decrypt=True))
                if not can_try():
                    break
        elif item == "railfence":
            for rails in range(2, max_rails + 1):
                if not can_try():
                    break
                attempts += 1
                try:
                    record("classical.railfence", f"rails={rails}", railfence_decrypt(text, rails))
                except ToolkitError:
                    pass
        elif item == "reverse":
            attempts += 1
            record("classical.reverse", "reverse", text[::-1])
        elif item == "bacon":
            attempts += 1
            record("classical.bacon", "A/B groups", bacon_decrypt(text))
        elif item == "rot47":
            attempts += 1
            record("classical.rot47", "rot47", rot47_transform(text))
        elif item == "trithemius":
            attempts += 1
            record("classical.trithemius", "progressive-shift", trithemius_transform(text, decrypt=True))
        elif item == "polybius":
            attempts += 1
            try:
                record("classical.polybius", "grid=standard", polybius_decrypt(text))
            except Exception:
                pass
        elif item == "scytale":
            for columns in range(2, max_rails + 1):
                if not can_try():
                    break
                attempts += 1
                try:
                    record("classical.scytale", f"columns={columns}", scytale_decrypt(text, columns))
                except ToolkitError:
                    pass
        elif item in CLASSICAL_DICTIONARY_METHODS:
            if not wordlist:
                raise ToolkitError(f"Brute forcing classical.{item} requires --wordlist with candidate keys/passphrases.")
            for candidate_key in wordlist:
                if not can_try():
                    break
                attempts += 1
                try:
                    if item == "vigenere":
                        plaintext = vigenere_transform(text, candidate_key, decrypt=True)
                    elif item == "beaufort":
                        plaintext = beaufort_transform(text, candidate_key)
                    elif item == "keyword":
                        plaintext = keyword_transform(text, candidate_key, decrypt=True)
                    elif item == "autokey":
                        plaintext = autokey_transform(text, candidate_key, decrypt=True)
                    elif item == "playfair":
                        plaintext = playfair_transform(text, candidate_key, decrypt=True)
                    else:  # columnar
                        plaintext = columnar_decrypt(text, candidate_key)
                except ToolkitError:
                    continue
                record(f"classical.{item}", f"key={candidate_key}", plaintext)
        elif item == "xor":
            raw_inputs: list[bytes] = []
            try:
                raw_inputs.append(decode_data(text, "general.base64"))
            except ToolkitError:
                pass
            try:
                raw_inputs.append(decode_data(text, "general.hex"))
            except ToolkitError:
                pass
            raw_inputs.append(text.encode("utf-8"))
            seen = set()
            for raw in raw_inputs:
                marker = raw[:32]
                if marker in seen:
                    continue
                seen.add(marker)
                for key in range(256):
                    if not can_try():
                        break
                    attempts += 1
                    plaintext = bytes(byte ^ key for byte in raw).decode("utf-8", errors="replace")
                    record("modern.xor", f"single-byte=0x{key:02x}", plaintext)
                if wordlist and can_try():
                    for candidate_key in wordlist:
                        if not can_try():
                            break
                        attempts += 1
                        plaintext = xor_bytes(raw, candidate_key).decode("utf-8", errors="replace")
                        record("modern.xor", f"key={candidate_key}", plaintext)
                if not can_try():
                    break
        elif item in MODERN_DICTIONARY_METHODS:
            if not wordlist:
                raise ToolkitError(f"Brute forcing modern.{item} requires --wordlist with candidate keys/passphrases.")
            authenticated = item != "aes256cbc"
            for candidate_key in wordlist:
                if not can_try():
                    break
                attempts += 1
                try:
                    plaintext = modern_decrypt(text, item, candidate_key, "general.base64url")
                except Exception:
                    continue
                if contains and contains.lower() not in plaintext.lower():
                    continue
                # A successful authenticated decrypt (fernet/AEAD) cryptographically
                # proves the key is correct, so it always ranks first. AES-256-CBC has
                # no built-in authentication, so we fall back to the English-likeness
                # heuristic since a wrong key can still "succeed" with valid padding.
                score = 999.0 if authenticated else english_score(plaintext)
                candidates.append({"method": f"modern.{item}", "key": f"key={candidate_key}", "score": score, "text": plaintext})
        else:
            raise ToolkitError(f"Brute force is not supported for method: {method}")

    candidates.sort(key=lambda candidate: candidate["score"], reverse=True)
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank
    return candidates


def load_wordlist(path: str) -> list[str]:
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        raise ToolkitError(f"Wordlist file not found: {path}")
    words = [
        line.strip()
        for line in wordlist_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    if not words:
        raise ToolkitError(f"Wordlist file has no usable entries: {path}")
    return words


def crypto_bruteforce(args: argparse.Namespace) -> int:
    text = read_text_arg(args.text, args.file)
    method = canonical_method(args.method)
    wordlist = load_wordlist(args.wordlist) if args.wordlist else None
    candidates = brute_force_candidates(
        text,
        method,
        args.max_attempts,
        contains=args.contains,
        max_rails=args.max_rails,
        wordlist=wordlist,
    )
    filtered = [candidate for candidate in candidates if candidate["score"] >= args.min_score]
    shown = filtered[: args.top]
    if args.json:
        print_json(shown)
    else:
        if not shown:
            print("No candidates met the filters.")
        for candidate in shown:
            print(f"#{candidate['rank']} score={candidate['score']} {candidate['method']} {candidate['key']}")
            print(candidate["text"])
            print()
    return 0

def parse_ports(port_expr: str) -> list[int]:
    if port_expr == "common":
        return DEFAULT_COMMON_PORTS[:]
    ports: set[int] = set()
    for part in port_expr.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ToolkitError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ToolkitError(f"Invalid port(s): {invalid}")
    return sorted(ports)


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: str
    service: str | None = None
    banner: str | None = None


def scan_one_port(host: str, port: int, timeout: float, grab_banner: bool) -> PortResult:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            service = None
            try:
                service = socket.getservbyport(port)
            except OSError:
                pass
            banner = None
            if grab_banner:
                sock.settimeout(timeout)
                try:
                    sock.sendall(b"\r\n")
                    banner = sock.recv(128).decode("utf-8", errors="replace").strip()
                except OSError:
                    banner = None
            return PortResult(host, port, "open", service, banner)
    except (OSError, socket.timeout):
        return PortResult(host, port, "closed")


def port_scan(args: argparse.Namespace) -> int:
    ports = parse_ports(args.ports)
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(scan_one_port, args.host, port, args.timeout, args.banner) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if args.show_closed or result.state == "open":
                results.append(result)

    results.sort(key=lambda item: item.port)
    if args.json:
        print_json([result.__dict__ for result in results])
        return 0

    for result in results:
        service = f" ({result.service})" if result.service else ""
        banner = f" - {result.banner}" if result.banner else ""
        print(f"{result.host}:{result.port} {result.state}{service}{banner}")
    if not results:
        print("No open ports found.")
    return 0


@dataclass(frozen=True)
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


def password_generate(args: argparse.Namespace) -> int:
    alphabet = ""
    if args.lower:
        alphabet += string.ascii_lowercase
    if args.upper:
        alphabet += string.ascii_uppercase
    if args.digits:
        alphabet += string.digits
    if args.symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/|"
    if not alphabet:
        raise ToolkitError("Enable at least one character class.")
    for _ in range(args.count):
        print("".join(_stdlib_secrets.choice(alphabet) for _ in range(args.length)))
    return 0


def password_audit(args: argparse.Namespace) -> int:
    password = args.password if args.password is not None else read_text_arg(None, None).strip()
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
    result = {
        "length": len(password),
        "classes": classes,
        "common_password": common,
        "score": score,
        "verdict": "strong" if score >= 80 and not common else "moderate" if score >= 50 else "weak",
    }
    print_json(result) if args.json else print(
        f"{result['verdict']} ({score}/100), length={len(password)}, classes={sum(classes.values())}/4"
    )
    return 0


def http_headers(args: argparse.Namespace) -> int:
    url = args.url if "://" in args.url else f"https://{args.url}"
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": f"SentinelCliPy/{VERSION}"})
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
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
        rows.append(
            {
                "header": label,
                "present": key in headers,
                "value": value,
                "guidance": SECURITY_HEADER_GUIDANCE[key],
                "issues": issues,
            }
        )
    score = max(0, 100 - sum(12 if not row["present"] else 4 * len(row["issues"]) for row in rows))
    result = {"url": url, "status": status, "score": score, "headers": rows}
    if args.json:
        print_json(result)
    else:
        print(f"{url} -> HTTP {status} security-header score={score}/100")
        for row in rows:
            state = "present" if row["present"] else "missing"
            value = f": {row['value']}" if row["value"] else ""
            issue = f" ({', '.join(row['issues'])})" if row["issues"] else ""
            print(f"{state:7} {row['header']}{value}{issue}")
    return 0


def tls_info(args: argparse.Namespace) -> int:
    context = ssl.create_default_context()
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=args.host) as sock:
            cert = sock.getpeercert()
            cipher = sock.cipher()
            version = sock.version()
    result = {
        "host": args.host,
        "port": args.port,
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
    print_json(result) if args.json else print(
        "\n".join(
            [
                f"{args.host}:{args.port}",
                f"TLS: {version}",
                f"Cipher: {cipher}",
                f"Subject: {result['subject']}",
                f"Issuer: {result['issuer']}",
                f"Valid: {result['not_before']} -> {result['not_after']}",
                f"Days remaining: {result.get('days_remaining', 'unknown')}",
                f"SANs: {', '.join(result['subject_alt_names'])}",
                *(f"warning: {warning}" for warning in warnings),
            ]
        )
    )
    return 0


def dns_lookup(args: argparse.Namespace) -> int:
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(args.host, None)})
    if args.json:
        print_json({"host": args.host, "addresses": addresses})
    else:
        for address in addresses:
            print(address)
    return 0


def hostname_to_ascii(hostname: str) -> str:
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def analyze_url_value(value: str) -> dict[str, object]:
    raw = value.strip()
    parsed = urllib.parse.urlsplit(raw if "://" in raw else f"http://{raw}")
    hostname = parsed.hostname or ""
    ascii_host = hostname_to_ascii(hostname) if hostname else ""
    decoded_path = urllib.parse.unquote(parsed.path)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    warnings = []
    if parsed.scheme not in {"http", "https"}:
        warnings.append(f"unusual scheme: {parsed.scheme or '<none>'}")
    if parsed.scheme == "http":
        warnings.append("plain HTTP URL")
    if parsed.username or parsed.password:
        warnings.append("URL contains embedded credentials")
    if "@" in parsed.netloc:
        warnings.append("netloc contains @; verify where the hostname actually starts")
    if hostname and ascii_host != hostname:
        warnings.append("internationalized domain name/punycode involved")
    if hostname and any(ord(char) > 127 for char in hostname):
        warnings.append("hostname contains non-ASCII characters")
    if hostname and "-" * 4 in hostname:
        warnings.append("hostname contains a long hyphen run")
    if hostname and hostname.count(".") >= 4:
        warnings.append("many subdomain levels")
    host_ip = None
    if hostname:
        try:
            host_ip = ipaddress.ip_address(hostname.strip("[]"))
        except ValueError:
            host_ip = None
    if host_ip:
        warnings.append("hostname is an IP address")
        if host_ip.is_private or host_ip.is_loopback or host_ip.is_link_local:
            warnings.append("URL targets a private, loopback, or link-local address")
    sensitive_params = sorted({key for key, _ in query_pairs if key.lower() in SENSITIVE_QUERY_KEYS})
    if sensitive_params:
        warnings.append(f"sensitive-looking query parameter(s): {', '.join(sensitive_params)}")
    lower_text = f"{hostname} {decoded_path}".lower()
    keywords = sorted(word for word in SUSPICIOUS_URL_KEYWORDS if word in lower_text)
    if keywords:
        warnings.append(f"suspicious keyword(s): {', '.join(keywords[:8])}")
    if "%" in parsed.path and decoded_path != parsed.path:
        warnings.append("path contains percent-encoding")
    if re.search(r"(?:\.\.|%2e%2e)", raw, re.IGNORECASE):
        warnings.append("path traversal marker present")
    path_entropy = entropy(decoded_path.encode("utf-8", errors="replace")) if decoded_path else 0.0
    if path_entropy >= 4.5 and len(decoded_path) >= 24:
        warnings.append("high-entropy path segment")
    return {
        "input": value,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "hostname_ascii": ascii_host,
        "port": parsed.port,
        "path": parsed.path,
        "decoded_path": decoded_path,
        "query_parameter_count": len(query_pairs),
        "sensitive_query_parameters": sensitive_params,
        "path_entropy": round(path_entropy, 4),
        "warnings": warnings,
    }


def url_analyze(args: argparse.Namespace) -> int:
    text = read_text_arg(args.text, args.file)
    urls = [line.strip() for line in text.splitlines() if line.strip()] if args.lines else [text.strip()]
    results = [analyze_url_value(url) for url in urls if url]
    output = getattr(args, "output", None)
    if output:
        payload = results if args.lines else (results[0] if results else {})
        write_or_print(json.dumps(payload, indent=2, sort_keys=True), output)
        return 0
    if args.json:
        print_json(results if args.lines else (results[0] if results else {}))
    else:
        for result in results:
            print(f"{result['input']}")
            print(f"  host={result['hostname']} ascii={result['hostname_ascii']} scheme={result['scheme']} port={result['port']}")
            print(f"  path_entropy={result['path_entropy']} query_params={result['query_parameter_count']}")
            if result["warnings"]:
                for warning in result["warnings"]:
                    print(f"  warning: {warning}")
            else:
                print("  no local heuristic warnings")
    return 0


def ip_info(args: argparse.Namespace) -> int:
    result = inspect_ip_address(args.address)
    if args.json:
        print_json(result)
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0


def inspect_ip_address(value: str) -> dict[str, object]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ToolkitError(f"Invalid IP address: {value}") from exc
    return {
        "address": str(address),
        "version": address.version,
        "compressed": address.compressed,
        "exploded": address.exploded,
        "reverse_pointer": address.reverse_pointer,
        "is_private": address.is_private,
        "is_global": address.is_global,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_reserved": address.is_reserved,
        "is_unspecified": address.is_unspecified,
    }


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


class CryptoAPI:
    def encode(self, data: str | bytes, method: str, key: str = "", **options: object) -> str:
        if isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = data
        group, name = split_method(method)
        if group == "general":
            return encode_data(payload, name)
        if group in {"modern", "classical"}:
            return self.encrypt(data if isinstance(data, str) else data.decode("utf-8", errors="strict"), method, key, **options)
        raise ToolkitError("Only general and reversible crypto methods support encode().")

    def decode(self, text: str, method: str, key: str = "", **options: object) -> str | bytes:
        group, name = split_method(method)
        if group == "general":
            value = decode_data(text, name)
            if isinstance(value, bytes):
                try:
                    return value.decode("utf-8")
                except UnicodeDecodeError:
                    return value.decode("latin-1")
            return str(value)
        return self.decrypt(text, method, key, **options)

    def encrypt(self, text: str, method: str, key: str = "", **options: object) -> str:
        group, name = split_method(method)
        if group == "general":
            return encode_data(text.encode("utf-8"), name)
        if group == "modern":
            return modern_encrypt(text, name, key, str(options.get("output_encoding", "base64")))
        if group != "classical":
            raise ToolkitError("One-way methods cannot be encrypted. Use crypto.hash(...).")
        if name == "caesar":
            return caesar_transform(text, int(options.get("shift", 3)))
        if name == "rot13":
            return caesar_transform(text, 13)
        if name == "atbash":
            return atbash_transform(text)
        if name == "vigenere":
            return vigenere_transform(text, key)
        if name == "beaufort":
            return beaufort_transform(text, key)
        if name == "affine":
            return affine_transform(text, int(options.get("affine_a", 5)), int(options.get("affine_b", 8)))
        if name == "railfence":
            return railfence_encrypt(text, int(options.get("rails", 3)))
        if name == "bacon":
            return bacon_encrypt(text)
        if name == "reverse":
            return text[::-1]
        if name == "rot47":
            return rot47_transform(text)
        if name == "trithemius":
            return trithemius_transform(text)
        if name == "keyword":
            return keyword_transform(text, key)
        if name == "autokey":
            return autokey_transform(text, key)
        if name == "columnar":
            return columnar_encrypt(text, key)
        if name == "scytale":
            return scytale_encrypt(text, int(options.get("columns", 5)))
        if name == "playfair":
            return playfair_transform(text, key)
        if name == "polybius":
            return polybius_encrypt(text, key)
        if name == "hill":
            return hill_transform(text, key)
        raise ToolkitError(f"Unsupported classical method: {name}")

    def decrypt(self, text: str, method: str, key: str = "", **options: object) -> str | list[dict[str, object]]:
        method_raw = canonical_method(method)
        wildcard = re.fullmatch(r"(general|classical|modern|oneway)\.\*", method_raw)
        namespace = argparse.Namespace(
            key=key,
            shift=int(options.get("shift", 3)),
            affine_a=int(options.get("affine_a", 5)),
            affine_b=int(options.get("affine_b", 8)),
            rails=int(options.get("rails", 3)),
            columns=int(options.get("columns", 5)),
            input_encoding=str(options.get("input_encoding", "base64")),
        )
        if wildcard:
            return group_decrypt_attempts(text, wildcard.group(1), namespace)
        group, name = split_method(method)
        return decrypt_single(group, name, text, namespace)

    def hash(self, text: str, algorithm: str = "oneway.sha256", length: int = 32) -> str:
        return hash_text(text, algorithm, length)

    def hmac(self, text: str, key: str, algorithm: str = "oneway.sha256") -> str:
        return hmac_digest(text, key, algorithm)

    def random(self, bytes: int = 32, urlsafe: bool = False) -> str:
        return _stdlib_secrets.token_urlsafe(bytes) if urlsafe else _stdlib_secrets.token_hex(bytes)

    def fernet_key(self) -> str:
        Fernet = require_fernet()
        return Fernet.generate_key().decode("ascii")

    def aes256_key(self) -> str:
        return base64.urlsafe_b64encode(_stdlib_secrets.token_bytes(32)).decode("ascii")

    def kdf(
        self,
        passphrase: str,
        salt: str | bytes | None = None,
        kdf: str = "pbkdf2-sha256",
        length: int = 32,
        rounds: int = 210000,
        salt_encoding: str = "base64url",
        output_encoding: str = "base64url",
        salt_bytes: int = 16,
    ) -> dict[str, object]:
        salt_bytes_value = salt if isinstance(salt, bytes) else decode_data(salt, salt_encoding) if salt else _stdlib_secrets.token_bytes(salt_bytes)
        key = derive_password_key(passphrase, salt_bytes_value, kdf, length, rounds)
        return {"kdf": kdf, "length": length, "rounds": rounds, "salt": encode_data(salt_bytes_value, "general.base64url"), "key": encode_data(key, output_encoding)}

    def compare(self, left: str, right: str) -> bool:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))

    def methods(self, group: str | None = None) -> list[dict[str, str]]:
        rows = []
        for full_name, description in sorted(METHOD_DESCRIPTIONS.items()):
            item_group, name = full_name.split(".", 1)
            if group and group != item_group:
                continue
            rows.append({"method": full_name, "group": item_group, "name": name, "use": description})
        for method in sorted(ONEWAY_METHODS):
            full_name = f"oneway.{method}"
            if full_name in METHOD_DESCRIPTIONS or (group and group != "oneway"):
                continue
            rows.append({"method": full_name, "group": "oneway", "name": method, "use": ONEWAY_DESCRIPTIONS.get(full_name, "One-way digest; integrity/fingerprints, not encryption.")})
        return rows

    def identify(self, text: str) -> list[dict[str, object]]:
        return identify_text(text)

    def brute_force(self, text: str, method: str = "all", max_attempts: int = 200, contains: str | None = None, max_rails: int = 12, wordlist: list[str] | None = None) -> list[dict[str, object]]:
        return brute_force_candidates(text, canonical_method(method), max_attempts, contains=contains, max_rails=max_rails, wordlist=wordlist)


class PortsAPI:
    def scan(self, host: str, ports: str = "common", timeout: float = 0.5, workers: int = 100, banner: bool = False, show_closed: bool = False) -> list[dict[str, object]]:
        selected_ports = parse_ports(ports)
        results: list[PortResult] = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(scan_one_port, host, port, timeout, banner) for port in selected_ports]
            for future in as_completed(futures):
                result = future.result()
                if show_closed or result.state == "open":
                    results.append(result)
        return [result.__dict__ for result in sorted(results, key=lambda item: item.port)]


class SecretsAPI:
    def scan(self, path: str | Path, hidden: bool = False, max_size: int = 1024 * 1024, reveal: bool = False) -> list[dict[str, object]]:
        return scan_secrets_path(path, hidden=hidden, max_size=max_size, reveal=reveal)


class FileHashAPI:
    def hash(self, file: str | Path, algorithm: str = "sha256") -> str:
        return hash_file_value(file, algorithm)


class EntropyAPI:
    def calculate(self, data: bytes) -> float:
        return entropy(data)

    def file(self, file: str | Path) -> float:
        return entropy(Path(file).read_bytes())


class PasswordAPI:
    def generate(self, length: int = 24, count: int = 1, lower: bool = True, upper: bool = True, digits: bool = True, symbols: bool = True) -> str | list[str]:
        passwords = generate_passwords(length=length, count=count, lower=lower, upper=upper, digits=digits, symbols=symbols)
        return passwords[0] if count == 1 else passwords

    def audit(self, password: str) -> dict[str, object]:
        return audit_password(password)


class HeadersAPI:
    def check(self, url: str, timeout: float = 5.0) -> dict[str, object]:
        return check_http_headers(url, timeout=timeout)


class TlsAPI:
    def inspect(self, host: str, port: int = 443, timeout: float = 5.0) -> dict[str, object]:
        return inspect_tls_host(host, port=port, timeout=timeout)


class DnsAPI:
    def lookup(self, host: str) -> list[str]:
        return resolve_host(host)


class JwtAPI:
    def decode(self, token: str) -> dict[str, object]:
        return decode_jwt_token(token)


class UrlAPI:
    def analyze(self, value: str) -> dict[str, object]:
        return analyze_url_value(value)

    def analyze_many(self, values: Iterable[str]) -> list[dict[str, object]]:
        return [analyze_url_value(value) for value in values]


class IpAPI:
    def info(self, address: str) -> dict[str, object]:
        return inspect_ip_address(address)


class FileInspectAPI:
    def inspect(self, file: str | Path, hashes: str | Iterable[str] = "sha256", indicators: bool = False, scan_bytes: int = 1024 * 1024, indicator_limit: int = 20) -> dict[str, object]:
        return inspect_file(file, hashes=hashes, indicators=indicators, scan_bytes=scan_bytes, indicator_limit=indicator_limit)


class TimestampAPI:
    def utc(self) -> str:
        return datetime.now(timezone.utc).isoformat()


class NetworkAPI:
    def scan(self, host: str, ports: str = "common", timeout: float = 0.5, workers: int = 100, banner: bool = False, show_closed: bool = False) -> list[dict[str, object]]:
        return ports_api.scan(host, ports=ports, timeout=timeout, workers=workers, banner=banner, show_closed=show_closed)

    def resolve(self, host: str) -> list[str]:
        return dns.lookup(host)

    def ip(self, address: str) -> dict[str, object]:
        return ip.info(address)

    def url(self, value: str) -> dict[str, object]:
        return url.analyze(value)


class FilesAPI:
    def hash(self, file: str | Path, algorithm: str = "sha256") -> str:
        return file_hash_api.hash(file, algorithm)

    def inspect(self, file: str | Path, hashes: str | Iterable[str] = "sha256", indicators: bool = False, scan_bytes: int = 1024 * 1024, indicator_limit: int = 20) -> dict[str, object]:
        return file_inspect_api.inspect(file, hashes=hashes, indicators=indicators, scan_bytes=scan_bytes, indicator_limit=indicator_limit)

    def entropy(self, file: str | Path) -> float:
        return entropy_tools.file(file)


class AuthAPI:
    def jwt(self, token: str) -> dict[str, object]:
        return jwt.decode(token)

    def password_audit(self, password: str) -> dict[str, object]:
        return password_api.audit(password)


class UtilsAPI:
    def utc_timestamp(self) -> str:
        return timestamp.utc()

    def print_json(self, data: object) -> None:
        print_json(data)

    def decode_base64url_json(self, value: str) -> object:
        return decode_base64url_json(value)


crypto = CryptoAPI()
ports = PortsAPI()
ports_api = ports
secrets_api = SecretsAPI()
secrets = secrets_api
secrets_module = secrets_api
secrets_scan_api = secrets_api
secrets_tools = secrets_api
file_hash_api = FileHashAPI()
entropy_api = EntropyAPI()
entropy_tools = entropy_api
password = PasswordAPI()
password_api = password
headers = HeadersAPI()
tls = TlsAPI()
dns = DnsAPI()
jwt = JwtAPI()
url = UrlAPI()
ip = IpAPI()
file_inspect_api = FileInspectAPI()
file_inspect_module = file_inspect_api
timestamp = TimestampAPI()
network = NetworkAPI()
files = FilesAPI()
auth = AuthAPI()
utils = UtilsAPI()


class SentinelRepl(cmd.Cmd):
    intro = None
    prompt = "sentinel> "

    MODULES = [
        ("crypto", "Encrypt/decrypt, encodings, hashes, HMACs, random tokens, and identification"),
        ("jwt", "Decode JWT header/payload and flag local token risks"),
        ("url", "Analyze URL structure and suspicious local indicators"),
        ("ip", "Classify an IP address for local/network triage"),
        ("ports", "Scan TCP ports on authorized hosts"),
        ("secrets", "Scan files/directories for secret patterns"),
        ("file-inspect", "Inspect file type, hashes, entropy, and embedded indicators"),
        ("file-hash", "Hash a file in binary mode"),
        ("entropy", "Calculate file entropy"),
        ("password", "Generate or audit passwords"),
        ("headers", "Check HTTP security headers"),
        ("tls", "Inspect TLS certificate and cipher"),
        ("dns", "Resolve host addresses"),
        ("timestamp", "Print current UTC timestamp"),
    ]

    def __init__(self, parser: argparse.ArgumentParser):
        super().__init__()
        self.parser = parser
        self.module_map = {str(index): name for index, (name, _) in enumerate(self.MODULES, start=1)}
        self.module_map.update({name: name for name, _ in self.MODULES})

    def preloop(self) -> None:
        print("SentinelCliPy guided REPL. Enter a module number, a command, help, menu, or exit.")
        self.print_menu()

    def print_menu(self) -> None:
        print("\nModules:")
        for index, (name, description) in enumerate(self.MODULES, start=1):
            print(f"  {index}. {name:<10} {description}")
        print("\nEnter a number to start a guided flow, or type a full command, e.g. crypto methods --group modern")

    def do_menu(self, _: str) -> None:
        """Show the module menu."""
        self.print_menu()

    def do_modules(self, arg: str) -> None:
        """Show the module menu."""
        self.print_menu()

    def do_help(self, arg: str) -> None:
        """Show REPL help, or command help when a command is provided."""
        if arg.strip():
            self.run_argv([*shlex.split(arg), "--help"])
            return
        print("Commands:")
        print("  menu/modules       Show the numbered module menu")
        print("  <number>           Start a guided module flow")
        print("  <module>           Start that guided module flow, e.g. crypto")
        print("  <full command>     Run normal CLI syntax, e.g. crypto hash --text hello")
        print("  help <command>     Show help for a command, e.g. help crypto")
        print("  exit/quit          Leave the REPL")
        self.print_menu()

    def do_exit(self, _: str) -> bool:
        """Exit the REPL."""
        return True

    def do_quit(self, _: str) -> bool:
        """Exit the REPL."""
        return True

    def do_EOF(self, _: str) -> bool:
        print()
        return True

    def do_crypto(self, arg: str) -> None:
        """Run a crypto command directly or open the guided crypto menu."""
        if arg.strip():
            self.run_argv(["crypto", *shlex.split(arg)])
        else:
            self.guided_crypto()

    def do_ports(self, arg: str) -> None:
        """Run a port scan command directly or open the guided port scanner."""
        if arg.strip():
            self.run_argv(["ports", *shlex.split(arg)])
        else:
            self.guided_ports()

    def do_secrets(self, arg: str) -> None:
        """Run a secrets scan command directly or open the guided secrets scanner."""
        if arg.strip():
            self.run_argv(["secrets", *shlex.split(arg)])
        else:
            self.guided_secrets()

    def do_password(self, arg: str) -> None:
        """Run a password command directly or open the guided password menu."""
        if arg.strip():
            self.run_argv(["password", *shlex.split(arg)])
        else:
            self.guided_password()

    def default(self, line: str) -> None:
        item = line.strip().lower()
        if not item:
            return
        if item in self.module_map:
            self.open_module(self.module_map[item])
            return
        self.run_argv(shlex.split(line))

    def run_argv(self, argv: list[str]) -> None:
        try:
            args = self.parser.parse_args(argv)
            if not hasattr(args, "func"):
                self.parser.print_help()
                return
            args.func(args)
        except SystemExit:
            pass
        except (ToolkitError, OSError, ValueError) as exc:
            eprint(f"error: {exc}")

    def open_module(self, module: str) -> None:
        handlers = {
            "crypto": self.guided_crypto,
            "jwt": self.guided_jwt,
            "url": self.guided_url,
            "ip": self.guided_ip,
            "ports": self.guided_ports,
            "secrets": self.guided_secrets,
            "file-inspect": self.guided_file_inspect,
            "file-hash": self.guided_file_hash,
            "entropy": self.guided_entropy,
            "password": self.guided_password,
            "headers": self.guided_headers,
            "tls": self.guided_tls,
            "dns": self.guided_dns,
            "timestamp": self.guided_timestamp,
        }
        handler = handlers.get(module)
        if handler:
            handler()
        else:
            eprint(f"error: unknown module: {module}")

    def ask(self, label: str, default: str | None = None, required: bool = False) -> str:
        suffix = f" [{default}]" if default is not None else ""
        while True:
            value = input(f"{label}{suffix}: ").strip()
            if value:
                return value
            if default is not None:
                return default
            if not required:
                return ""
            print("This value is required.")

    def ask_bool(self, label: str, default: bool = False) -> bool:
        default_text = "Y/n" if default else "y/N"
        while True:
            value = input(f"{label} [{default_text}]: ").strip().lower()
            if not value:
                return default
            if value in {"y", "yes", "true", "1"}:
                return True
            if value in {"n", "no", "false", "0"}:
                return False
            print("Enter yes or no.")

    def ask_int(self, label: str, default: int) -> int:
        while True:
            value = self.ask(label, str(default))
            try:
                return int(value)
            except ValueError:
                print("Enter a whole number.")

    def ask_float(self, label: str, default: float) -> float:
        while True:
            value = self.ask(label, str(default))
            try:
                return float(value)
            except ValueError:
                print("Enter a number.")

    def ask_choice(self, title: str, choices: list[tuple[str, str]]) -> str:
        print(f"\n{title}:")
        for index, (key, description) in enumerate(choices, start=1):
            print(f"  {index}. {key:<14} {description}")
        mapping = {str(index): key for index, (key, _) in enumerate(choices, start=1)}
        mapping.update({key: key for key, _ in choices})
        while True:
            value = self.ask("Choice", required=True).lower()
            if value in mapping:
                return mapping[value]
            print("Unknown choice. Use a listed number or name.")

    def source_args(self) -> list[str]:
        source = self.ask_choice(
            "Input source",
            [("text", "Type or paste text directly"), ("file", "Read input from a file path")],
        )
        if source == "file":
            return ["--file", self.ask("File path", required=True)]
        return ["--text", self.ask("Text", required=True)]

    def maybe_output_arg(self) -> list[str]:
        output = self.ask("Output file (blank for stdout)")
        return ["--output", output] if output else []

    def json_arg(self) -> list[str]:
        return ["--json"] if self.ask_bool("JSON output", False) else []

    def guided_crypto(self) -> None:
        action = self.ask_choice(
            "Crypto actions",
            [
                ("encrypt", "Encrypt, cipher, or encode text"),
                ("decrypt", "Decrypt, decipher, or decode text"),
                ("hash", "Create a one-way digest"),
                ("hmac", "Create a keyed HMAC digest"),
                ("random", "Generate a secure random token"),
                ("fernet-key", "Generate a Fernet key"),
                ("aes256-key", "Generate a random AES-256 key"),
                ("kdf", "Derive key material from a passphrase and salt"),
                ("compare", "Constant-time compare two strings/files"),
                ("methods", "List method groups and use cases"),
                ("identify", "Guess possible encoding/cipher/hash formats"),
                ("brute-force", "Generate bounded brute-force candidates"),
            ],
        )
        if action in {"encrypt", "decrypt"}:
            print(
                "Examples: general.base64, classical.caesar, classical.vigenere, classical.playfair, "
                "classical.columnar, classical.hill, modern.aes256gcm, modern.aes256ctrhmac, modern.aes256cbchmac"
            )
            if action == "decrypt":
                print("Tip: use a group wildcard like modern.* to try every method in that group with one key.")
            while True:
                method = self.ask("Method", required=True)
                wildcard = action == "decrypt" and re.fullmatch(r"(general|classical|modern)\.\*", canonical_method(method))
                if wildcard:
                    group, name = wildcard.group(1), "*"
                    break
                try:
                    group, name = split_method(method)
                    break
                except ToolkitError as exc:
                    eprint(f"error: {exc}")
            argv = ["crypto", action, "--method", method, *self.source_args(), *self.maybe_output_arg()]
            if name == "*":
                key = self.ask("Key/passphrase (blank if not needed for every method in the group)")
                if key:
                    argv += ["--key", key]
                argv += self.json_arg()
                self.run_argv(argv)
                return
            if name == "caesar":
                argv += ["--shift", str(self.ask_int("Caesar shift", 3))]
            if name in {"vigenere", "beaufort", "keyword", "autokey", "columnar", "playfair"} or group == "modern":
                argv += ["--key", self.ask("Key/passphrase", required=True)]
            if name == "hill":
                argv += ["--key", self.ask("Key as four integers a,b,c,d (e.g. 3,3,2,5)", required=True)]
            if name == "polybius":
                key = self.ask("Optional keyword for the grid (blank for standard A-Z grid)")
                if key:
                    argv += ["--key", key]
            if name == "affine":
                argv += ["--affine-a", str(self.ask_int("Affine A", 5)), "--affine-b", str(self.ask_int("Affine B", 8))]
            if name == "railfence":
                argv += ["--rails", str(self.ask_int("Rails", 3))]
            if name == "scytale":
                argv += ["--columns", str(self.ask_int("Columns", 5))]
            if name == "xor":
                flag = "--output-encoding" if action == "encrypt" else "--input-encoding"
                argv += [flag, self.ask("XOR ciphertext encoding", "base64")]
            self.run_argv(argv)
        elif action == "hash":
            argv = ["crypto", "hash", "--algorithm", self.ask("Algorithm", "oneway.sha256"), *self.source_args()]
            if "shake" in argv[3]:
                argv += ["--length", str(self.ask_int("SHAKE output bytes", 32))]
            self.run_argv(argv)
        elif action == "hmac":
            argv = ["crypto", "hmac", "--algorithm", self.ask("Algorithm", "oneway.sha256"), "--key", self.ask("HMAC key", required=True), *self.source_args()]
            self.run_argv(argv)
        elif action == "random":
            argv = ["crypto", "random", "--bytes", str(self.ask_int("Random byte count", 32))]
            if self.ask_bool("URL-safe output", False):
                argv.append("--urlsafe")
            self.run_argv(argv)
        elif action == "kdf":
            argv = [
                "crypto",
                "kdf",
                "--passphrase",
                self.ask("Passphrase", required=True),
                "--kdf",
                self.ask("KDF: pbkdf2-sha256/pbkdf2-sha512/scrypt", "pbkdf2-sha256"),
                "--length",
                str(self.ask_int("Output bytes", 32)),
                "--rounds",
                str(self.ask_int("Iterations or scrypt N", 210000)),
            ]
            salt = self.ask("Existing salt (blank to generate one)")
            if salt:
                argv += ["--salt", salt, "--salt-encoding", self.ask("Salt encoding", "base64url")]
            argv += self.json_arg()
            self.run_argv(argv)
        elif action == "compare":
            argv = ["crypto", "compare", "--left", self.ask("Left value", required=True), "--right", self.ask("Right value", required=True)]
            argv += self.json_arg()
            self.run_argv(argv)
        elif action == "methods":
            group = self.ask("Group filter: general/classical/modern/oneway (blank for all)")
            argv = ["crypto", "methods"]
            if group:
                argv += ["--group", group]
            argv += self.json_arg()
            self.run_argv(argv)
        elif action == "identify":
            self.run_argv(["crypto", "identify", *self.source_args(), *self.json_arg()])
        elif action == "brute-force":
            method = self.ask(
                "Method: all/classical.caesar/classical.affine/classical.railfence/classical.scytale/"
                "classical.vigenere/classical.playfair/modern.xor/modern.aes256gcm/modern.aes256cbc "
                "(keyed classical ciphers and modern.* need a --wordlist)",
                "all",
            )
            wordlist_path = self.ask("Wordlist file for keyed ciphers (blank to skip)")
            argv = [
                "crypto",
                "brute-force",
                "--method",
                method,
                *self.source_args(),
                *(["--wordlist", wordlist_path] if wordlist_path else []),
                "--max-attempts",
                str(self.ask_int("Max attempts", 200)),
                "--top",
                str(self.ask_int("Top results", 10)),
                "--max-rails",
                str(self.ask_int("Max rail-fence rails", 12)),
            ]
            contains = self.ask("Only show candidates containing text (blank for no filter)")
            if contains:
                argv += ["--contains", contains]
            min_score = self.ask("Minimum score (blank for 0)")
            if min_score:
                argv += ["--min-score", min_score]
            argv += self.json_arg()
            self.run_argv(argv)
        elif action == "aes256-key":
            self.run_argv(["crypto", "aes256-key"])
        else:
            self.run_argv(["crypto", "fernet-key"])

    def guided_jwt(self) -> None:
        self.run_argv(["jwt", *self.source_args(), *self.json_arg()])

    def guided_url(self) -> None:
        argv = ["url", *self.source_args()]
        if self.ask_bool("Treat input as one URL per line", False):
            argv.append("--lines")
        argv += self.json_arg()
        self.run_argv(argv)

    def guided_ip(self) -> None:
        self.run_argv(["ip", self.ask("IP address", required=True), *self.json_arg()])

    def guided_ports(self) -> None:
        argv = [
            "ports",
            self.ask("Host/IP", "127.0.0.1", required=True),
            "--ports",
            self.ask("Ports (common, 80,443, 1-1024)", "common"),
            "--timeout",
            str(self.ask_float("Timeout seconds", 0.5)),
            "--workers",
            str(self.ask_int("Workers", 100)),
        ]
        if self.ask_bool("Attempt banner grab", False):
            argv.append("--banner")
        if self.ask_bool("Show closed ports", False):
            argv.append("--show-closed")
        argv += self.json_arg()
        self.run_argv(argv)

    def guided_secrets(self) -> None:
        argv = ["secrets", self.ask("File or directory", ".", required=True), "--max-size", str(self.ask_int("Max file size bytes", 1024 * 1024))]
        if self.ask_bool("Include hidden files/directories", False):
            argv.append("--hidden")
        if self.ask_bool("Reveal full secret matches", False):
            argv.append("--reveal")
        if self.ask_bool("Fail on findings", False):
            argv.append("--fail-on-findings")
        argv += self.json_arg()
        self.run_argv(argv)

    def guided_file_inspect(self) -> None:
        argv = ["file-inspect", self.ask("File", required=True), "--hashes", self.ask("Hashes", "sha256")]
        if self.ask_bool("Extract embedded indicators", False):
            argv.append("--indicators")
        argv += self.json_arg()
        self.run_argv(argv)

    def guided_file_hash(self) -> None:
        self.run_argv(["file-hash", self.ask("File", required=True), "--algorithm", self.ask("Algorithm", "sha256")])

    def guided_entropy(self) -> None:
        self.run_argv(["entropy", self.ask("File", required=True), "--threshold", str(self.ask_float("High entropy threshold", 7.5))])

    def guided_password(self) -> None:
        action = self.ask_choice("Password actions", [("generate", "Generate passwords"), ("audit", "Score a password locally")])
        if action == "generate":
            argv = ["password", "generate", "--length", str(self.ask_int("Length", 24)), "--count", str(self.ask_int("Count", 1))]
            for flag in ["lower", "upper", "digits", "symbols"]:
                if not self.ask_bool(f"Use {flag}", True):
                    argv.append(f"--no-{flag}")
            self.run_argv(argv)
        else:
            argv = ["password", "audit", self.ask("Password", required=True)]
            argv += self.json_arg()
            self.run_argv(argv)

    def guided_headers(self) -> None:
        argv = ["headers", self.ask("URL or host", required=True), "--timeout", str(self.ask_float("Timeout seconds", 5.0)), *self.json_arg()]
        self.run_argv(argv)

    def guided_tls(self) -> None:
        argv = ["tls", self.ask("Host", required=True), "--port", str(self.ask_int("Port", 443)), "--timeout", str(self.ask_float("Timeout seconds", 5.0)), *self.json_arg()]
        self.run_argv(argv)

    def guided_dns(self) -> None:
        self.run_argv(["dns", self.ask("Host", required=True), *self.json_arg()])

    def guided_timestamp(self) -> None:
        self.run_argv(["timestamp"])


def add_text_file_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group()
    source.add_argument("-t", "--text", help="Input text. If omitted, stdin is used when piped.")
    source.add_argument("-f", "--file", help="Read input text from a file.")
    parser.add_argument("-o", "--output", help="Write output to a file instead of stdout.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelclipy",
        description="CLI cybersecurity toolkit for authorized defensive workflows.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    crypto = subparsers.add_parser("crypto", help="Encrypt, decrypt, encode, hash, HMAC, identify formats, and random tokens.")
    crypto_sub = crypto.add_subparsers(dest="crypto_command")

    enc = crypto_sub.add_parser("encrypt", help="Encrypt, cipher, or encode input.")
    add_text_file_args(enc)
    enc.add_argument(
        "-m",
        "--method",
        required=True,
        help="Method name, e.g. general.base64, classical.caesar, modern.aes256gcm. Run 'crypto methods'.",
    )
    enc.add_argument("--shift", type=int, default=3, help="Caesar shift. Default: 3.")
    enc.add_argument(
        "-k",
        "--key",
        default="",
        help=(
            "Key/passphrase for vigenere, beaufort, keyword, autokey, columnar, playfair, hill (four "
            "integers, e.g. '3,3,2,5'), xor, fernet, aesgcm/aes256gcm, aes256cbc, "
            "aes256ctrhmac, aes256cbchmac, or chacha20poly1305. "
            "Optional for polybius."
        ),
    )
    enc.add_argument("--affine-a", type=int, default=5, help="Affine A value. Must be coprime with 26. Default: 5.")
    enc.add_argument("--affine-b", type=int, default=8, help="Affine B shift. Default: 8.")
    enc.add_argument("--rails", type=int, default=3, help="Rail fence rail count. Default: 3.")
    enc.add_argument("--columns", type=int, default=5, help="Column count for the scytale cipher. Default: 5.")
    enc.add_argument("--output-encoding", choices=["base64", "base64url", "base32", "hex", "ascii85", "base85"], default="base64", help="Encoding for XOR ciphertext.")
    enc.set_defaults(func=crypto_encrypt)

    dec = crypto_sub.add_parser("decrypt", help="Decrypt, decipher, or decode input.")
    add_text_file_args(dec)
    dec.add_argument(
        "-m",
        "--method",
        required=True,
        help=(
            "Method name, e.g. general.base64, classical.caesar, modern.aes256gcm. Run 'crypto methods'. "
            "Also accepts a group wildcard (general.*, classical.*, or modern.*) to try every method in that "
            "group with the given --key/--shift/etc. and report which ones worked, ranked best-first."
        ),
    )
    dec.add_argument("--shift", type=int, default=3, help="Caesar shift. Default: 3.")
    dec.add_argument(
        "-k",
        "--key",
        default="",
        help=(
            "Key/passphrase for vigenere, beaufort, keyword, autokey, columnar, playfair, hill (four "
            "integers, e.g. '3,3,2,5'), xor, fernet, aesgcm/aes256gcm, aes256cbc, "
            "aes256ctrhmac, aes256cbchmac, or chacha20poly1305. "
            "Optional for polybius."
        ),
    )
    dec.add_argument("--affine-a", type=int, default=5, help="Affine A value. Must be coprime with 26. Default: 5.")
    dec.add_argument("--affine-b", type=int, default=8, help="Affine B shift. Default: 8.")
    dec.add_argument("--rails", type=int, default=3, help="Rail fence rail count. Default: 3.")
    dec.add_argument("--columns", type=int, default=5, help="Column count for the scytale cipher. Default: 5.")
    dec.add_argument("--input-encoding", choices=["base64", "base64url", "base32", "hex", "ascii85", "base85"], default="base64", help="Encoding for XOR ciphertext.")
    dec.add_argument("--json", action="store_true", help="Emit JSON. Only used with a group.* wildcard method.")
    dec.set_defaults(func=crypto_decrypt)

    hash_parser = crypto_sub.add_parser("hash", help="One-way hash text or a text file.")
    add_text_file_args(hash_parser)
    hash_parser.add_argument("-a", "--algorithm", default="oneway.sha256", help="Hash algorithm, e.g. oneway.sha256, oneway.sha3-256, oneway.blake2b.")
    hash_parser.add_argument("--length", type=int, default=32, help="Output byte length for SHAKE hashes. Default: 32.")
    hash_parser.set_defaults(func=crypto_hash)

    hmac_parser = crypto_sub.add_parser("hmac", help="Create an HMAC digest.")
    add_text_file_args(hmac_parser)
    hmac_parser.add_argument("-k", "--key", required=True, help="HMAC key.")
    hmac_parser.add_argument("-a", "--algorithm", default="oneway.sha256", help="Hash algorithm.")
    hmac_parser.set_defaults(func=crypto_hmac)

    rand_parser = crypto_sub.add_parser("random", help="Generate a secure random token.")
    rand_parser.add_argument("-b", "--bytes", type=int, default=32, help="Random byte count. Default: 32.")
    rand_parser.add_argument("--urlsafe", action="store_true", help="Emit URL-safe base64 instead of hex.")
    rand_parser.set_defaults(func=crypto_random)

    fernet_key = crypto_sub.add_parser("fernet-key", help="Generate a Fernet key for authenticated encryption.")
    fernet_key.set_defaults(func=crypto_fernet_key)

    aes256_key = crypto_sub.add_parser("aes256-key", aliases=["aeskey"], help="Generate a random 32-byte AES-256 key (base64url) for aes256gcm/aes256cbc.")
    aes256_key.set_defaults(func=crypto_aes256_key)

    kdf_parser = crypto_sub.add_parser("kdf", help="Derive key material from a passphrase using PBKDF2 or scrypt.")
    kdf_parser.add_argument("-p", "--passphrase", required=True, help="Passphrase to derive from.")
    kdf_parser.add_argument("--kdf", choices=["pbkdf2-sha256", "pbkdf2-sha512", "scrypt"], default="pbkdf2-sha256")
    kdf_parser.add_argument("--length", type=int, default=32, help="Output byte length. Default: 32.")
    kdf_parser.add_argument("--rounds", type=int, default=210000, help="PBKDF2 iterations, or scrypt N. Default: 210000.")
    kdf_parser.add_argument("--salt", help="Existing salt. If omitted, a random salt is generated.")
    kdf_parser.add_argument("--salt-bytes", type=int, default=16, help="Random salt byte count when --salt is omitted. Default: 16.")
    kdf_parser.add_argument("--salt-encoding", choices=["base64", "base64url", "base32", "hex", "ascii85", "base85"], default="base64url")
    kdf_parser.add_argument("--output-encoding", choices=["base64", "base64url", "base32", "hex", "ascii85", "base85"], default="base64url")
    kdf_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    kdf_parser.set_defaults(func=crypto_kdf)

    compare_parser = crypto_sub.add_parser("compare", help="Constant-time compare two strings or text files.")
    left_source = compare_parser.add_mutually_exclusive_group(required=True)
    left_source.add_argument("--left", help="Left string.")
    left_source.add_argument("--left-file", help="Read left string from a file.")
    right_source = compare_parser.add_mutually_exclusive_group(required=True)
    right_source.add_argument("--right", help="Right string.")
    right_source.add_argument("--right-file", help="Read right string from a file.")
    compare_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    compare_parser.set_defaults(func=crypto_compare)

    methods_parser = crypto_sub.add_parser("methods", help="List grouped crypto/encoding/hash methods and what they are good for.")
    methods_parser.add_argument("--group", choices=["general", "classical", "modern", "oneway"], help="Filter by method group.")
    methods_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    methods_parser.set_defaults(func=crypto_methods)

    identify_parser = crypto_sub.add_parser("identify", help="Guess possible encodings, ciphers, hashes, or token formats from text.")
    add_text_file_args(identify_parser)
    identify_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    identify_parser.set_defaults(func=crypto_identify)
    brute_parser = crypto_sub.add_parser("brute-force", aliases=["bruteforce", "brute"], help="Generate bounded brute-force candidates for classical/CTF ciphers.")
    add_text_file_args(brute_parser)
    brute_parser.add_argument(
        "-m",
        "--method",
        default="all",
        help=(
            "Method to try: all (tries every no-key/small-key classical cipher, plus every "
            "--wordlist-keyed classical cipher when --wordlist is given), classical.caesar, "
            "classical.affine, classical.railfence, classical.scytale, classical.rot47, "
            "classical.trithemius, classical.polybius, classical.bacon, classical.reverse, "
            "modern.xor, or (with --wordlist) classical.vigenere, classical.beaufort, "
            "classical.keyword, classical.autokey, classical.playfair, classical.columnar, "
            "modern.fernet, modern.aesgcm, modern.aes256gcm, modern.aes256cbc, "
            "modern.aes256ctrhmac, modern.aes256cbchmac, "
            "modern.chacha20poly1305."
        ),
    )
    brute_parser.add_argument("--max-attempts", type=int, default=200, help="Maximum candidate attempts. Default: 200.")
    brute_parser.add_argument("--top", type=int, default=10, help="Number of top-scoring candidates to print. Default: 10.")
    brute_parser.add_argument("--contains", help="Only keep candidates containing this text, case-insensitive.")
    brute_parser.add_argument("--min-score", type=float, default=0.0, help="Minimum English-likeness score to display. Default: 0.")
    brute_parser.add_argument("--max-rails", type=int, default=12, help="Maximum rails/columns for rail fence and scytale attempts. Default: 12.")
    brute_parser.add_argument(
        "--wordlist",
        help=(
            "Path to a newline-separated file of candidate keys/passphrases for a dictionary attack. "
            "Required for modern.fernet/aesgcm/aes256gcm/aes256cbc/aes256ctrhmac/"
            "aes256cbchmac/chacha20poly1305 and for the keyed "
            "classical ciphers (classical.vigenere, classical.beaufort, classical.keyword, "
            "classical.autokey, classical.playfair, classical.columnar); optionally adds multi-byte "
            "key guesses to modern.xor; and, with method=all, also runs every keyed classical cipher "
            "against the wordlist."
        ),
    )
    brute_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    brute_parser.set_defaults(func=crypto_bruteforce)

    jwt_parser = subparsers.add_parser("jwt", help="Decode a JWT header/payload and flag local token risks.")
    add_text_file_args(jwt_parser)
    jwt_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    jwt_parser.set_defaults(func=jwt_decode)

    url_parser = subparsers.add_parser("url", help="Analyze URL structure and suspicious local indicators.")
    add_text_file_args(url_parser)
    url_parser.add_argument("--lines", action="store_true", help="Treat input as one URL per line.")
    url_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    url_parser.set_defaults(func=url_analyze)

    ip_parser = subparsers.add_parser("ip", help="Classify an IP address for local/network triage.")
    ip_parser.add_argument("address", help="IPv4 or IPv6 address.")
    ip_parser.add_argument("--json", action="store_true", help="Emit JSON.")
    ip_parser.set_defaults(func=ip_info)

    ps = subparsers.add_parser("ports", help="TCP connect port scanner.")
    ps.add_argument("host", help="Host or IP to scan. Use only on systems you are authorized to test.")
    ps.add_argument("-p", "--ports", default="common", help="Ports: common, 80,443, 1-1024, or mixed ranges.")
    ps.add_argument("-t", "--timeout", type=float, default=0.5, help="Connection timeout per port in seconds.")
    ps.add_argument("-w", "--workers", type=int, default=100, help="Concurrent worker count.")
    ps.add_argument("--banner", action="store_true", help="Attempt small banner grab on open ports.")
    ps.add_argument("--show-closed", action="store_true", help="Include closed ports in output.")
    ps.add_argument("--json", action="store_true", help="Emit JSON.")
    ps.set_defaults(func=port_scan)

    ss = subparsers.add_parser("secrets", help="Scan files for common secret patterns.")
    ss.add_argument("path", help="File or directory to scan.")
    ss.add_argument("--hidden", action="store_true", help="Include hidden files and directories.")
    ss.add_argument("--max-size", type=int, default=1024 * 1024, help="Maximum file size in bytes. Default: 1 MiB.")
    ss.add_argument("--reveal", action="store_true", help="Print full matched secrets instead of masking.")
    ss.add_argument("--fail-on-findings", action="store_true", help="Return exit code 1 when findings exist.")
    ss.add_argument("--json", action="store_true", help="Emit JSON.")
    ss.set_defaults(func=secrets_scan)

    fi = subparsers.add_parser("file-inspect", help="Inspect file type, hashes, entropy, and embedded indicators.")
    fi.add_argument("file", help="File to inspect.")
    fi.add_argument("--hashes", default="sha256", help="Comma-separated hashes/checksums. Default: sha256.")
    fi.add_argument("--indicators", action="store_true", help="Extract simple embedded URLs, IPv4 addresses, and domains.")
    fi.add_argument("--scan-bytes", type=int, default=1024 * 1024, help="Bytes to scan for indicators. Default: 1 MiB.")
    fi.add_argument("--indicator-limit", type=int, default=20, help="Maximum indicators per type. Default: 20.")
    fi.add_argument("--json", action="store_true", help="Emit JSON.")
    fi.set_defaults(func=file_inspect)

    fh = subparsers.add_parser("file-hash", help="Hash a file in binary mode.")
    fh.add_argument("file", help="File to hash.")
    fh.add_argument("-a", "--algorithm", default="sha256", help="Hash algorithm.")
    fh.set_defaults(func=file_hash)

    ent = subparsers.add_parser("entropy", help="Calculate file Shannon entropy.")
    ent.add_argument("file", help="File to inspect.")
    ent.add_argument("--threshold", type=float, default=7.5, help="High-entropy threshold. Default: 7.5.")
    ent.set_defaults(func=entropy_cmd)

    pw = subparsers.add_parser("password", help="Generate or audit passwords.")
    pw_sub = pw.add_subparsers(dest="password_command")
    pw_gen = pw_sub.add_parser("generate", help="Generate secure passwords.")
    pw_gen.add_argument("-l", "--length", type=int, default=24, help="Password length.")
    pw_gen.add_argument("-c", "--count", type=int, default=1, help="Number of passwords.")
    pw_gen.add_argument("--lower", action=argparse.BooleanOptionalAction, default=True)
    pw_gen.add_argument("--upper", action=argparse.BooleanOptionalAction, default=True)
    pw_gen.add_argument("--digits", action=argparse.BooleanOptionalAction, default=True)
    pw_gen.add_argument("--symbols", action=argparse.BooleanOptionalAction, default=True)
    pw_gen.set_defaults(func=password_generate)
    pw_audit = pw_sub.add_parser("audit", help="Score a password locally.")
    pw_audit.add_argument("password", nargs="?", help="Password to audit. If omitted, stdin is used.")
    pw_audit.add_argument("--json", action="store_true", help="Emit JSON.")
    pw_audit.set_defaults(func=password_audit)

    hh = subparsers.add_parser("headers", help="Check common HTTP security headers.")
    hh.add_argument("url", help="URL or host.")
    hh.add_argument("-t", "--timeout", type=float, default=5.0)
    hh.add_argument("--json", action="store_true")
    hh.set_defaults(func=http_headers)

    ti = subparsers.add_parser("tls", help="Inspect a server TLS certificate and negotiated cipher.")
    ti.add_argument("host", help="TLS host.")
    ti.add_argument("-p", "--port", type=int, default=443)
    ti.add_argument("-t", "--timeout", type=float, default=5.0)
    ti.add_argument("--json", action="store_true")
    ti.set_defaults(func=tls_info)

    dl = subparsers.add_parser("dns", help="Resolve host addresses.")
    dl.add_argument("host", help="Host to resolve.")
    dl.add_argument("--json", action="store_true")
    dl.set_defaults(func=dns_lookup)

    ts = subparsers.add_parser("timestamp", help="Print current UTC timestamp.")
    ts.set_defaults(func=timestamp_cmd)

    repl = subparsers.add_parser("repl", help="Start an interactive toolkit shell.")
    repl.set_defaults(func=lambda args: SentinelRepl(parser).cmdloop() or 0)

    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return 130
    except ToolkitError as exc:
        eprint(f"error: {exc}")
        return 2
    except OSError as exc:
        eprint(f"error: {exc}")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
