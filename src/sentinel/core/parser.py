"""Argparse command tree for SentinelCLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "sentinel.core"

from ..modules.auth.operations import *
from ..modules.crypto.operations import *
from ..modules.dns.operations import *
from ..modules.files.operations import *
from ..modules.infrastructure.operations import *
from ..modules.network.operations import *
from ..modules.network.diagnostics import *
from ..modules.secrets.operations import *
from ..modules.security.operations import *
from ..modules.system.operations import *
from ..modules.tls.operations import *
from ..modules.utilities.operations import *
from .common import *
from .guided_repl import SentinelRepl


def _run_repl(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.legacy:
        return int(SentinelRepl(parser).cmdloop() or 0)
    from .launcher import _run_textual_app

    return _run_textual_app(parser)


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

    ping = subparsers.add_parser("ping", help="Check host reachability and latency.")
    ping.add_argument("host", help="Host or IP address.")
    ping.add_argument("-t", "--timeout", type=float, default=2.0, help="Timeout per request in seconds.")
    ping.add_argument("-c", "--count", type=int, default=1, help="Number of echo requests, maximum 4.")
    ping.add_argument("--json", action="store_true", help="Emit JSON.")
    ping.set_defaults(func=ping_command)

    da = subparsers.add_parser("dns-audit", help="Resolve A records and optional reverse lookups.")
    da.add_argument("host", help="Hostname to resolve.")
    da.add_argument("--reverse", action="store_true", help="Perform reverse lookups for resolved addresses.")
    da.add_argument("--json", action="store_true", help="Emit JSON.")
    da.set_defaults(func=dns_audit)

    pub = subparsers.add_parser("public-ip", help="Show the current public IP address.")
    pub.add_argument("-t", "--timeout", type=float, default=5.0)
    pub.add_argument("--json", action="store_true", help="Emit JSON.")
    pub.set_defaults(func=public_ip)

    system = subparsers.add_parser("system-info", help="Show local operating-system and Python details.")
    system.add_argument("--json", action="store_true", help="Emit JSON.")
    system.set_defaults(func=system_info)

    disk = subparsers.add_parser("disk-usage", help="Show filesystem capacity for a path.")
    disk.add_argument("path", nargs="?", default=".", help="Path or mount point.")
    disk.add_argument("--json", action="store_true", help="Emit JSON.")
    disk.set_defaults(func=disk_usage)

    processes = subparsers.add_parser("process-list", help="List local processes without modifying them.")
    processes.add_argument("--filter", help="Filter process names.")
    processes.add_argument("--limit", type=int, default=50)
    processes.add_argument("--json", action="store_true", help="Emit JSON.")
    processes.set_defaults(func=process_list)

    logs = subparsers.add_parser("log-scan", help="Find matching lines in a local log file.")
    logs.add_argument("file", help="Log file path.")
    logs.add_argument("--pattern", default="ERROR|CRITICAL|WARNING", help="Regular expression to match.")
    logs.add_argument("--limit", type=int, default=100)
    logs.add_argument("--json", action="store_true", help="Emit JSON.")
    logs.set_defaults(func=log_scan)

    ssh = subparsers.add_parser("ssh-key", help="Audit or generate SSH keys.")
    ssh_sub = ssh.add_subparsers(dest="ssh_command")
    ssh_audit = ssh_sub.add_parser("audit", help="Audit public-key file formats.")
    ssh_audit.add_argument("path", nargs="?", default="~/.ssh")
    ssh_audit.add_argument("--json", action="store_true", help="Emit JSON.")
    ssh_audit.set_defaults(func=ssh_key_audit)
    ssh_generate = ssh_sub.add_parser("generate", help="Generate a local SSH key pair.")
    ssh_generate.add_argument("output", help="Private-key output path.")
    ssh_generate.add_argument("--type", choices=["ed25519", "rsa", "ecdsa"], default="ed25519")
    ssh_generate.add_argument("--comment", default="sentinelcli")
    ssh_generate.set_defaults(func=ssh_key_generate)

    config = subparsers.add_parser("config-validate", help="Validate local JSON, INI, CFG, CONF, or ENV files.")
    config.add_argument("file")
    config.add_argument("--json", action="store_true", help="Emit JSON.")
    config.set_defaults(func=config_validate)

    cloud = subparsers.add_parser("cloud-context", help="Show configured cloud context names without reading secrets.")
    cloud.add_argument("--json", action="store_true", help="Emit JSON.")
    cloud.set_defaults(func=cloud_context)

    repl = subparsers.add_parser("repl", help="Start an interactive toolkit shell.")
    repl.add_argument("--legacy", action="store_true", help="Use the compatibility cmd-based guided shell.")
    repl.set_defaults(func=lambda args: _run_repl(parser, args))

    return parser

