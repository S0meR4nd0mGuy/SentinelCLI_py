"""Compatibility guided command shell."""

from __future__ import annotations

import argparse
import cmd
import re
import shlex
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "sentinel.core"

from ..modules.auth.operations import *
from ..modules.crypto.operations import *
from ..modules.dns.operations import *
from ..modules.files.operations import *
from ..modules.network.operations import *
from ..modules.secrets.operations import *
from ..modules.tls.operations import *
from ..modules.utilities.operations import *
from .common import *
from .common import ToolkitError, ansi, eprint


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
        header = ansi("1;36", "\nModules:")
        print(header)
        for index, (name, description) in enumerate(self.MODULES, start=1):
            name_label = ansi("1;32", f"{name:<10}")
            description_label = ansi("0;37", description)
            print(f"  {index}. {name_label} {description_label}")
        footer = ansi("1;33", "\nEnter a number to start a guided flow, or type a full command, e.g. crypto methods --group modern")
        print(footer)

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
        prompt = ansi("1;36", f"{label}{suffix}") + ansi("0;37", ": ")
        while True:
            value = input(f"{prompt}").strip()
            if value:
                return value
            if default is not None:
                return default
            if not required:
                return ""
            print(ansi("1;31", "This value is required."))

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

