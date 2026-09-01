# SentinelCliPy

SentinelCliPy is a Python toolkit for defensive security workflows, local analysis, and operational triage. It includes password and crypto tooling, JWT inspection, URL/IP review, file and secret scanning, TLS and HTTP checks, entropy analysis, and a small interactive REPL.

It is intended for authorized use in security testing, internal validation, research, and defensive tooling scenarios.

## What it includes

- Crypto and hashing utilities
- JWT decoding and validation helpers
- File inspection and entropy analysis
- Secret scanning for common credential patterns
- URL and IP triage
- Port scanning helpers
- HTTP security header evaluation
- TLS endpoint inspection
- DNS lookup and host analysis
- REPL mode for guided execution

## Installation

Install the package in editable mode:

```powershell
python -m pip install -e .
```

If you want the optional crypto dependencies as well:

```powershell
python -m pip install -e ".[crypto]"
```

You can then run the CLI commands:

```powershell
sentinelcli --help
sentinelcli repl
sentinelclipy --help
```

If you prefer to run the script directly:

```powershell
python .\sentinelcli.py --help
python .\sentinelcli.py repl
```

## Quick start

### CLI usage

```powershell
sentinelcli crypto encrypt --method general.base64 --text "hello"
sentinelcli crypto hash --algorithm oneway.sha256 --text "hello"
sentinelcli jwt --text "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
sentinelcli url --text "https://example.com/login?token=abc"
sentinelcli headers https://example.com
sentinelcli file-inspect .\README.md --hashes sha256,crc32 --indicators
```

### Python module usage

```python
import sentinelcli as s

encoded = s.crypto.encode("hello", "general.base64")
print(encoded)  # aGVsbG8=
print(s.crypto.decode(encoded, "general.base64"))  # hello

result = s.decode_jwt_token("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.")
print(result["header"])
print(result["payload"])
print(result["warnings"])

print(s.entropy(b"hello world"))
```

This is the recommended import style for scripting and library integration:

```python
import sentinelcli as s
s.crypto.encode(...)
s.jwt.decode(...)
s.files.inspect(...)
s.network.scan(...)
```

## Crypto method groups

Method names can be used in grouped form such as `general.base64`, `classical.caesar`, `modern.aes256gcm`, and `oneway.sha256`. Short names like `base64` and `caesar` also work in many cases.

List the available methods:

```powershell
sentinelcli crypto methods
sentinelcli crypto methods --group modern
```

### General encodings

These are reversible encodings, not true encryption.

- `general.base64`
- `general.base64url`
- `general.base32`
- `general.hex`
- `general.ascii85`
- `general.base85`
- `general.binary`
- `general.octal`
- `general.decimal`
- `general.url`
- `general.html`

### Classical ciphers

Educational or lab-only methods. These are not intended for real confidentiality.

- `classical.caesar`
- `classical.rot13`
- `classical.atbash`
- `classical.vigenere`
- `classical.beaufort`
- `classical.affine`
- `classical.railfence`
- `classical.bacon`
- `classical.reverse`

### Modern symmetric encryption

These methods require the optional crypto dependency and are intended for authenticated or interoperable encryption workflows.

- `modern.xor`
- `modern.fernet`
- `modern.aesgcm`
- `modern.aes256gcm`
- `modern.aes256cbc`
- `modern.aes256ctrhmac`
- `modern.aes256cbchmac`
- `modern.chacha20poly1305`

Use `modern.aes256gcm` or `modern.chacha20poly1305` for new work when you need authenticated encryption.

### One-way hashes and checksums

These are integrity or fingerprint tools; they are not reversible.

- `oneway.md5`
- `oneway.sha1`
- `oneway.sha224`
- `oneway.sha256`
- `oneway.sha384`
- `oneway.sha512`
- `oneway.sha3-256`
- `oneway.sha3-512`
- `oneway.blake2s`
- `oneway.blake2b`
- `oneway.crc32`
- `oneway.adler32`

## Example commands

```powershell
sentinelcli crypto encrypt --method general.base64 --text "hello"
sentinelcli crypto decrypt --method general.base64 --text "aGVsbG8="
sentinelcli crypto encrypt --method classical.caesar --shift 7 --text "hello"
sentinelcli crypto encrypt --method modern.aes256gcm --key "passphrase" --text "secret"
sentinelcli crypto decrypt --method modern.aes256gcm --key "passphrase" --text "PASTE_TOKEN"
sentinelcli crypto hash --algorithm oneway.sha256 --text "message"
sentinelcli crypto hmac --algorithm oneway.sha512 --key "shared-key" --text "message"
sentinelcli crypto identify --text "aGVsbG8="
sentinelcli crypto fernet-key
sentinelcli crypto aes256-key
```

## JWT workflow

Use the CLI to inspect JWTs and highlight timing or trust issues:

```powershell
sentinelcli jwt --text "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ." --json
```

In Python:

```python
import sentinelcli as s

token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
result = s.decode_jwt_token(token)
print(result["header"])
print(result["payload"])
print(result["warnings"])
```

The decoder validates the returned structure and includes `header`, `payload`, `signature_present`, `timeline`, `warnings`, and `parts` in the result.

## Network and security checks

```powershell
sentinelcli ports 127.0.0.1 --ports common --timeout 0.25
sentinelcli headers https://example.com
sentinelcli tls example.com
sentinelcli dns example.com
sentinelcli url --text "https://example.com/login?token=abc"
sentinelcli ip 127.0.0.1 --json
```

## File and secret inspection

```powershell
sentinelcli file-inspect .\README.md --hashes sha256,crc32 --indicators
sentinelcli entropy .\README.md
sentinelcli secrets . --hidden --json
```

## Password utilities

```powershell
sentinelcli password generate --length 24 --count 3
sentinelcli password audit "Password123!" --json
```

## Guided REPL

Start the interactive mode:

```powershell
sentinelcli repl
```

The REPL presents a numbered set of modules and allows guided flows or direct command entry.

## Security and usage guidance

- Only test systems and data that you own or are explicitly authorized to assess.
- Treat all output as operational telemetry, not proof of malicious activity.
- JWTs should be validated against your trust boundaries and expected issuer/audience rules.
- Authentication and secret scanners should be used defensively and with clear scope.
- Network scanning should be limited to systems under your control or explicitly approved for testing.

## Building an executable

To create a standalone EXE with PyInstaller:

```powershell
python -m pip install pyinstaller
pyinstaller --onefile --name sentinelcli .\sentinelcli.py
```

The generated binary will appear in the `dist` directory.

## Release note

This project is intended as a release-ready defensive toolkit with a clean CLI surface and a Python module API for automation. It is best suited for local security workflow support, validation, triage, and developer-oriented defensive tooling.

## License

This project is provided as-is for authorized defensive use. Please review the repository license before publication or redistribution.
