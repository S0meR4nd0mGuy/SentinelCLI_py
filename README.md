# SentinelCliPy

SentinelCliPy is a Python cybersecurity CLI toolkit for authorized defensive work. It includes crypto helpers, hashing, JWT decoding, URL/IP/file triage, port scanning, secrets scanning, password utilities, HTTP security header checks, TLS certificate inspection, DNS lookup, entropy checks, and an optional REPL.

## Install

```powershell
python -m pip install -e ".[crypto]"
```

After installation you can run either:

```powershell
sentinelclipy --help
python .\sentinelclipy.py --help
```

## Crypto Method Groups

Method names can be grouped as `group.method`, for example `general.base64`, `classical.caesar`, `modern.aes256gcm`, or `oneway.sha256`. Short names like `base64` and `caesar` still work.

List everything with:

```powershell
sentinelclipy crypto methods
sentinelclipy crypto methods --group modern
```

### General Encodings

These are reversible encodings, not encryption. They are useful for transport, parsing, and CTF work.

- `general.base64`
- `general.base64url`
- `general.base32`
- `general.base16`
- `general.hex`
- `general.ascii85`
- `general.base85`
- `general.url`
- `general.html`
- `general.binary`
- `general.octal`
- `general.decimal`

### Classical Ciphers

These are educational ciphers and puzzle/CTF tools. Do not use them for real confidentiality.

- `classical.caesar`
- `classical.rot13`
- `classical.atbash`
- `classical.vigenere`
- `classical.beaufort`: polyalphabetic cipher, self-reciprocal (the same command decrypts what it encrypted)
- `classical.affine`
- `classical.railfence`
- `classical.bacon`
- `classical.reverse`

### Modern Symmetric Encryption

These use keys/passphrases. `modern.fernet`, `modern.aesgcm`/`modern.aes256gcm`, `modern.aes256cbc`, `modern.aes256ctrhmac`, `modern.aes256cbchmac`, and `modern.chacha20poly1305` require the optional `cryptography` dependency installed by `.[crypto]`.

- `modern.xor`: lab/CTF byte XOR, not real security by itself
- `modern.fernet`: authenticated encryption with Fernet tokens
- `modern.aesgcm` / `modern.aes256gcm`: AES-256-GCM authenticated encryption (`aes256gcm` is an alias for `aesgcm` — same algorithm, same ciphertext format). This is the recommended AES-256 option for anything new.
- `modern.aes256cbc`: AES-256-CBC with PKCS7 padding. No built-in authentication (unlike the GCM/ChaCha modes above), so a corrupted or tampered ciphertext may silently decrypt to garbage instead of failing loudly. Use this only when you specifically need classic CBC-mode AES for interop.
- `modern.aes256ctrhmac`: AES-256-CTR with HMAC-SHA256 encrypt-then-MAC authentication.
- `modern.aes256cbchmac`: AES-256-CBC with PKCS7 padding plus HMAC-SHA256 authentication. Prefer this over plain CBC when CBC interop is needed and you control both sides.
- `modern.chacha20poly1305`: ChaCha20-Poly1305 authenticated encryption

Any of `aesgcm`/`aes256gcm`/`aes256cbc`/`aes256ctrhmac`/`aes256cbchmac`/`chacha20poly1305` accepts either a raw passphrase (hashed down to a 256-bit key) or a proper 32-byte key. Generate one with:

```powershell
sentinelclipy crypto aes256-key
```

This is the AES-256 analogue of `crypto fernet-key`: a random, cryptographically strong 32-byte key, base64url-encoded, ready to pass to `--key` for any of the AES-256/ChaCha20 methods above.

### One-Way Hashes & Checksums

Hashes are integrity/fingerprint methods. They cannot be decrypted.

- `oneway.md5`
- `oneway.sha1`
- `oneway.sha224`
- `oneway.sha256`
- `oneway.sha384`
- `oneway.sha512`
- `oneway.sha512-224`
- `oneway.sha512-256`
- `oneway.sha3-224`
- `oneway.sha3-256`
- `oneway.sha3-384`
- `oneway.sha3-512`
- `oneway.blake2b`
- `oneway.blake2s`
- `oneway.shake-128`
- `oneway.shake-256`

Also available in the `oneway` group, but **not** cryptographic hashes — fast checksums for catching accidental corruption only, not tampering:

- `oneway.crc32`
- `oneway.adler32`

`crypto hmac` refuses `crc32`/`adler32` since HMAC needs a real cryptographic hash to mean anything.

## Examples

```powershell
sentinelclipy crypto encrypt --method general.base64 --text "hello"
sentinelclipy crypto decrypt --method general.base64 --text "aGVsbG8="
sentinelclipy crypto encrypt --method classical.caesar --shift 7 --text "hello"
sentinelclipy crypto decrypt --method classical.caesar --shift 7 --text "olssv"
sentinelclipy crypto encrypt --method classical.railfence --rails 3 --text "attackatdawn"
sentinelclipy crypto encrypt --method classical.beaufort --key "lemon" --text "attackatdawn"
sentinelclipy crypto encrypt --method modern.aes256gcm --key "passphrase" --text "secret"
sentinelclipy crypto decrypt --method modern.aes256gcm --key "passphrase" --text "PASTE_TOKEN"
sentinelclipy crypto encrypt --method modern.aes256cbc --key "passphrase" --text "secret"
sentinelclipy crypto decrypt --method modern.aes256cbc --key "passphrase" --text "PASTE_TOKEN"
sentinelclipy crypto encrypt --method modern.aes256ctrhmac --key "passphrase" --text "secret"
sentinelclipy crypto decrypt --method modern.aes256ctrhmac --key "passphrase" --text "PASTE_TOKEN"
sentinelclipy crypto kdf --passphrase "passphrase" --kdf pbkdf2-sha256 --length 32 --json
sentinelclipy crypto compare --left "digest-a" --right "digest-a"
sentinelclipy crypto fernet-key
sentinelclipy crypto aes256-key
sentinelclipy crypto hash --algorithm oneway.sha256 --text "message"
sentinelclipy crypto hash --algorithm oneway.crc32 --text "message"
sentinelclipy crypto hmac --algorithm oneway.sha512 --key "shared-key" --text "message"
sentinelclipy crypto identify --text "aGVsbG8="
```

## Brute-Forcing & Dictionary Attacks

`crypto brute-force` generates decryption candidates without a known key and ranks them by an English-likeness score (except where noted below).

**No wordlist needed** — full keyspace search, since these key spaces are small:

```powershell
sentinelclipy crypto brute-force --method all --text "khoor zruog" --top 5
sentinelclipy crypto brute-force --method classical.affine --text "..." --top 5
sentinelclipy crypto brute-force --method classical.railfence --max-rails 12 --text "..." --top 5
sentinelclipy crypto brute-force --method modern.xor --text "..." --top 5
```

`modern.xor` without a wordlist tries every single-byte key (0x00–0xFF). `classical.vigenere` and `classical.beaufort` aren't included in `--method all` because guessing a multi-character key exhaustively isn't bounded the same way.

**Dictionary attack (`--wordlist`)** — required for authenticated modern encryption, since AES-256/ChaCha20 keys can't be brute-forced by keyspace at all (2^256 possibilities). A wordlist attack only works if the real passphrase is actually in your list — it audits weak/guessable passphrases, it does not break real AES-256 security:

```powershell
sentinelclipy crypto brute-force --method modern.aes256gcm --wordlist common-passwords.txt --text "PASTE_TOKEN" --top 5
sentinelclipy crypto brute-force --method modern.aes256cbc --wordlist common-passwords.txt --text "PASTE_TOKEN" --top 5
sentinelclipy crypto brute-force --method modern.aes256ctrhmac --wordlist common-passwords.txt --text "PASTE_TOKEN" --top 5
sentinelclipy crypto brute-force --method modern.aes256cbchmac --wordlist common-passwords.txt --text "PASTE_TOKEN" --top 5
sentinelclipy crypto brute-force --method modern.chacha20poly1305 --wordlist common-passwords.txt --text "PASTE_TOKEN" --top 5
sentinelclipy crypto brute-force --method modern.fernet --wordlist candidate-keys.txt --text "PASTE_TOKEN" --top 5
sentinelclipy crypto brute-force --method modern.xor --wordlist common-passwords.txt --text "..." --top 5
```

The wordlist is a plain text file, one candidate key/passphrase per line. For `aesgcm`/`aes256gcm`/`aes256ctrhmac`/`aes256cbchmac`/`chacha20poly1305`/`fernet`, a successful decrypt is cryptographically authenticated (the AEAD tag, HMAC, or Fernet signature verified), so a match is reported at score `999` and is guaranteed correct — not just "probably English." `aes256cbc` has no built-in authentication, so matches are still ranked only by the English-likeness heuristic; a wrong key can occasionally produce plausible-looking padding, so double-check the top result.

Use `--contains "some known phrase"` to filter candidates, and `--max-attempts` to cap how much work is done. Only run dictionary attacks against ciphertext you're authorized to test (e.g. auditing your own weak passphrases), not against systems or data you don't own.

## Guided REPL

Start the interactive mode with:

```powershell
sentinelclipy repl
```

On startup it prints a numbered module menu:

- `1` crypto
- `2` jwt
- `3` url
- `4` ip
- `5` ports
- `6` secrets
- `7` file-inspect
- `8` file-hash
- `9` entropy
- `10` password
- `11` headers
- `12` tls
- `13` dns
- `14` timestamp

You can enter a number to start a guided prompt flow, enter a module name like `crypto`, or run full commands directly inside the REPL:

```text
sentinel> 1
sentinel> crypto methods --group modern
sentinel> crypto hash --algorithm oneway.sha256 --text hello
sentinel> 6
```

Inside guided crypto mode, the REPL asks for the action, method, input source (`text` or `file`), the actual text or path, output file, and only the method-specific settings that apply.
## Other Modules

```powershell
sentinelclipy ports 127.0.0.1 --ports common --timeout 0.25
sentinelclipy secrets . --hidden --json
sentinelclipy jwt --text "HEADER.PAYLOAD.SIGNATURE" --json
sentinelclipy url --text "https://example.com/login?token=abc"
sentinelclipy ip 127.0.0.1 --json
sentinelclipy file-inspect .\sentinelclipy.py --hashes sha256,crc32 --indicators
sentinelclipy password generate --length 32 --count 3
sentinelclipy password audit "Password123!" --json
sentinelclipy headers https://example.com
sentinelclipy tls example.com
sentinelclipy dns example.com
sentinelclipy entropy .\sentinelclipy.py
sentinelclipy repl
```

Only run network checks against systems you own or have explicit permission to test.

To build a .exe file, run the following commands:

```sh
python -m pip install pyinstaller
```

```sh
pyinstaller --onefile --name sentinelcli .\sentinelclipy.py
```