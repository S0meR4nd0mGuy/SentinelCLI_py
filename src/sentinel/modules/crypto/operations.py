"""Crypto command implementations."""

from ...core.common import *
from ...core.common import _stdlib_secrets

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

