import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sentinelcli as s


class ToolkitTests(unittest.TestCase):
    def test_caesar_round_trip(self):
        encrypted = s.caesar_transform("Attack at dawn", 5)
        self.assertEqual(encrypted, "Fyyfhp fy ifbs")
        self.assertEqual(s.caesar_transform(encrypted, 5, decrypt=True), "Attack at dawn")

    def test_vigenere_round_trip(self):
        encrypted = s.vigenere_transform("Defend the east wall", "lemon")
        self.assertEqual(s.vigenere_transform(encrypted, "lemon", decrypt=True), "Defend the east wall")

    def test_xor_round_trip(self):
        data = b"secret"
        encrypted = s.xor_bytes(data, "key")
        self.assertEqual(s.xor_bytes(encrypted, "key"), data)

    def test_general_encodings_round_trip(self):
        for method in ["general.base64", "general.base64url", "general.base32", "general.hex", "general.ascii85", "general.base85", "general.binary", "general.octal", "general.decimal"]:
            encoded = s.encode_data(b"hello", method)
            self.assertEqual(s.decode_data(encoded, method), b"hello")

    def test_classical_round_trips(self):
        self.assertEqual(s.atbash_transform(s.atbash_transform("Attack")), "Attack")
        affine = s.affine_transform("Attack", 5, 8)
        self.assertEqual(s.affine_transform(affine, 5, 8, decrypt=True), "Attack")
        rail = s.railfence_encrypt("attackatdawn", 3)
        self.assertEqual(s.railfence_decrypt(rail, 3), "attackatdawn")
        bacon = s.bacon_encrypt("abc")
        self.assertEqual(s.bacon_decrypt(bacon), "abc")

    def test_modern_aead_round_trips(self):
        for method in ["aesgcm", "chacha20poly1305", "aes256ctrhmac", "aes256cbchmac"]:
            encrypted = s.modern_encrypt("secret message", method, "passphrase", "base64")
            self.assertEqual(s.modern_decrypt(encrypted, method, "passphrase", "base64"), "secret message")

    def test_kdf_and_constant_time_compare(self):
        salt = b"saltysalt"
        left = s.derive_password_key("passphrase", salt, "pbkdf2-sha256", 32, 1000)
        right = s.derive_password_key("passphrase", salt, "pbkdf2-sha256", 32, 1000)
        self.assertEqual(left, right)
        args = type("Args", (), {"left": "abc", "left_file": None, "right": "abc", "right_file": None, "json": False})()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(s.crypto_compare(args), 0)
        self.assertIn("equal", out.getvalue())

    def test_identify_hash_and_fernet_shapes(self):
        sha256 = "a" * 64
        methods = {candidate["method"] for candidate in s.identify_text(sha256)}
        self.assertIn("general.hex", methods)
        self.assertIn("oneway.sha256/sha3-256/blake2s", methods)
        fernet_like = "gAAAA" + "A" * 80
        self.assertIn("modern.fernet", {candidate["method"] for candidate in s.identify_text(fernet_like)})

    def test_grouped_method_validation_suggests_correct_group(self):
        with self.assertRaisesRegex(s.ToolkitError, "classical.caesar"):
            s.split_method("general.caesar")

    def test_repl_reprompts_invalid_grouped_method(self):
        repl = s.SentinelRepl(s.build_parser())
        answers = iter(["1", "general.caesar", "classical.caesar", "1", "Hi to PRT!", "", "8"])
        with mock.patch("builtins.input", lambda _: next(answers)):
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                repl.default("1")
        self.assertIn("Pq bw XZB!", out.getvalue())
        self.assertIn("classical.caesar", err.getvalue())

    def test_repl_direct_command(self):
        repl = s.SentinelRepl(s.build_parser())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            repl.default("crypto encrypt --method general.base64 --text hello")
        self.assertIn("aGVsbG8=", out.getvalue())

    def test_repl_number_guided_crypto_hash(self):
        repl = s.SentinelRepl(s.build_parser())
        answers = iter(["3", "oneway.sha256", "1", "hello"])
        with mock.patch("builtins.input", lambda _: next(answers)):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                repl.default("1")
        self.assertIn("2cf24dba5fb0a30e", out.getvalue())


    def test_repl_guided_crypto_encrypt_text_source(self):
        repl = s.SentinelRepl(s.build_parser())
        answers = iter(["1", "base64", "1", "hello", ""])
        with mock.patch("builtins.input", lambda _: next(answers)):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                repl.default("crypto")
        self.assertIn("aGVsbG8=", out.getvalue())

    def test_repl_number_guided_password_audit(self):
        repl = s.SentinelRepl(s.build_parser())
        answers = iter(["2", "Password123!", "y"])
        with mock.patch("builtins.input", lambda _: next(answers)):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                repl.default("10")
        self.assertIn('"verdict"', out.getvalue())

    def test_parse_ports(self):
        self.assertEqual(s.parse_ports("22,80-82"), [22, 80, 81, 82])

    def test_jwt_decode_flags_unsigned_token(self):
        header = s.encode_data(b'{"alg":"none","typ":"JWT"}', "general.base64url")
        payload = s.encode_data(b'{"sub":"123"}', "general.base64url")
        token = f"{header}.{payload}."
        args = type("Args", (), {"text": token, "file": None, "json": True})()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(s.jwt_decode(args), 0)
        self.assertIn("JWT uses no signing algorithm", out.getvalue())

    def test_public_module_api_and_jwt_structure(self):
        self.assertTrue(hasattr(s, "crypto"))
        self.assertTrue(hasattr(s, "jwt"))
        self.assertTrue(hasattr(s, "file_hash"))
        self.assertTrue(hasattr(s, "file_inspect"))
        self.assertTrue(hasattr(s, "entropy"))
        self.assertTrue(hasattr(s, "secrets"))
        self.assertEqual(s.crypto.encode("hello", "general.base64"), "aGVsbG8=")
        self.assertEqual(s.crypto.decode("aGVsbG8=", "general.base64"), "hello")

        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
        result = s.decode_jwt_token(token)
        self.assertEqual(set(result.keys()), {"header", "payload", "signature_present", "timeline", "warnings", "parts"})
        self.assertEqual(result["parts"], ["eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", "eyJzdWIiOiIxMjMifQ", ""])

    def test_url_and_ip_triage(self):
        result = s.analyze_url_value("http://127.0.0.1/login?token=abc")
        self.assertIn("plain HTTP URL", result["warnings"])
        self.assertTrue(any("sensitive-looking" in warning for warning in result["warnings"]))
        args = type("Args", (), {"address": "127.0.0.1", "json": True})()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(s.ip_info(args), 0)
        self.assertIn('"is_loopback": true', out.getvalue())

    def test_file_inspect_detects_indicators(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("callback http://example.com/a and 8.8.8.8\n", encoding="utf-8")
            args = type("Args", (), {
                "file": str(path),
                "hashes": "sha256,crc32",
                "indicators": True,
                "scan_bytes": 1024,
                "indicator_limit": 10,
                "json": True,
            })()
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(s.file_inspect(args), 0)
            output = out.getvalue()
            self.assertIn("example.com", output)
            self.assertIn("8.8.8.8", output)

    def test_secret_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.txt"
            path.write_text("api_key = \"1234567890abcdef\"\n", encoding="utf-8")
            args = type("Args", (), {
                "path": str(path),
                "hidden": False,
                "max_size": 1024,
                "reveal": False,
                "fail_on_findings": True,
                "json": True,
            })()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(s.secrets_scan(args), 1)


if __name__ == "__main__":
    unittest.main()
