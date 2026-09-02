"""Auth command implementations."""

from ...core.common import *
from ...core.common import _stdlib_secrets
from ..utilities.operations import audit_password, generate_passwords

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
class AuthAPI:
    def jwt(self, token: str) -> dict[str, object]:
        return jwt.decode(token)

    def password_audit(self, password: str) -> dict[str, object]:
        return password_api.audit(password)
