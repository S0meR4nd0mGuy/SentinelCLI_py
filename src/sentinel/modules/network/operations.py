"""Network command implementations."""

from ...core.common import *
from ...core.common import _stdlib_secrets

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
@dataclass
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
class JwtAPI:
    def decode(self, token: str) -> dict[str, object]:
        return decode_jwt_token(token)
class UrlAPI:
    def analyze(self, value: str) -> dict[str, object]:
        return analyze_url_value(value)

    def analyze_many(self, values: Iterable[str]) -> list[dict[str, object]]:
        return [analyze_url_value(value) for value in values]
class NetworkAPI:
    def scan(self, host: str, ports: str = "common", timeout: float = 0.5, workers: int = 100, banner: bool = False, show_closed: bool = False) -> list[dict[str, object]]:
        return ports_api.scan(host, ports=ports, timeout=timeout, workers=workers, banner=banner, show_closed=show_closed)

    def resolve(self, host: str) -> list[str]:
        return dns.lookup(host)

    def ip(self, address: str) -> dict[str, object]:
        return ip.info(address)

    def url(self, value: str) -> dict[str, object]:
        return url.analyze(value)

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


class IpAPI:
    def info(self, address: str) -> dict[str, object]:
        return inspect_ip_address(address)

