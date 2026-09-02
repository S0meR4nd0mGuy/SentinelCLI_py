"""DNS resolution operations."""

from ..network.operations import dns_lookup, resolve_host
from ..auth.operations import DnsAPI

__all__ = ["DnsAPI", "dns_lookup", "resolve_host"]
