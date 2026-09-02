"""DNS resolution and host lookup operations."""

from .operations import DnsAPI, dns_lookup, resolve_host

__all__ = [name for name in globals() if not name.startswith("_")]