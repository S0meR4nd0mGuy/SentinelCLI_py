"""Compatibility namespace for the split SentinelCLI implementation."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
	sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
	__package__ = "sentinel.core"

from ..modules.auth import operations as _auth_operations
from ..modules.auth.operations import *
from ..modules.crypto import operations as _crypto_operations
from ..modules.crypto.operations import *
from ..modules.dns import operations as _dns_operations
from ..modules.dns.operations import *
from ..modules.files import operations as _files_operations
from ..modules.files.operations import *
from ..modules.network import operations as _network_operations
from ..modules.network.operations import *
from ..modules.secrets import operations as _secrets_operations
from ..modules.secrets.operations import *
from ..modules.tls.operations import *
from ..modules.utilities import operations as _utilities_operations
from ..modules.utilities.operations import *
from . import common as _common
from .common import *

_implementation_namespace = globals()
for _module in (
	_auth_operations,
	_crypto_operations,
	_dns_operations,
	_files_operations,
	_network_operations,
	_secrets_operations,
	_utilities_operations,
):
	_implementation_namespace.update({
		_name: _value for _name, _value in vars(_module).items()
		if not _name.startswith("__")
	})
for _module in (_common, _auth_operations, _crypto_operations, _dns_operations, _files_operations, _network_operations, _secrets_operations, _utilities_operations):
	_module.__dict__.update({
		_name: _value for _name, _value in _implementation_namespace.items()
		if not _name.startswith("__")
	})

from .guided_repl import SentinelRepl
from .parser import add_text_file_args, build_parser
from .launcher import _run_operator_repl, _run_textual_app, main

crypto = CryptoAPI()
ports = PortsAPI()
ports_api = ports
secrets_api = SecretsAPI()
secrets = secrets_api
secrets_module = secrets_api
secrets_scan_api = secrets_api
secrets_tools = secrets_api
file_hash_api = FileHashAPI()
entropy_api = EntropyAPI()
entropy_tools = entropy_api
password = PasswordAPI()
password_api = password
headers = HeadersAPI()
tls = TlsAPI()
dns = DnsAPI()
jwt = JwtAPI()
url = UrlAPI()
ip = IpAPI()
file_inspect_api = FileInspectAPI()
file_inspect_module = file_inspect_api
timestamp = TimestampAPI()
network = NetworkAPI()
files = FilesAPI()
auth = AuthAPI()
utils = UtilsAPI()


