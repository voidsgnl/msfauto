"""Metasploit RPC integration."""
from .client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MsgpackHttpTransport,
    RpcTransport,
    describe_module,
)

__all__ = [
    "MetasploitClient",
    "MetasploitConfig",
    "MetasploitError",
    "MsgpackHttpTransport",
    "RpcTransport",
    "describe_module",
]
