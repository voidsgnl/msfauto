"""Compatibility exports; Metasploit RPC lives in :mod:`msfauto.integrations.metasploit`."""
from .integrations.metasploit import MetasploitClient, MetasploitConfig, MetasploitError, MsgpackHttpTransport, RpcTransport, describe_module

__all__ = ["MetasploitClient", "MetasploitConfig", "MetasploitError", "MsgpackHttpTransport", "RpcTransport", "describe_module"]
