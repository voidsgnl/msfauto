from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen

class MetasploitError(RuntimeError):
    """Raised when the local Metasploit RPC service cannot answer safely."""


class RpcTransport(Protocol):
    def request(self, method: str, arguments: tuple[str, ...]) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class MetasploitConfig:
    url: str = "http://127.0.0.1:55553/api/1.0"
    username: str = ""
    password: str = ""
    timeout: float = 10.0


class MsgpackHttpTransport:
    def __init__(self, config: MetasploitConfig) -> None:
        self.config = config

    def request(self, method: str, arguments: tuple[str, ...]) -> dict[str, Any]:
        try:
            import msgpack
        except ImportError as exc:
            raise MetasploitError("The msgpack dependency is required for Metasploit RPC.") from exc
        payload = msgpack.packb([method, *arguments], use_bin_type=True)
        request = Request(
            self.config.url,
            data=payload,
            headers={"Content-Type": "binary/message-pack"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                decoded = msgpack.unpackb(response.read(), raw=False)
        except (OSError, URLError, TimeoutError) as exc:
            raise MetasploitError(f"Unable to connect to Metasploit RPC at {self.config.url}") from exc
        if not isinstance(decoded, dict):
            raise MetasploitError("Metasploit RPC returned an invalid response.")
        if "error" in decoded and decoded["error"]:
            message = decoded.get("error_message", "Metasploit RPC request failed")
            raise MetasploitError(str(message))
        return decoded


class MetasploitClient:
    """Read-only module metadata client; execution methods are intentionally absent."""

    def __init__(self, transport: RpcTransport, username: str = "", password: str = "") -> None:
        self.transport = transport
        self.token = ""
        if username or password:
            self.authenticate(username, password)

    def authenticate(self, username: str, password: str) -> None:
        response = self.transport.request("auth.login", (username, password))
        token = response.get("token")
        if not isinstance(token, str) or not token:
            raise MetasploitError("Metasploit RPC authentication returned no token.")
        self.token = token

    def _request(self, method: str, *arguments: str) -> dict[str, Any]:
        request_arguments = ((self.token,) if self.token else ()) + arguments
        return self.transport.request(method, request_arguments)

    def search_modules(self, query: str) -> list[dict[str, Any]]:
        if not query.strip():
            raise MetasploitError("Module search query cannot be empty.")
        response = self._request("module.search", query)
        modules = response.get("modules", [])
        if not isinstance(modules, list):
            raise MetasploitError("Metasploit RPC returned invalid module search data.")
        return [module for module in modules if isinstance(module, dict)]

    def module_info(self, module_type: str, module_name: str) -> dict[str, Any]:
        if not module_type or not module_name:
            raise MetasploitError("Module type and name are required.")
        response = self._request("module.info", module_type, module_name)
        if not isinstance(response, dict):
            raise MetasploitError("Metasploit RPC returned invalid module metadata.")
        return response

    def module_options(self, module_type: str, module_name: str) -> dict[str, Any]:
        if not module_type or not module_name:
            raise MetasploitError("Module type and name are required.")
        response = self._request("module.options", module_type, module_name)
        options = response.get("options", response)
        if not isinstance(options, dict):
            raise MetasploitError("Metasploit RPC returned invalid module options.")
        return options

    def fetch_module_metadata(self, module_type: str, module_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.module_info(module_type, module_name), self.module_options(module_type, module_name)


def describe_module(metadata: dict[str, Any]) -> str:
    """Return a stable, human-readable summary for the TUI and audit log."""
    fields = {
        "name": metadata.get("name", ""),
        "description": metadata.get("description", ""),
        "rank": metadata.get("rank", ""),
    }
    return json.dumps(fields, sort_keys=True)
