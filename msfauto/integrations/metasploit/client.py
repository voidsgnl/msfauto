from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen


class MetasploitError(RuntimeError):
    """Raised when the local Metasploit RPC service cannot answer safely."""


class RpcTransport(Protocol):
    def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
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

    def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
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
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise MetasploitError("Metasploit RPC response exceeded the 1 MB limit.")
                decoded = msgpack.unpackb(raw, raw=False)
        except (OSError, URLError, TimeoutError) as exc:
            raise MetasploitError(
                f"Unable to connect to Metasploit RPC at {self.config.url}"
            ) from exc
        except (ValueError, msgpack.exceptions.UnpackException) as exc:
            raise MetasploitError("Metasploit RPC returned an invalid MessagePack response.") from exc
        if not isinstance(decoded, dict):
            raise MetasploitError("Metasploit RPC returned an invalid response.")
        if decoded.get("error"):
            message = decoded.get("error_message", "Metasploit RPC request failed")
            raise MetasploitError(str(message))
        return decoded


class MetasploitClient:
    """Metasploit MessagePack RPC client for metadata and adapter primitives."""

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

    def _request(self, method: str, *arguments: Any) -> dict[str, Any]:
        request_arguments = ((self.token,) if self.token else ()) + arguments
        return self.transport.request(method, request_arguments)

    def exploit_modules(self) -> list[str]:
        """Return the connected framework's exploit module reference names."""
        response = self._request("module.exploits")
        modules = response.get("modules", [])
        if not isinstance(modules, list) or any(
            not isinstance(module, str) or not module.strip() for module in modules
        ):
            raise MetasploitError("Metasploit RPC returned invalid exploit catalog data.")
        return list(dict.fromkeys(modules))

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

    def fetch_module_metadata(
        self, module_type: str, module_name: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.module_info(module_type, module_name), self.module_options(module_type, module_name)

    def execute_auxiliary(
        self, module_name: str, options: dict[str, str | int | float | bool | None]
    ) -> tuple[int, str]:
        """Dispatch an auxiliary module with a flat scalar datastore."""
        if not module_name or module_name.startswith("auxiliary/"):
            raise MetasploitError("Auxiliary module name must be a non-prefixed module path.")
        if not isinstance(options, dict) or any(
            not isinstance(value, (str, int, float, bool)) and value is not None
            for value in options.values()
        ):
            raise MetasploitError("Metasploit module options must contain scalar values.")
        response = self._request("module.execute", "auxiliary", module_name, options)
        job_id = response.get("job_id")
        run_uuid = response.get("uuid")
        if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 0:
            raise MetasploitError("Metasploit did not return a valid job identifier.")
        if not isinstance(run_uuid, str) or not run_uuid:
            raise MetasploitError("Metasploit did not return a module execution UUID.")
        return job_id, run_uuid

    def _execute_exploit(
        self, module_name: str, options: dict[str, str | int | float | bool | None]
    ) -> tuple[int, str]:
        """Dispatch one exploit module using a caller-constructed, scalar datastore."""
        if not module_name or module_name.startswith("exploit/"):
            raise MetasploitError("Exploit module name must be a non-prefixed module path.")
        if not isinstance(options, dict) or any(
            not isinstance(value, (str, int, float, bool)) and value is not None
            for value in options.values()
        ):
            raise MetasploitError("Metasploit module options must contain scalar values.")
        response = self._request("module.execute", "exploit", module_name, options)
        job_id = response.get("job_id")
        run_uuid = response.get("uuid")
        if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 0:
            raise MetasploitError("Metasploit did not return a valid job identifier.")
        if not isinstance(run_uuid, str) or not run_uuid:
            raise MetasploitError("Metasploit did not return a module execution UUID.")
        return job_id, run_uuid

    def module_results(self, run_uuid: str) -> dict[str, Any]:
        if not run_uuid:
            raise MetasploitError("A Metasploit module execution UUID is required.")
        response = self._request("module.results", run_uuid)
        if not isinstance(response.get("status"), str):
            raise MetasploitError("Metasploit returned an invalid module result.")
        return response

    def stop_job(self, job_id: int) -> None:
        if isinstance(job_id, bool) or job_id < 0:
            raise MetasploitError("A valid Metasploit job identifier is required.")
        response = self._request("job.stop", str(job_id))
        if response.get("result") != "success":
            raise MetasploitError("Metasploit did not confirm that the job was stopped.")


def describe_module(metadata: dict[str, Any]) -> str:
    """Return a stable, human-readable summary for the TUI and audit log."""
    fields = {
        "name": metadata.get("name", ""),
        "description": metadata.get("description", ""),
        "rank": metadata.get("rank", ""),
    }
    return json.dumps(fields, sort_keys=True)
