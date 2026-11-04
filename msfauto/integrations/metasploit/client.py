from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from time import monotonic, sleep
from typing import Any, Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen


class MetasploitError(RuntimeError):
    """Raised when the local Metasploit RPC service cannot answer safely."""


def _normalize_msgpack_value(value: Any) -> Any:
    """Decode MessagePack binary strings used by Metasploit as UTF-8 text."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value
    if isinstance(value, dict):
        return {
            _normalize_msgpack_value(key): _normalize_msgpack_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_msgpack_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_normalize_msgpack_value(item) for item in value)
    return value


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
        decoded = _normalize_msgpack_value(decoded)
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

    def _console_command(self, command: str, timeout: float = 300.0) -> str:
        """Run one bounded command in a temporary Metasploit RPC console."""
        if not command or "\\n" in command or "\\r" in command:
            raise MetasploitError("A single-line Metasploit console command is required.")
        if timeout <= 0:
            raise MetasploitError("Metasploit console timeout must be positive.")
        created = self._request("console.create")
        console_id = created.get("id")
        if not isinstance(console_id, (str, int)):
            raise MetasploitError("Metasploit did not return a valid console identifier.")
        console_id = str(console_id)
        output: list[str] = []
        total_bytes = 0
        deadline = monotonic() + timeout
        try:
            # Drain the initial banner before submitting the command.
            self._request("console.read", console_id)
            written = self._request("console.write", console_id, command + "\\n")
            if not isinstance(written.get("wrote"), int) or written["wrote"] <= 0:
                raise MetasploitError("Metasploit did not accept the console command.")
            while monotonic() < deadline:
                response = self._request("console.read", console_id)
                chunk = response.get("data", "")
                if not isinstance(chunk, str):
                    raise MetasploitError("Metasploit console returned invalid output.")
                total_bytes += len(chunk.encode("utf-8"))
                if total_bytes > 4_194_304:
                    raise MetasploitError("Metasploit console output exceeded the 4 MB limit.")
                if chunk:
                    output.append(chunk)
                if response.get("busy") is False:
                    return "".join(output)
                sleep(0.1)
            raise MetasploitError(f"Metasploit command timed out after {timeout:g} seconds.")
        finally:
            self._request("console.destroy", console_id)

    def run_db_nmap(
        self,
        workspace: str,
        targets: tuple[str, ...],
        port_spec: str,
        timeout: float = 300.0,
    ) -> str:
        """Run db_nmap in Metasploit and persist results in its selected workspace."""
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", workspace):
            raise MetasploitError("Metasploit workspace name contains unsupported characters.")
        if not targets:
            raise MetasploitError("At least one authorized IP or network target is required.")
        normalized_targets: list[str] = []
        for target in targets:
            try:
                normalized_targets.append(str(ipaddress.ip_network(target, strict=False)))
            except ValueError as exc:
                raise MetasploitError(f"db_nmap only accepts validated IP/CIDR targets: {target}") from exc
        if port_spec != "-" and not re.fullmatch(r"[0-9,\-]+", port_spec):
            raise MetasploitError("Invalid db_nmap port selection.")
        if port_spec != "-":
            for item in port_spec.split(","):
                bounds = item.split("-")
                if len(bounds) > 2 or any(not part.isdecimal() for part in bounds):
                    raise MetasploitError("Invalid db_nmap port range.")
                low = int(bounds[0])
                high = int(bounds[-1])
                if not 1 <= low <= high <= 65535:
                    raise MetasploitError("db_nmap ports must be between 1 and 65535.")
        # Creating a framework console initializes the framework database
        # connection on Metasploit builds that lazily load the DB subsystem.
        self._console_command("version", timeout=min(timeout, 10.0))
        added = self._request("db.add_workspace", workspace)
        if added.get("result") not in {"success", "failed"}:
            raise MetasploitError("Metasploit returned an invalid workspace creation response.")
        selected = self._request("db.set_workspace", workspace)
        if selected.get("result") != "success":
            raise MetasploitError(f"Unable to select Metasploit database workspace: {workspace}")
        port_args = "-p-" if port_spec == "-" else f"-p {port_spec}"
        command = " ".join((
            "db_nmap", "-n", "-Pn", "-sV", "--version-light",
            port_args, *normalized_targets,
        ))
        return self._console_command(command, timeout=timeout)

    def database_hosts(
        self, workspace: str, addresses: tuple[str, ...] = (), limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 10000:
            raise MetasploitError("Metasploit host query limit must be between 1 and 10000.")
        response = self._request("db.hosts", {
            "workspace": workspace, "addresses": list(addresses), "limit": limit,
        })
        records = response.get("hosts", [])
        if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
            raise MetasploitError("Metasploit returned invalid host inventory data.")
        return records

    def database_services(
        self, workspace: str, addresses: tuple[str, ...] = (), limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 10000:
            raise MetasploitError("Metasploit service query limit must be between 1 and 10000.")
        response = self._request("db.services", {
            "workspace": workspace, "addresses": list(addresses),
            "only_up": True, "limit": limit,
        })
        records = response.get("services", [])
        if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
            raise MetasploitError("Metasploit returned invalid service inventory data.")
        return records

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

    def job_list(self) -> dict[int, str]:
        """Return active framework jobs as numeric IDs and their descriptions."""
        response = self._request("job.list")
        jobs = response.get("jobs", response)
        if not isinstance(jobs, dict):
            raise MetasploitError("Metasploit RPC returned an invalid job list.")
        normalized: dict[int, str] = {}
        for raw_id, description in jobs.items():
            try:
                job_id = int(raw_id)
            except (TypeError, ValueError) as exc:
                raise MetasploitError("Metasploit RPC returned an invalid job identifier.") from exc
            if job_id < 0 or not isinstance(description, str):
                raise MetasploitError("Metasploit RPC returned invalid job metadata.")
            normalized[job_id] = description
        return normalized

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
