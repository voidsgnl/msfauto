from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from threading import Event
from time import monotonic, sleep

from ..storage.models import DiscoveryRun, Host, ScopePolicy, Service


class DiscoveryError(ValueError):
    """Raised when discovery data is malformed or outside the active scope."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_nmap(
    workspace: str,
    policy: ScopePolicy,
    output_path: Path,
    timeout: float = 300,
    executable: str = "nmap",
    cancel_event: Event | None = None,
) -> tuple[DiscoveryRun, tuple[Host, ...]]:
    """Run a bounded XML-producing discovery command for the active policy."""
    scanner = shutil.which(executable)
    if scanner is None:
        raise DiscoveryError(f"Scanner executable not found: {executable}")
    if timeout <= 0:
        raise DiscoveryError("Discovery timeout must be greater than zero.")

    targets = tuple(str(item) for item in (*policy.networks, *policy.addresses))
    if not targets:
        raise DiscoveryError("Cannot discover without an authorized target scope.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [scanner, "-n", "-sV", "--version-light", "-oX", str(output_path)]
    if policy.allowed_ports:
        command.extend(["-p", ",".join(str(port) for port in policy.allowed_ports)])
    command.extend(targets)
    started_at = _utc_now()
    deadline = monotonic() + timeout
    with tempfile.TemporaryFile(mode="w+t") as stderr_file:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
            text=True,
        )
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                return (
                    DiscoveryRun(
                        workspace, executable, tuple(command), str(output_path), "cancelled",
                        started_at, _utc_now(), "Discovery cancelled by operator.",
                    ),
                    (),
                )
            if monotonic() >= deadline:
                process.kill()
                process.wait()
                stderr_file.seek(0)
                detail = stderr_file.read().strip()
                return (
                    DiscoveryRun(
                        workspace, executable, tuple(command), str(output_path), "timed_out",
                        started_at, _utc_now(), detail or "Discovery timed out.",
                    ),
                    (),
                )
            sleep(0.1)

        stderr_file.seek(0)
        stderr = stderr_file.read().strip()
        if process.returncode != 0:
            return (
                DiscoveryRun(
                    workspace, executable, tuple(command), str(output_path), "failed",
                    started_at, _utc_now(), stderr,
                ),
                (),
            )
    hosts = parse_nmap_xml(output_path, policy)
    return (
        DiscoveryRun(
            workspace, executable, tuple(command), str(output_path), "completed",
            started_at, _utc_now(),
        ),
        hosts,
    )


def parse_nmap_xml(
    path: Path,
    policy: ScopePolicy,
    source: str = "nmap",
    observed_at: str | None = None,
) -> tuple[Host, ...]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise DiscoveryError(f"Unable to read discovery XML: {path}") from exc

    hosts: list[Host] = []
    observation_time = observed_at or _utc_now()
    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        if address_node is None or not address_node.get("addr"):
            continue
        try:
            address = ip_address(address_node.get("addr", ""))
        except ValueError as exc:
            raise DiscoveryError("Discovery XML contains an invalid IP address.") from exc
        if not policy.permits_address(address):
            raise DiscoveryError(f"Discovery result is outside the configured scope: {address}")

        status_node = host_node.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        hostname_node = host_node.find("./hostnames/hostname")
        hostname = hostname_node.get("name", "") if hostname_node is not None else ""

        services: list[Service] = []
        for port_node in host_node.findall("./ports/port"):
            try:
                port = int(port_node.get("portid", ""))
            except ValueError as exc:
                raise DiscoveryError("Discovery XML contains an invalid port.") from exc
            if not policy.permits_port(port):
                continue
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            confidence_text = service_node.get("conf", "0") if service_node is not None else "0"
            try:
                confidence = int(confidence_text)
            except ValueError as exc:
                raise DiscoveryError("Discovery XML contains an invalid service confidence.") from exc
            if not 0 <= confidence <= 10:
                raise DiscoveryError("Discovery XML service confidence must be between 0 and 10.")
            services.append(
                Service(
                    port=port,
                    protocol=port_node.get("protocol", ""),
                    state=state_node.get("state", "unknown") if state_node is not None else "unknown",
                    name=service_node.get("name", "") if service_node is not None else "",
                    product=service_node.get("product", "") if service_node is not None else "",
                    version=service_node.get("version", "") if service_node is not None else "",
                    method=service_node.get("method", "unknown") if service_node is not None else "unknown",
                    confidence=confidence,
                    extra_info=service_node.get("extrainfo", "") if service_node is not None else "",
                    tunnel=service_node.get("tunnel", "") if service_node is not None else "",
                    cpes=tuple(node.text or "" for node in service_node.findall("cpe") if node.text)
                    if service_node is not None else (),
                    source=source,
                    observed_at=observation_time,
                )
            )
        hosts.append(Host(address=address, status=status, hostname=hostname, services=tuple(services)))
    return tuple(hosts)
