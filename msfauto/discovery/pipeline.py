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
from typing import TYPE_CHECKING

from ..storage.models import DiscoveryRun, Host, ScopePolicy, Service

if TYPE_CHECKING:
    from ..integrations.metasploit import MetasploitClient


class DiscoveryError(ValueError):
    """Raised when discovery data is malformed or outside the active scope."""


# The fast profile covers the most common web entry points plus a small
# set of high-value supporting services. Standard adds common alternate
# web, mail, remote-access, directory, and database ports. Full is -p-.
QUICK_TCP_PORTS = (
    22, 25, 53, 80, 443, 445, 465, 587, 3000, 3306, 5000, 5432,
    8000, 8080, 8443,
)
STANDARD_TCP_PORTS = tuple(sorted({
    *QUICK_TCP_PORTS,
    20, 21, 23, 110, 111, 135, 139, 143, 389, 636, 993, 995,
    1433, 1521, 2049, 2375, 2376, 3389, 4000, 5001, 5900,
    5985, 5986, 6379, 7001, 7002, 8008, 8081, 8082, 8888,
    9000, 9090, 9200, 9443, 10000, 11211, 27017,
}))
SCAN_PROFILES = ("quick", "standard", "full")


def _ports_for_profile(policy: ScopePolicy, profile: str) -> tuple[int, ...] | None:
    if profile not in SCAN_PROFILES:
        raise DiscoveryError(
            f"Unknown scan profile: {profile}. Choose quick, standard, or full."
        )
    if policy.allowed_ports:
        # An explicit workspace port allowlist is the operator's selected
        # assessment surface and takes precedence over profile defaults.
        return tuple(policy.allowed_ports)
    if profile == "full":
        return None
    return QUICK_TCP_PORTS if profile == "quick" else STANDARD_TCP_PORTS


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_nmap(
    workspace: str,
    policy: ScopePolicy,
    output_path: Path,
    timeout: float = 300,
    executable: str = "nmap",
    cancel_event: Event | None = None,
    scan_profile: str = "standard",
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
    selected_ports = _ports_for_profile(policy, scan_profile)
    command = [scanner, "-n", "-Pn", "-sV", "--version-light", "-oX", str(output_path)]
    if selected_ports is None:
        command.append("-p-")
    else:
        command.extend(["-p", ",".join(str(port) for port in selected_ports)])
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
                output_path.unlink(missing_ok=True)
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
                output_path.unlink(missing_ok=True)
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
            output_path.unlink(missing_ok=True)
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



def run_metasploit_db_nmap(
    workspace: str,
    policy: ScopePolicy,
    client: MetasploitClient,
    timeout: float = 300,
    scan_profile: str = "standard",
) -> tuple[DiscoveryRun, tuple[Host, ...]]:
    """Discover through Metasploit's db_nmap and read normalized DB inventory."""
    if timeout <= 0:
        raise DiscoveryError("Discovery timeout must be greater than zero.")
    targets = tuple(str(item) for item in (*policy.networks, *policy.addresses))
    if not targets:
        raise DiscoveryError("Cannot discover without an authorized target scope.")
    selected_ports = _ports_for_profile(policy, scan_profile)
    port_spec = "-" if selected_ports is None else ",".join(map(str, selected_ports))
    command = (
        "db_nmap", "-n", "-Pn", "-sV", "--version-light",
        "-p-" if port_spec == "-" else f"-p {port_spec}", *targets,
    )
    started_at = _utc_now()
    output = client.run_db_nmap(workspace, targets, port_spec, timeout=timeout)
    host_records = client.database_hosts(workspace, targets)
    service_records = client.database_services(workspace, targets)

    normalized_hosts: dict[str, dict[str, object]] = {}
    for record in host_records:
        address_text = record.get("address")
        if not isinstance(address_text, str):
            continue
        try:
            address = ip_address(address_text)
        except ValueError:
            continue
        if policy.permits_address(address):
            normalized_hosts[str(address)] = record

    services_by_host: dict[str, list[Service]] = {}
    for record in service_records:
        address_text = record.get("host")
        if not isinstance(address_text, str):
            continue
        try:
            address = ip_address(address_text)
            port = int(record.get("port", 0))
        except (ValueError, TypeError):
            continue
        if not policy.permits_address(address) or not policy.permits_port(port):
            continue
        if str(record.get("state", "")).casefold() != "open":
            continue
        protocol = str(record.get("proto") or "tcp")
        info = str(record.get("info") or "")
        services_by_host.setdefault(str(address), []).append(Service(
            port=port,
            protocol=protocol,
            state="open",
            name=str(record.get("name") or ""),
            extra_info=info,
            method="metasploit-db_nmap",
            confidence=5,
            source="metasploit-db",
            observed_at=_utc_now(),
        ))
        normalized_hosts.setdefault(str(address), {"address": str(address), "state": "alive"})

    hosts: list[Host] = []
    for address_text, record in normalized_hosts.items():
        try:
            address = ip_address(address_text)
        except ValueError:
            continue
        hosts.append(Host(
            address=address,
            status=str(record.get("state") or "unknown"),
            hostname=str(record.get("name") or ""),
            services=tuple(sorted(
                services_by_host.get(address_text, []),
                key=lambda service: (service.port, service.protocol),
            )),
        ))
    hosts.sort(key=lambda host: str(host.address))
    run = DiscoveryRun(
        workspace=workspace,
        scanner="metasploit:db_nmap",
        command=command,
        output_path="",
        status="completed",
        started_at=started_at,
        finished_at=_utc_now(),
        error="",
    )
    # Keep command output available to the caller for progress/audit diagnostics.
    if not output.strip():
        return run, tuple(hosts)
    return run, tuple(hosts)


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
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            # The current inventory and service-enumeration inputs represent
            # exposed services only. Closed/filtered ports remain in the raw
            # Nmap XML artifact and historical scan provenance.
            if state != "open":
                continue
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
                    state=state,
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
