from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Union

IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ScopePolicy:
    """Explicit allowlist for safe, authorized assessment operations."""

    networks: tuple[IPNetwork, ...] = ()
    addresses: tuple[IPAddress, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    profile: str = "safe"

    def permits_address(self, address: IPAddress) -> bool:
        return address in self.addresses or any(address in network for network in self.networks)

    def permits_port(self, port: int) -> bool:
        return not self.allowed_ports or port in self.allowed_ports

    @property
    def allows_dangerous_actions(self) -> bool:
        return self.profile == "dangerous-actions"


@dataclass
class Workspace:
    name: str
    policy: ScopePolicy = field(default_factory=ScopePolicy)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass(frozen=True)
class Host:
    address: IPAddress
    status: str
    hostname: str = ""
    services: tuple[Service, ...] = ()


@dataclass(frozen=True)
class DiscoveryRun:
    workspace: str
    scanner: str
    command: tuple[str, ...]
    output_path: str
    status: str
    started_at: str
    finished_at: str
    error: str = ""


@dataclass(frozen=True)
class ModuleMetadata:
    workspace: str
    module_type: str
    module_name: str
    metadata: dict[str, object]
    options: dict[str, object]
    source: str
    fetched_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Recommendation:
    target: str
    port: int
    protocol: str
    module_type: str
    module_name: str
    confidence: int
    reason: str
    risk: str = "non-invasive"


@dataclass(frozen=True)
class AssessmentPlan:
    workspace: str
    recommendations: tuple[Recommendation, ...]
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class JobEvent:
    job_id: str
    timestamp: str
    level: str
    message: str


@dataclass(frozen=True)
class CheckJob:
    job_id: str
    workspace: str
    target: str
    port: int
    protocol: str
    module_name: str
    status: str
    started_at: str
    finished_at: str = ""
    error: str = ""


@dataclass(frozen=True)
class AssessmentRun:
    run_id: str
    workspace: str
    status: str
    stage: str
    started_at: str
    updated_at: str
    finished_at: str = ""
    error: str = ""


@dataclass(frozen=True)
class AssessmentEvent:
    run_id: str
    timestamp: str
    stage: str
    level: str
    message: str
