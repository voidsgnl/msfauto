from __future__ import annotations

from dataclasses import dataclass, field

from .base import IPAddress, IPNetwork, utc_now


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
