from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Iterable

from ..models import IPAddress, IPNetwork, ScopePolicy

PROFILES = ("safe", "dangerous-actions")


class ScopeError(ValueError):
    """Raised when an assessment scope is invalid or unsafe."""


def parse_targets(values: Iterable[str]) -> tuple[tuple[IPNetwork, ...], tuple[IPAddress, ...]]:
    networks: list[IPNetwork] = []
    addresses: list[IPAddress] = []
    for raw_value in values:
        value = raw_value.strip()
        if not value:
            continue
        try:
            if "/" in value:
                networks.append(ip_network(value, strict=False))
            else:
                addresses.append(ip_address(value))
        except ValueError as exc:
            raise ScopeError(f"Invalid target: {value}") from exc
    if not networks and not addresses:
        raise ScopeError("At least one IP address or network is required.")
    return tuple(networks), tuple(addresses)


def parse_ports(value: str) -> tuple[int, ...]:
    if not value.strip():
        return ()
    ports: set[int] = set()
    for item in value.split(","):
        try:
            port = int(item.strip())
        except ValueError as exc:
            raise ScopeError(f"Invalid port: {item.strip()}") from exc
        if not 1 <= port <= 65535:
            raise ScopeError(f"Port must be between 1 and 65535: {port}")
        ports.add(port)
    return tuple(sorted(ports))


def build_policy(targets: Iterable[str], ports: str = "", profile: str = "safe") -> ScopePolicy:
    if profile not in PROFILES:
        raise ScopeError(f"Unknown profile: {profile}. Choose safe or dangerous-actions.")
    networks, addresses = parse_targets(targets)
    return ScopePolicy(
        networks=networks,
        addresses=addresses,
        allowed_ports=parse_ports(ports),
        profile=profile,
    )
