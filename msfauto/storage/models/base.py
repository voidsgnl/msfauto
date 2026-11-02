from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
