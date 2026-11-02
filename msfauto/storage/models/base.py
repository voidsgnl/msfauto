from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Union

IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
