from dataclasses import dataclass

from .base import IPAddress
from .service import Service


@dataclass(frozen=True)
class Host:
    address: IPAddress
    status: str
    hostname: str = ""
    services: tuple[Service, ...] = ()
