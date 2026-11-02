from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
