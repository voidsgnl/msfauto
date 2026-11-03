from dataclasses import dataclass


@dataclass(frozen=True)
class Service:
    """Normalized service fingerprint observed on a host/port."""

    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    method: str = "unknown"
    confidence: int = 0
    extra_info: str = ""
    tunnel: str = ""
    cpes: tuple[str, ...] = ()
    source: str = "unknown"
    observed_at: str = ""
