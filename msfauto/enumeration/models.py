from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServiceObservation:
    """A bounded, timestamped observation collected from one discovered service."""

    observation_id: str
    workspace: str
    target: str
    port: int
    transport: str
    protocol: str
    kind: str
    status: str
    attributes: dict[str, object] = field(default_factory=dict)
    source: str = "msfauto"
    confidence: int = 0
    observed_at: str = ""
