from __future__ import annotations

from dataclasses import dataclass, field

from .base import utc_now

FINDING_SEVERITIES = {"info", "low", "medium", "high", "critical"}
FINDING_STATUSES = {"potential", "confirmed", "unverified", "false_positive"}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    workspace: str
    title: str
    description: str
    severity: str
    status: str
    confidence: int
    evidence_ids: tuple[str, ...] = ()
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.severity not in FINDING_SEVERITIES:
            raise ValueError(f"Unsupported finding severity: {self.severity}")
        if self.status not in FINDING_STATUSES:
            raise ValueError(f"Unsupported finding status: {self.status}")
        if not 0 <= self.confidence <= 100:
            raise ValueError("Finding confidence must be between 0 and 100.")
        if self.status == "confirmed" and not self.evidence_ids:
            raise ValueError("Confirmed findings must reference at least one evidence record.")
        if not self.finding_id or not self.workspace or not self.title.strip():
            raise ValueError("Finding ID, workspace, and title are required.")
