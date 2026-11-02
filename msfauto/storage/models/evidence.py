from __future__ import annotations

from dataclasses import dataclass, field

from .base import utc_now


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    workspace: str
    source: str
    target: str
    evidence_type: str
    summary: str
    artifact_path: str
    sha256: str
    size_bytes: int
    collected_at: str = field(default_factory=utc_now)
    metadata: dict[str, object] = field(default_factory=dict)
