from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

from .base import utc_now


@dataclass(frozen=True)
class DiscoveryRun:
    workspace: str
    scanner: str
    command: tuple[str, ...]
    output_path: str
    status: str
    started_at: str
    finished_at: str
    error: str = ""
    scan_id: str = field(default_factory=lambda: uuid4().hex)


@dataclass(frozen=True)
class ModuleMetadata:
    workspace: str
    module_type: str
    module_name: str
    metadata: dict[str, object]
    options: dict[str, object]
    source: str
    fetched_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class Recommendation:
    target: str
    port: int
    protocol: str
    module_type: str
    module_name: str
    confidence: int
    reason: str
    risk: str = "non-invasive"


@dataclass(frozen=True)
class AssessmentPlan:
    workspace: str
    recommendations: tuple[Recommendation, ...]
    created_at: str = field(default_factory=utc_now)


@dataclass(frozen=True)
class AssessmentRun:
    run_id: str
    workspace: str
    status: str
    stage: str
    started_at: str
    updated_at: str
    finished_at: str = ""
    error: str = ""


@dataclass(frozen=True)
class AssessmentEvent:
    run_id: str
    timestamp: str
    stage: str
    level: str
    message: str
