from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

from ..evidence import EvidenceCollector
from ..storage.models import Finding, utc_now
from ..storage.models.finding import FINDING_STATUSES


class FindingError(ValueError):
    """Raised when a finding cannot be safely recorded."""


def create_finding(
    store,
    workspace: str,
    title: str,
    description: str,
    severity: str = "info",
    status: str = "potential",
    confidence: int = 0,
    evidence_ids: tuple[str, ...] = (),
) -> Finding:
    if not workspace:
        raise FindingError("A workspace is required.")
    collector = EvidenceCollector(store)
    for evidence_id in evidence_ids:
        evidence = store.get_evidence(evidence_id)
        if (
            evidence is None
            or evidence.workspace != workspace
            or not collector.verify(evidence)
        ):
            raise FindingError(
                f"Evidence {evidence_id} is missing, belongs to another workspace, or failed integrity verification."
            )
    finding = Finding(
        finding_id=uuid4().hex,
        workspace=workspace,
        title=title,
        description=description,
        severity=severity,
        status=status,
        confidence=confidence,
        evidence_ids=evidence_ids,
    )
    store.save_finding(finding)
    return finding


def update_finding_status(store, finding_id: str, status: str) -> Finding:
    if status not in FINDING_STATUSES:
        raise FindingError(f"Unsupported finding status: {status}")
    finding = store.get_finding(finding_id)
    if finding is None:
        raise FindingError(f"Unknown finding: {finding_id}")
    collector = EvidenceCollector(store)
    for evidence_id in finding.evidence_ids:
        evidence = store.get_evidence(evidence_id)
        if (
            evidence is None
            or evidence.workspace != finding.workspace
            or not collector.verify(evidence)
        ):
            raise FindingError(
                f"Evidence {evidence_id} is missing, belongs to another workspace, or failed integrity verification."
            )
    updated = replace(finding, status=status, updated_at=utc_now())
    store.save_finding(updated)
    return updated
