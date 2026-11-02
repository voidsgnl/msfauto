from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Mapping
from uuid import uuid4

from ..storage.models import EvidenceRecord


class EvidenceError(ValueError):
    """Raised when evidence cannot be safely stored or verified."""


class EvidenceCollector:
    """Stores bounded evidence artifacts and integrity metadata locally."""

    def __init__(self, store, max_bytes: int = 2_000_000) -> None:
        if max_bytes < 1:
            raise EvidenceError("max_bytes must be at least one.")
        self.store = store
        self.root = store.path.parent / "evidence"
        self.max_bytes = max_bytes

    def collect(
        self,
        workspace: str,
        source: str,
        target: str,
        evidence_type: str,
        summary: str,
        content: bytes,
        metadata: Mapping[str, object] | None = None,
    ) -> EvidenceRecord:
        if not workspace or not source.strip() or not evidence_type.strip():
            raise EvidenceError("Workspace, source, and evidence type are required.")
        if len(content) > self.max_bytes:
            raise EvidenceError(f"Evidence exceeds the {self.max_bytes}-byte limit.")
        evidence_id = uuid4().hex
        workspace_key = hashlib.sha256(workspace.encode()).hexdigest()[:20]
        directory = self.root / workspace_key
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or directory.is_symlink():
            raise EvidenceError("Evidence storage paths must not be symbolic links.")
        self.root.chmod(0o700)
        directory.chmod(0o700)
        artifact = directory / f"{evidence_id}.bin"
        temporary = directory / f".{evidence_id}.tmp"
        digest = hashlib.sha256(content).hexdigest()
        try:
            with temporary.open("xb") as handle:
                handle.write(content)
            temporary.replace(artifact)
            artifact.chmod(0o600)
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            artifact.unlink(missing_ok=True)
            raise EvidenceError(f"Unable to persist evidence artifact: {exc}") from exc

        record = EvidenceRecord(
            evidence_id=evidence_id,
            workspace=workspace,
            source=source,
            target=target,
            evidence_type=evidence_type,
            summary=summary,
            artifact_path=str(artifact),
            sha256=digest,
            size_bytes=len(content),
            metadata=dict(metadata or {}),
        )
        try:
            self.store.save_evidence(record)
        except (sqlite3.Error, TypeError, ValueError):
            artifact.unlink(missing_ok=True)
            raise
        return record

    def verify(self, evidence: EvidenceRecord) -> bool:
        artifact = Path(evidence.artifact_path).resolve()
        root = self.root.resolve()
        if not artifact.is_relative_to(root) or not artifact.is_file():
            return False
        try:
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        except OSError:
            return False
        return digest == evidence.sha256
