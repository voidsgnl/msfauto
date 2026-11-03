from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from msfauto.storage.database import WorkspaceStore


class ExploitOutcomeValidationError(ValueError):
    """Raised when an outcome assessment lacks independent target-side evidence."""


@dataclass(frozen=True)
class TargetOutcomeAssessment:
    assessment_id: str
    execution_id: str
    workspace: str
    target: str
    verdict: str
    verifier: str
    method: str
    evidence_ids: tuple[str, ...]
    rationale: str
    actor: str
    assessed_at: str


class ExploitOutcomeValidator:
    """Record evidence-backed target assessments separately from framework state.

    This component deliberately does not infer a verdict from a Metasploit job
    result. A module-specific verifier or analyst must supply the verdict and
    target-side evidence produced by an independent observation.
    """

    _VERDICTS = frozenset({"confirmed", "not_confirmed", "inconclusive"})
    _FRAMEWORK_SOURCES = frozenset({
        "metasploit", "metasploit-rpc", "msfconsole", "msfrpcd",
    })

    def __init__(self, store: WorkspaceStore) -> None:
        self.store = store
        with sqlite3.connect(self.store.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_outcome_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    target TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    verifier TEXT NOT NULL,
                    method TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    assessed_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_exploit_outcomes_execution "
                "ON exploit_outcome_assessments(execution_id, assessed_at)"
            )

    def record(
        self,
        execution_id: str,
        *,
        verdict: str,
        verifier: str,
        method: str,
        evidence_ids: tuple[str, ...] = (),
        rationale: str,
        actor: str,
        assessed_at: str | None = None,
    ) -> TargetOutcomeAssessment:
        execution = self.store.get_exploit_execution(execution_id)
        if execution is None:
            raise ExploitOutcomeValidationError("Unknown exploit execution.")
        if execution.state not in {"completed", "failed", "timed_out"}:
            raise ExploitOutcomeValidationError(
                "Target outcome can be assessed only after a terminal framework execution."
            )
        if verdict not in self._VERDICTS:
            raise ExploitOutcomeValidationError("Unsupported target outcome verdict.")
        if not verifier.strip() or not method.strip() or not rationale.strip() or not actor.strip():
            raise ExploitOutcomeValidationError(
                "Verifier, method, rationale, and actor are required."
            )
        if verifier.strip().casefold() in self._FRAMEWORK_SOURCES:
            raise ExploitOutcomeValidationError(
                "Metasploit framework status cannot act as an independent verifier."
            )
        normalized_ids = tuple(dict.fromkeys(evidence_ids))
        if verdict != "inconclusive" and not normalized_ids:
            raise ExploitOutcomeValidationError(
                "A conclusive target outcome requires at least one evidence record."
            )
        for evidence_id in normalized_ids:
            evidence = self.store.get_evidence(evidence_id)
            if evidence is None:
                raise ExploitOutcomeValidationError(
                    f"Evidence record does not exist: {evidence_id}"
                )
            if evidence.workspace != execution.workspace or evidence.target != execution.target:
                raise ExploitOutcomeValidationError(
                    "Evidence must belong to the same workspace and exact target as the execution."
                )
            if evidence.source.strip().casefold() in self._FRAMEWORK_SOURCES:
                raise ExploitOutcomeValidationError(
                    "Framework-generated evidence cannot independently verify target outcome."
                )
        timestamp = assessed_at or datetime.now(timezone.utc).isoformat()
        assessment = TargetOutcomeAssessment(
            assessment_id=uuid4().hex,
            execution_id=execution.execution_id,
            workspace=execution.workspace,
            target=execution.target,
            verdict=verdict,
            verifier=verifier.strip(),
            method=method.strip(),
            evidence_ids=normalized_ids,
            rationale=rationale.strip(),
            actor=actor.strip(),
            assessed_at=timestamp,
        )
        with sqlite3.connect(self.store.path) as connection:
            connection.execute(
                """
                INSERT INTO exploit_outcome_assessments(
                    assessment_id, execution_id, workspace, target, verdict,
                    verifier, method, evidence_ids_json, rationale, actor, assessed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment.assessment_id, assessment.execution_id,
                    assessment.workspace, assessment.target, assessment.verdict,
                    assessment.verifier, assessment.method,
                    json.dumps(assessment.evidence_ids), assessment.rationale,
                    assessment.actor, assessment.assessed_at,
                ),
            )
        return assessment

    def get_for_execution(self, execution_id: str) -> tuple[TargetOutcomeAssessment, ...]:
        with sqlite3.connect(self.store.path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT * FROM exploit_outcome_assessments
                WHERE execution_id = ? ORDER BY assessed_at, assessment_id
                """,
                (execution_id,),
            ).fetchall()
        assessments = []
        for row in rows:
            data = dict(row)
            data["evidence_ids"] = tuple(json.loads(data.pop("evidence_ids_json")))
            assessments.append(TargetOutcomeAssessment(**data))
        return tuple(assessments)
