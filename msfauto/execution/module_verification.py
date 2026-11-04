from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from msfauto.storage.database import WorkspaceStore

from .lifecycle import TERMINAL_STATES, ExploitExecution
from .outcome_validation import (
    ExploitOutcomeValidator,
    TargetOutcomeAssessment,
)


class ModuleVerificationError(ValueError):
    """Raised when a module-specific verifier cannot be safely selected or run."""


@dataclass(frozen=True)
class ModuleVerificationResult:
    """A verifier's target-side conclusion and references to independently stored evidence."""

    verdict: str
    method: str
    rationale: str
    evidence_ids: tuple[str, ...] = ()


ModuleVerifier = Callable[[ExploitExecution, float], ModuleVerificationResult]


class ModuleVerifierRegistry:
    """Dispatch only exact, explicitly registered module-specific target verifiers.

    A verifier receives the persisted execution and a timeout budget in seconds.
    It must enforce that budget in its own network operations and return evidence
    IDs created from target-side observations. Framework job state is never used
    as evidence. Missing verifiers and timeouts produce an inconclusive record.
    """

    MIN_TIMEOUT_SECONDS = 0.1
    MAX_TIMEOUT_SECONDS = 30.0

    def __init__(
        self,
        store: WorkspaceStore,
        verifiers: Mapping[str, ModuleVerifier] | None = None,
    ) -> None:
        self.store = store
        self.outcomes = ExploitOutcomeValidator(store)
        self.verifiers = dict(verifiers or {})
        if any(not name.strip() for name in self.verifiers):
            raise ModuleVerificationError("Verifier registrations require exact module names.")

    def verify(
        self,
        execution_id: str,
        *,
        actor: str,
        timeout_seconds: float = 5.0,
    ) -> TargetOutcomeAssessment:
        if not math.isfinite(timeout_seconds) or not (
            self.MIN_TIMEOUT_SECONDS <= timeout_seconds <= self.MAX_TIMEOUT_SECONDS
        ):
            raise ModuleVerificationError(
                f"Verification timeout must be between {self.MIN_TIMEOUT_SECONDS} "
                f"and {self.MAX_TIMEOUT_SECONDS} seconds."
            )
        execution = self.store.get_exploit_execution(execution_id)
        if execution is None:
            raise ModuleVerificationError("Unknown exploit execution.")
        if execution.state not in TERMINAL_STATES:
            raise ModuleVerificationError(
                "Target verification is available only after terminal framework execution."
            )

        verifier = self.verifiers.get(execution.module_name)
        if verifier is None:
            return self._inconclusive(
                execution,
                actor=actor,
                verifier="msfauto:module-verifier-registry",
                method="exact module registry lookup",
                rationale=(
                    f"No target-side verifier is registered for the exact module "
                    f"{execution.module_name!r}; no probe was sent."
                ),
            )

        try:
            result = verifier(execution, timeout_seconds)
        except TimeoutError:
            return self._inconclusive(
                execution,
                actor=actor,
                verifier=f"module:{execution.module_name}",
                method="module-specific verification timeout",
                rationale=(
                    f"The registered verifier exceeded its {timeout_seconds:g}-second "
                    "budget; no exploit outcome was inferred."
                ),
            )

        if not isinstance(result, ModuleVerificationResult):
            raise ModuleVerificationError(
                "A module verifier must return ModuleVerificationResult."
            )
        return self.outcomes.record(
            execution.execution_id,
            verdict=result.verdict,
            verifier=f"module:{execution.module_name}",
            method=result.method,
            evidence_ids=result.evidence_ids,
            rationale=result.rationale,
            actor=actor,
        )

    def _inconclusive(
        self,
        execution: ExploitExecution,
        *,
        actor: str,
        verifier: str,
        method: str,
        rationale: str,
    ) -> TargetOutcomeAssessment:
        return self.outcomes.record(
            execution.execution_id,
            verdict="inconclusive",
            verifier=verifier,
            method=method,
            rationale=rationale,
            actor=actor,
        )
