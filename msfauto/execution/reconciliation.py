from __future__ import annotations

from dataclasses import dataclass

from msfauto.execution.lifecycle import (
    ExploitExecution,
    ExploitExecutionError,
    finish_exploit_execution,
)
from msfauto.integrations.metasploit import MetasploitClient, MetasploitError
from msfauto.storage.database import WorkspaceStore


class ExploitReconciliationError(ValueError):
    """Raised when a framework job cannot be safely associated with an execution."""


@dataclass(frozen=True)
class ExploitPollResult:
    execution: ExploitExecution
    framework_status: str
    job_active: bool
    detail: str


class MetasploitExploitReconciler:
    """Poll framework job state without treating completion as proof of exploit success."""

    _RUNNING = frozenset({"running", "pending", "started", "queued"})
    _COMPLETED = frozenset({"completed"})
    _FAILED = frozenset({"failed", "error"})
    _CANCELLED = frozenset({"cancelled", "canceled"})

    def __init__(self, store: WorkspaceStore, client: MetasploitClient) -> None:
        self.store = store
        self.client = client

    def poll(self, execution_id: str, *, actor: str) -> ExploitPollResult:
        if not actor.strip():
            raise ExploitReconciliationError("An operator identity is required.")
        execution = self.store.get_exploit_execution(execution_id)
        if execution is None:
            raise ExploitReconciliationError(f"Unknown execution record: {execution_id}")
        if execution.state not in {"running", "cancelling"}:
            raise ExploitReconciliationError(
                "Only running or cancelling executions can be polled; uncertain records "
                "require explicit operator reconciliation."
            )
        if not execution.external_job_id or not execution.external_uuid:
            raise ExploitReconciliationError(
                "The execution has no complete Metasploit job and UUID reference."
            )
        try:
            job_id = int(execution.external_job_id)
        except ValueError as exc:
            raise ExploitReconciliationError(
                "The persisted Metasploit job identifier is invalid."
            ) from exc

        active_jobs = self.client.job_list()
        if job_id in active_jobs:
            return ExploitPollResult(
                execution=execution,
                framework_status="running",
                job_active=True,
                detail="Metasploit still lists this job as active.",
            )

        # An absent job is not proof of success or failure. Ask the module-results
        # endpoint for the UUID-specific terminal result; if unavailable, preserve
        # the current state for an operator to reconcile.
        try:
            result = self.client.module_results(execution.external_uuid)
        except MetasploitError:
            return ExploitPollResult(
                execution=execution,
                framework_status="unresolved",
                job_active=False,
                detail=(
                    "The job is no longer listed, but Metasploit did not provide a "
                    "UUID-specific result. Execution state remains unchanged."
                ),
            )

        status = result["status"].strip().casefold()
        if status in self._RUNNING:
            return ExploitPollResult(
                execution=execution,
                framework_status="unresolved",
                job_active=False,
                detail=(
                    "The job is absent from the active list while module results still "
                    "report a running state. Execution state remains unchanged."
                ),
            )
        if status not in self._COMPLETED | self._FAILED | self._CANCELLED:
            return ExploitPollResult(
                execution=execution,
                framework_status="unresolved",
                job_active=False,
                detail=(
                    f"Metasploit returned an unrecognized result status ({status or 'empty'}); "
                    "execution state remains unchanged."
                ),
            )

        if status in self._COMPLETED:
            terminal_state = "completed"
            summary = (
                "Metasploit reports that module execution completed. Exploit success "
                "and security impact have not been independently verified."
            )
        elif status in self._FAILED:
            terminal_state = "failed"
            summary = (
                "Metasploit reports that module execution failed. This does not establish "
                "whether the target is vulnerable."
            )
        else:
            terminal_state = "cancelled"
            summary = "Metasploit reports that module execution was cancelled."

        try:
            updated = finish_exploit_execution(
                self.store,
                execution_id,
                terminal_state,
                actor=actor,
                detail=f"Framework job reconciliation: {status}.",
                outcome_summary=summary,
            )
        except ExploitExecutionError:
            raise
        return ExploitPollResult(
            execution=updated,
            framework_status=status,
            job_active=False,
            detail=summary,
        )
