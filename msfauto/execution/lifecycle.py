from __future__ import annotations  # noqa: I001

import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4

from ..exploitation.authorization import (
    ExploitAuthorization,
    ExploitAuthorizationError,
    validate_authorization,
)
from ..exploitation.models import ExploitOpportunity
from ..storage.database import WorkspaceStore


EXECUTION_STATES = frozenset({
    "prepared",
    "dispatching",
    "dispatch_uncertain",
    "running",
    "cancelling",
    "completed",
    "failed",
    "timed_out",
    "cancelled",
})

TERMINAL_STATES = frozenset({"completed", "failed", "timed_out", "cancelled"})


class ExploitExecutionError(ValueError):
    """Raised when an exploit execution lifecycle transition is invalid."""


@dataclass(frozen=True)
class ExploitExecution:
    execution_id: str
    workspace: str
    opportunity_id: str
    exploit_id: str
    module_name: str
    target: str
    port: int
    protocol: str
    authorization_id: str
    review_id: str
    state: str
    created_at: str
    updated_at: str
    dispatched_at: str = ""
    finished_at: str = ""
    external_job_id: str = ""
    external_uuid: str = ""
    outcome_summary: str = ""
    error_code: str = ""

    def __post_init__(self) -> None:
        if self.state not in EXECUTION_STATES:
            raise ValueError(f"Unsupported exploit execution state: {self.state}")
        if not 1 <= self.port <= 65535:
            raise ValueError("Execution port must be between 1 and 65535.")
        required = (
            self.execution_id, self.workspace, self.opportunity_id,
            self.exploit_id, self.module_name, self.target, self.protocol,
            self.authorization_id, self.review_id, self.created_at, self.updated_at,
        )
        if not all(value.strip() for value in required):
            raise ValueError("Exploit execution identity fields are required.")


@dataclass(frozen=True)
class ExploitExecutionEvent:
    execution_id: str
    timestamp: str
    from_state: str
    to_state: str
    actor: str
    detail: str
    external_reference: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def prepare_exploit_execution(
    store: WorkspaceStore,
    opportunity: ExploitOpportunity,
    authorization: ExploitAuthorization,
    *,
    actor: str,
    now: str | None = None,
) -> ExploitExecution:
    """Create a durable prepared record after verifying persisted approval and scope."""
    if not actor.strip():
        raise ExploitExecutionError("An operator identity is required.")
    workspace = store.get(opportunity.workspace)
    if workspace is None:
        raise ExploitExecutionError("Workspace does not exist.")
    persisted_opportunity = next(
        (
            item for item in store.get_exploit_opportunities(opportunity.workspace)
            if item.opportunity_id == opportunity.opportunity_id
        ),
        None,
    )
    if persisted_opportunity != opportunity:
        raise ExploitExecutionError("Exploit opportunity is missing or changed in storage.")
    persisted_authorization = store.get_exploit_authorization(
        authorization.authorization_id
    )
    if persisted_authorization != authorization:
        raise ExploitExecutionError("Authorization is missing or differs from the persisted record.")
    review = store.get_exploit_review(authorization.review_id)
    if review is None or review.decision != "accepted":
        raise ExploitExecutionError("The accepted review linked to this authorization is unavailable.")
    review_identity = (
        review.workspace, review.opportunity_id, review.exploit_id, review.module_name,
        review.target, review.port, review.protocol, review.product, review.observed_version,
    )
    opportunity_identity = (
        opportunity.workspace, opportunity.opportunity_id, opportunity.exploit_id,
        opportunity.module_name, opportunity.target, opportunity.port,
        opportunity.protocol, opportunity.product, opportunity.observed_version,
    )
    if authorization.review_id != review.review_id or review_identity != opportunity_identity:
        raise ExploitExecutionError("The stored review does not match the authorized opportunity.")
    try:
        validate_authorization(authorization, opportunity, workspace.policy)
    except ExploitAuthorizationError as exc:
        raise ExploitExecutionError(str(exc)) from exc

    timestamp = now or _now()
    record = ExploitExecution(
        execution_id=uuid4().hex,
        workspace=opportunity.workspace,
        opportunity_id=opportunity.opportunity_id,
        exploit_id=opportunity.exploit_id,
        module_name=opportunity.module_name,
        target=opportunity.target,
        port=opportunity.port,
        protocol=opportunity.protocol,
        authorization_id=authorization.authorization_id,
        review_id=authorization.review_id,
        state="prepared",
        created_at=timestamp,
        updated_at=timestamp,
    )
    try:
        store.create_exploit_execution(
            record,
            ExploitExecutionEvent(
                record.execution_id, timestamp, "", "prepared", actor.strip(),
                "Execution prepared; no module has been dispatched.",
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise ExploitExecutionError(
            "This authorization has already been used for an execution attempt."
        ) from exc
    return record


def _transition(
    store: WorkspaceStore,
    record: ExploitExecution,
    expected_states: frozenset[str],
    new_state: str,
    *,
    actor: str,
    detail: str,
    now: str | None = None,
    external_job_id: str = "",
    external_uuid: str = "",
    outcome_summary: str = "",
    error_code: str = "",
) -> ExploitExecution:
    if not actor.strip() or not detail.strip():
        raise ExploitExecutionError("Every lifecycle transition requires an actor and explanation.")
    if record.state not in expected_states:
        raise ExploitExecutionError(
            f"Cannot transition execution from {record.state} to {new_state}."
        )
    if new_state not in EXECUTION_STATES:
        raise ExploitExecutionError(f"Unsupported execution state: {new_state}")
    timestamp = now or _now()
    updated = replace(
        record,
        state=new_state,
        updated_at=timestamp,
        dispatched_at=(record.dispatched_at or timestamp) if new_state == "dispatching" else record.dispatched_at,
        finished_at=timestamp if new_state in TERMINAL_STATES else record.finished_at,
        external_job_id=external_job_id or record.external_job_id,
        external_uuid=external_uuid or record.external_uuid,
        outcome_summary=outcome_summary or record.outcome_summary,
        error_code=error_code or record.error_code,
    )
    event = ExploitExecutionEvent(
        record.execution_id,
        timestamp,
        record.state,
        new_state,
        actor.strip(),
        detail.strip(),
        external_uuid or external_job_id,
    )
    store.transition_exploit_execution(updated, record.state, event)
    return updated


def begin_exploit_dispatch(
    store: WorkspaceStore,
    execution_id: str,
    opportunity: ExploitOpportunity,
    *,
    actor: str,
    now: str | None = None,
) -> ExploitExecution:
    """Atomically mark dispatch intent after revalidating the latest persisted scope."""
    record = store.get_exploit_execution(execution_id)
    if record is None:
        raise ExploitExecutionError(f"Unknown execution: {execution_id}")
    if record.state != "prepared":
        raise ExploitExecutionError("Only a prepared execution can enter dispatching.")
    if (
        record.workspace != opportunity.workspace
        or record.opportunity_id != opportunity.opportunity_id
        or record.exploit_id != opportunity.exploit_id
        or record.module_name != opportunity.module_name
        or record.target != opportunity.target
        or record.port != opportunity.port
        or record.protocol != opportunity.protocol
    ):
        raise ExploitExecutionError("Execution identity no longer matches the opportunity.")
    workspace = store.get(record.workspace)
    if workspace is None:
        raise ExploitExecutionError("Workspace does not exist.")
    current_opportunity = next(
        (
            item for item in store.get_exploit_opportunities(record.workspace)
            if item.opportunity_id == record.opportunity_id
        ),
        None,
    )
    if current_opportunity != opportunity:
        raise ExploitExecutionError("Persisted exploit opportunity changed before dispatch.")
    authorization = store.get_exploit_authorization(record.authorization_id)
    if authorization is None:
        raise ExploitExecutionError("Persisted authorization is unavailable.")
    review = store.get_exploit_review(record.review_id)
    if review is None or review.decision != "accepted":
        raise ExploitExecutionError("The accepted review is no longer available.")
    review_identity = (
        review.workspace, review.opportunity_id, review.exploit_id, review.module_name,
        review.target, review.port, review.protocol, review.product, review.observed_version,
    )
    opportunity_identity = (
        opportunity.workspace, opportunity.opportunity_id, opportunity.exploit_id,
        opportunity.module_name, opportunity.target, opportunity.port,
        opportunity.protocol, opportunity.product, opportunity.observed_version,
    )
    if authorization.review_id != review.review_id or review_identity != opportunity_identity:
        raise ExploitExecutionError("The stored review no longer matches the authorized opportunity.")
    try:
        validate_authorization(authorization, opportunity, workspace.policy)
    except ExploitAuthorizationError as exc:
        raise ExploitExecutionError(str(exc)) from exc
    return _transition(
        store,
        record,
        frozenset({"prepared"}),
        "dispatching",
        actor=actor,
        detail="Dispatch intent recorded; the external RPC call may now be attempted once.",
        now=now,
    )


def mark_dispatch_uncertain(
    store: WorkspaceStore,
    execution_id: str,
    *,
    actor: str,
    detail: str,
    now: str | None = None,
) -> ExploitExecution:
    record = store.get_exploit_execution(execution_id)
    if record is None:
        raise ExploitExecutionError(f"Unknown execution: {execution_id}")
    return _transition(
        store, record, frozenset({"dispatching", "cancelling"}),
        "dispatch_uncertain", actor=actor, detail=detail, now=now,
    )


def mark_exploit_running(
    store: WorkspaceStore,
    execution_id: str,
    *,
    actor: str,
    external_job_id: str = "",
    external_uuid: str = "",
    reconciled: bool = False,
    detail: str = "External framework confirmed the module is running.",
    now: str | None = None,
) -> ExploitExecution:
    record = store.get_exploit_execution(execution_id)
    if record is None:
        raise ExploitExecutionError(f"Unknown execution: {execution_id}")
    allowed = frozenset({"dispatching", "dispatch_uncertain"}) if reconciled else frozenset({"dispatching"})
    return _transition(
        store, record, allowed, "running", actor=actor, detail=detail, now=now,
        external_job_id=external_job_id, external_uuid=external_uuid,
    )


def request_exploit_cancellation(
    store: WorkspaceStore,
    execution_id: str,
    *,
    actor: str,
    detail: str,
    now: str | None = None,
) -> ExploitExecution:
    record = store.get_exploit_execution(execution_id)
    if record is None:
        raise ExploitExecutionError(f"Unknown execution: {execution_id}")
    return _transition(
        store, record, frozenset({"running"}), "cancelling",
        actor=actor, detail=detail, now=now,
    )


def finish_exploit_execution(
    store: WorkspaceStore,
    execution_id: str,
    state: str,
    *,
    actor: str,
    detail: str,
    outcome_summary: str = "",
    error_code: str = "",
    now: str | None = None,
    reconciled: bool = False,
) -> ExploitExecution:
    if state not in {"completed", "failed", "timed_out", "cancelled"}:
        raise ExploitExecutionError("Finish state must be completed, failed, timed_out, or cancelled.")
    record = store.get_exploit_execution(execution_id)
    if record is None:
        raise ExploitExecutionError(f"Unknown execution: {execution_id}")
    allowed = {"dispatching", "running", "cancelling"}
    if reconciled:
        allowed.add("dispatch_uncertain")
    return _transition(
        store, record, frozenset(allowed), state, actor=actor, detail=detail, now=now,
        outcome_summary=outcome_summary, error_code=error_code,
    )


def reconcile_uncertain_execution(
    store: WorkspaceStore,
    execution_id: str,
    confirmed_state: str,
    *,
    actor: str,
    rationale: str,
    external_job_id: str = "",
    external_uuid: str = "",
    now: str | None = None,
) -> ExploitExecution:
    """Operator-only reconciliation; a confirmed non-dispatch closes this attempt."""
    if confirmed_state == "not_dispatched":
        return finish_exploit_execution(
            store, execution_id, "cancelled", actor=actor,
            detail=f"Operator reconciliation: {rationale}. Attempt closed; create a new review and authorization for another attempt.",
            now=now, reconciled=True,
        )
    if confirmed_state == "running":
        return mark_exploit_running(
            store, execution_id, actor=actor, external_job_id=external_job_id,
            external_uuid=external_uuid, reconciled=True,
            detail=f"Operator reconciliation: {rationale}", now=now,
        )
    if confirmed_state in {"completed", "failed", "timed_out", "cancelled"}:
        return finish_exploit_execution(
            store, execution_id, confirmed_state, actor=actor,
            detail=f"Operator reconciliation: {rationale}", now=now, reconciled=True,
        )
    raise ExploitExecutionError("Reconciliation state must be not_dispatched, running, or terminal.")


def recover_interrupted_dispatches(
    store: WorkspaceStore,
    *,
    actor: str = "recovery",
    now: str | None = None,
) -> tuple[ExploitExecution, ...]:
    """Mark persisted dispatching records uncertain; never retry them automatically."""
    recovered = []
    for record in store.get_exploit_executions(states=("dispatching", "cancelling")):
        recovered.append(
            mark_dispatch_uncertain(
                store,
                record.execution_id,
                actor=actor,
                detail="Process recovery found an interrupted dispatch; operator reconciliation is required.",
                now=now,
            )
        )
    return tuple(recovered)
