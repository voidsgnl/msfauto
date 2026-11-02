from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from .discovery import DiscoveryError, run_nmap
from .models import (
    AssessmentEvent, AssessmentPlan, AssessmentRun, Host, Workspace, utc_now,
)
from .planner import build_plan
from .storage import WorkspaceStore


class WorkflowError(RuntimeError):
    """Raised when an assessment workflow cannot safely proceed."""


class AssessmentApplication:
    """Shared application-service boundary and durable assessment orchestrator."""

    def __init__(self, workspace: Workspace, store: WorkspaceStore) -> None:
        self.workspace = workspace
        self.store = store

    def discover(self) -> tuple[str, tuple[Host, ...]]:
        """Run bounded discovery for the workspace's saved authorization scope."""
        output_path = self.store.path.parent / "discovery" / f"{self.workspace.name}.xml"
        run, hosts = run_nmap(self.workspace.name, self.workspace.policy, output_path)
        self.store.save_discovery_run(run)
        if run.status != "completed":
            detail = run.error or "The scanner did not complete successfully."
            raise DiscoveryError(f"Discovery {run.status}: {detail}")
        self.store.save_hosts(self.workspace.name, hosts)
        return run.status, hosts

    def targets(self) -> tuple[Host, ...]:
        return self.store.get_hosts(self.workspace.name)

    def build_assessment_plan(self) -> AssessmentPlan:
        plan = build_plan(
            self.workspace.name,
            self.store.get_hosts(self.workspace.name),
            self.store.get_all_module_metadata(self.workspace.name),
        )
        self.store.save_plan(plan)
        return plan

    def run_assessment(
        self, progress: Callable[[AssessmentEvent], None] | None = None
    ) -> tuple[AssessmentRun, AssessmentPlan]:
        """Persist a discovery-and-planning workflow; never dispatch active checks."""
        run_id = uuid4().hex
        started = utc_now()
        current = AssessmentRun(
            run_id, self.workspace.name, "running", "validating_scope",
            started, started,
        )
        self.store.save_assessment_run(current)

        def emit(stage: str, message: str, level: str = "info") -> None:
            nonlocal current
            timestamp = utc_now()
            event = AssessmentEvent(run_id, timestamp, stage, level, message)
            self.store.save_assessment_event(event)
            if progress is not None:
                progress(event)

        def transition(stage: str, message: str) -> None:
            nonlocal current
            now = utc_now()
            current = AssessmentRun(
                run_id, self.workspace.name, "running", stage,
                started, now,
            )
            self.store.save_assessment_run(current)
            emit(stage, message)

        try:
            if not self.workspace.policy.networks and not self.workspace.policy.addresses:
                raise WorkflowError("Assessment blocked: no authorized targets are configured.")
            transition("discovery", "Starting bounded discovery within the saved authorization scope.")
            _, hosts = self.discover()
            emit("discovery", f"Discovery completed; {len(hosts)} host(s) imported.")
            transition("planning", "Building a read-only plan from stored observations.")
            plan = self.build_assessment_plan()
            emit("planning", f"Read-only plan generated with {len(plan.recommendations)} recommendation(s).")
            now = utc_now()
            current = AssessmentRun(
                run_id, self.workspace.name, "completed", "completed",
                started, now, now,
            )
            self.store.save_assessment_run(current)
            emit("completed", "Assessment workflow completed. No active checks were dispatched.")
            return current, plan
        except Exception as exc:
            now = utc_now()
            current = AssessmentRun(
                run_id, self.workspace.name, "failed", current.stage,
                started, now, now, str(exc),
            )
            self.store.save_assessment_run(current)
            emit(current.stage, f"Assessment failed: {exc}", "error")
            raise
