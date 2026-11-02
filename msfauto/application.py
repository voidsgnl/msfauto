from __future__ import annotations

from .discovery import DiscoveryError, run_nmap
from .models import AssessmentPlan, Host, Workspace
from .planner import build_plan
from .storage import WorkspaceStore


class AssessmentApplication:
    """Application-service boundary shared by terminal interfaces."""

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
