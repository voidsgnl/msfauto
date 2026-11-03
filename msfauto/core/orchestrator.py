from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from ..assessment.planner import build_plan
from ..discovery import DiscoveryError, run_nmap
from ..enumeration import enumerate_services
from ..exploitation.matcher import load_exploit_catalog, match_exploits
from ..storage import WorkspaceStore
from ..storage.models import (
    AssessmentEvent,
    AssessmentPlan,
    AssessmentRun,
    Host,
    Workspace,
    utc_now,
)
from ..vulnerability.workflow import assess_with_osv, load_package_mappings


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
            transition("enumeration", "Enumerating recognized HTTP/HTTPS, SSH, FTP, SMB2, and TLS services within scope.")
            observations = enumerate_services(
                self.workspace.name, hosts, self.workspace.policy
            )
            self.store.save_service_observations(observations)
            mappings = load_package_mappings()
            if mappings:
                transition("vulnerability_assessment", "Querying OSV for explicitly mapped package identities.")
                summary = assess_with_osv(
                    self.workspace.name,
                    hosts,
                    mappings,
                    self.store,
                    on_event=lambda message: emit("vulnerability_assessment", message),
                )
                emit(
                    "vulnerability_assessment",
                    f"OSV assessment: {summary.mapped_services} mapped service(s), "
                    f"{summary.unique_queries} unique query/queries, "
                    f"{summary.successful_queries} successful, {summary.failed_queries} failed, "
                    f"{summary.advisories} advisory record(s), "
                    f"{len(summary.candidates)} candidate(s).",
                )
            else:
                emit(
                    "vulnerability_assessment",
                    "OSV assessment skipped: no explicit package identity mappings configured.",
                )
            curated_catalog = load_exploit_catalog()
            persisted_catalog = self.store.get_exploit_catalog(self.workspace.name)
            catalog_by_id = {
                item.exploit_id: item
                for item in (*persisted_catalog, *curated_catalog)
            }
            exploit_catalog = tuple(catalog_by_id.values())
            if exploit_catalog:
                transition(
                    "exploit_intelligence",
                    "Matching discovered services and vulnerability candidates against curated and synchronized exploit catalog entries.",
                )
                opportunities = match_exploits(
                    self.workspace.name,
                    hosts,
                    exploit_catalog,
                    self.store.get_vulnerability_candidates(self.workspace.name),
                )
                if opportunities:
                    self.store.save_exploit_opportunities(opportunities)
                emit(
                    "exploit_intelligence",
                    f"Exploit intelligence matched {len(opportunities)} opportunity/ies "
                    f"from {len(exploit_catalog)} catalog entry/entries. "
                    "No module was approved or executed.",
                )
            else:
                emit(
                    "exploit_intelligence",
                    "Exploit matching skipped: no curated or synchronized catalog entries are available.",
                )
            completed = sum(item.status == "completed" for item in observations)
            failed = sum(item.status == "failed" for item in observations)
            emit(
                "enumeration",
                f"Service enumeration recorded {len(observations)} observation(s): "
                f"{completed} completed, {failed} failed.",
            )
            transition("planning", "Building a read-only plan from stored observations.")
            plan = self.build_assessment_plan()
            self.store.save_run_plan(run_id, plan)
            emit(
                "planning",
                f"Read-only plan generated with {len(plan.recommendations)} recommendation(s); "
                "run-specific snapshot persisted.",
            )
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
