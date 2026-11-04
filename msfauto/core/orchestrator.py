from __future__ import annotations

from collections.abc import Callable
from threading import Event
from uuid import uuid4

from ..assessment.investigation import build_investigation_steps
from ..assessment.planner import build_plan
from ..discovery import DiscoveryError, run_metasploit_db_nmap, run_nmap
from ..enumeration import enumerate_services
from ..enumeration.models import ServiceObservation
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
from ..integrations.metasploit import MetasploitClient


class WorkflowError(RuntimeError):
    """Raised when an assessment workflow cannot safely proceed."""


class WorkflowCancelled(WorkflowError):
    """Raised when an operator cancels an assessment at a safe checkpoint."""


class AssessmentApplication:
    """Shared application-service boundary and durable assessment orchestrator."""

    def __init__(
        self, workspace: Workspace, store: WorkspaceStore,
        metasploit_client: MetasploitClient | None = None,
    ) -> None:
        self.workspace = workspace
        self.store = store
        self.metasploit_client = metasploit_client

    def discover(
        self, cancel_event: Event | None = None, scan_profile: str = "standard",
    ) -> tuple[str, tuple[Host, ...], str]:
        """Run bounded discovery for the workspace's saved authorization scope."""
        output_path = self.store.path.parent / "discovery" / f"{uuid4().hex}.xml"
        if self.metasploit_client is not None:
            run, hosts = run_metasploit_db_nmap(
                self.workspace.name, self.workspace.policy, self.metasploit_client,
                scan_profile=scan_profile,
            )
        else:
            run, hosts = run_nmap(
                self.workspace.name, self.workspace.policy, output_path,
                cancel_event=cancel_event,
                scan_profile=scan_profile,
            )
        self.store.save_discovery_run(run, hosts)
        if run.status == "cancelled":
            raise WorkflowCancelled(run.error or "Discovery cancelled by operator.")
        if run.status != "completed":
            detail = run.error or "The scanner did not complete successfully."
            raise DiscoveryError(f"Discovery {run.status}: {detail}")
        self.store.save_hosts(self.workspace.name, hosts)
        return run.status, hosts, run.scan_id

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
        self,
        progress: Callable[[AssessmentEvent], None] | None = None,
        cancel_event: Event | None = None,
        scan_profile: str = "standard",
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

        def check_cancelled() -> None:
            if cancel_event is not None and cancel_event.is_set():
                raise WorkflowCancelled("Assessment cancelled by operator.")

        try:
            if not self.workspace.policy.networks and not self.workspace.policy.addresses:
                raise WorkflowError("Assessment blocked: no authorized targets are configured.")
            check_cancelled()
            transition(
                "discovery",
                f"Starting {scan_profile} TCP discovery within the saved authorization scope.",
            )
            _, hosts, discovery_run_id = self.discover(cancel_event, scan_profile)
            check_cancelled()
            emit("discovery", f"Discovery completed; {len(hosts)} host(s) imported.")
            transition(
                "enumeration",
                "Investigating discovered open services individually; unmatched services will be recorded for manual review.",
            )
            collected = list(enumerate_services(
                self.workspace.name,
                hosts,
                self.workspace.policy,
                max_workers=1,
            ))
            observed_endpoints = {
                (item.target, item.port, item.transport)
                for item in collected
            }
            for host in hosts:
                for service in host.services:
                    endpoint = (str(host.address), service.port, service.protocol)
                    if service.state != "open" or endpoint in observed_endpoints:
                        continue
                    collected.append(ServiceObservation(
                        observation_id=uuid4().hex,
                        workspace=self.workspace.name,
                        target=str(host.address),
                        port=service.port,
                        transport=service.protocol,
                        protocol=service.name or "unknown",
                        kind="service_fingerprint",
                        status="unsupported",
                        attributes={
                            "nmap_fingerprint": {
                                "name": service.name,
                                "product": service.product,
                                "version": service.version,
                                "method": service.method,
                                "confidence": service.confidence,
                                "tunnel": service.tunnel,
                                "cpes": list(service.cpes),
                            },
                            "reason": "No matching protocol adapter produced an observation.",
                            "next_action": "Review the service fingerprint and investigate manually until a dedicated adapter is available.",
                        },
                        confidence=0,
                        observed_at=utc_now(),
                    ))
                    emit(
                        "enumeration",
                        f"MANUAL REVIEW: {host.address}:{service.port}/{service.protocol} "
                        f"({service.product or service.name or 'unidentified service'}) has no matching adapter.",
                        "warning",
                    )
            observations = tuple(collected)
            self.store.save_service_observations(observations, discovery_run_id)
            investigation_steps = build_investigation_steps(
                tuple((str(host.address), service) for host in hosts for service in host.services),
                observations,
            )
            for step in investigation_steps:
                emit(
                    "investigation",
                    f"{step.state}: {step.target}:{step.port}/{step.transport} "
                    f"[{step.action}] — {step.rationale} "
                    f"Expected evidence: {step.expected_evidence}",
                    "warning" if step.state == "NEEDS_REVIEW" else "info",
                )
            for item in observations:
                if item.status in {"failed", "partial"}:
                    detail = str(item.attributes.get("error") or item.attributes.get("error_type") or "protocol response incomplete")[:160]
                    emit(
                        "enumeration",
                        f"{item.status.upper()}: {item.target}:{item.port}/{item.protocol} — {detail}",
                        "warning",
                    )
            check_cancelled()
            mappings = load_package_mappings()
            if mappings:
                transition("vulnerability_assessment", "Querying OSV for explicitly mapped package identities.")
                summary = assess_with_osv(
                    self.workspace.name,
                    hosts,
                    mappings,
                    self.store,
                    on_event=lambda message: emit("vulnerability_assessment", message),
                    observations=observations,
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
            check_cancelled()
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
            partial = sum(item.status == "partial" for item in observations)
            failed = sum(item.status == "failed" for item in observations)
            emit(
                "enumeration",
                f"Service enumeration recorded {len(observations)} observation(s): "
                f"{completed} completed, {partial} partial, {failed} failed.",
            )
            check_cancelled()
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
            emit(
                "completed",
                "Assessment completed: discovery, per-service investigation, vulnerability correlation, exploit matching, and read-only planning finished. No exploit modules were dispatched.",
            )
            return current, plan
        except Exception as exc:
            now = utc_now()
            cancelled = isinstance(exc, WorkflowCancelled)
            current = AssessmentRun(
                run_id, self.workspace.name, "cancelled" if cancelled else "failed",
                current.stage, started, now, now, str(exc),
            )
            self.store.save_assessment_run(current)
            emit(
                current.stage,
                f"Assessment {'cancelled' if cancelled else 'failed'}: {exc}",
                "warning" if cancelled else "error",
            )
            raise
