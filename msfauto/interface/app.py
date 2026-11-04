from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Static

from ..core import AssessmentApplication, WorkflowError
from ..discovery import DiscoveryError
from ..storage import WorkspaceStore
from ..storage.models import Host, Workspace


class Dashboard(App[None]):
    """Full-screen, menu-driven terminal interface for MSFAuto."""

    TITLE = "MSFAuto"
    SUB_TITLE = "SECURITY ASSESSMENT FRAMEWORK"

    CSS = """
    Screen {
        background: #080e12;
        color: #d7e1e7;
        padding: 0 1;
    }
    Header, Footer {
        background: #101a20;
        color: #91a4ad;
    }
    #brand {
        height: 7;
        padding: 0 2;
        border: double #287c78;
        background: #0d171c;
        color: #9ce4d6;
        margin-bottom: 1;
    }
    #context {
        height: 4;
        padding: 0 2;
        border: round #344750;
        background: #10171c;
        margin-bottom: 1;
    }
    #screen-title {
        height: 3;
        padding: 0 2;
        background: #14242b;
        color: #9ce4d6;
        text-style: bold;
    }
    #screen-content {
        height: 1fr;
        min-height: 8;
        padding: 1 2;
        border: round #344750;
        background: #0c1419;
        overflow-y: auto;
    }
    #records {
        height: 1fr;
        min-height: 8;
        border: round #344750;
        background: #0c1419;
    }
    DataTable > .datatable--header {
        background: #16262c;
        color: #9ce4d6;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #17413f;
        color: #ffffff;
    }
    #task-panel {
        height: 4;
        padding: 0 2;
        border: round #287c78;
        background: #101a20;
        color: #9ce4d6;
        margin-top: 1;
    }
    #activity {
        height: 6;
        padding: 0 2;
        border: round #344750;
        background: #0c1419;
        color: #aab9c0;
    }
    #prompt {
        height: 2;
        padding: 0 2;
        color: #9ce4d6;
    }
    """

    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        ("1", "start_assessment", "Start assessment"),
        ("2", "targets", "Targets/services"),
        ("3", "vulnerabilities", "Vulnerabilities"),
        ("4", "exploits", "Exploit intelligence"),
        ("5", "executions", "Execution manager"),
        ("6", "evidence", "Findings/evidence"),
        ("7", "scope", "Workspace/scope"),
        ("8", "history", "Assessment history"),
        ("h", "home", "Main menu"),
        ("r", "refresh", "Refresh"),
        ("escape", "home", "Main menu"),
        ("q", "quit", "Quit"),
    ]

    MENU = (
        "[bold #9ce4d6]  1.[/bold #9ce4d6]  Start assessment"
        "       [dim]Run discovery, enumeration and assessment planning[/dim]\n"
        "[bold #9ce4d6]  2.[/bold #9ce4d6]  Targets & services"
        "     [dim]Hosts, ports, fingerprints and service observations[/dim]\n"
        "[bold #9ce4d6]  3.[/bold #9ce4d6]  Vulnerability assessment"
        " [dim]Matched advisories and assessment candidates[/dim]\n"
        "[bold #9ce4d6]  4.[/bold #9ce4d6]  Exploit intelligence"
        "    [dim]Applicable exploit opportunities and metadata[/dim]\n"
        "[bold #9ce4d6]  5.[/bold #9ce4d6]  Execution manager"
        "      [dim]Exploit execution lifecycle and job states[/dim]\n"
        "[bold #9ce4d6]  6.[/bold #9ce4d6]  Findings & evidence"
        "      [dim]Recorded findings, artifacts and provenance[/dim]\n"
        "[bold #9ce4d6]  7.[/bold #9ce4d6]  Workspace & scope"
        "       [dim]Saved authorization policy and target boundaries[/dim]\n"
        "[bold #9ce4d6]  8.[/bold #9ce4d6]  Assessment history"
        "       [dim]Previous runs and their final states[/dim]\n\n"
        "[dim]  Press a number to open a section. Press H or ESC to return here.[/dim]"
    )

    def __init__(self, workspace: Workspace, store: WorkspaceStore) -> None:
        super().__init__()
        self.workspace = workspace
        self.store = store
        self.services = AssessmentApplication(workspace, store)
        self._hosts: dict[str, Host] = {}
        self._activity_lines: list[str] = []
        self._task_started: float | None = None
        self._task_active = False
        self._spinner_index = 0
        self._current_view = "home"

    def compose(self) -> ComposeResult:
        targets = [
            str(item)
            for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)
        ]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "discovered ports"
        yield Header()
        with Vertical():
            yield Static(
                "[bold #9ce4d6]███╗   ███╗███████╗███████╗[/bold #9ce4d6]  "
                "[bold #d7e1e7]MSFAuto[/bold]  [dim]v0.1.0[/dim]\n"
                "[bold #9ce4d6]████╗ ████║██╔════╝██╔════╝[/bold #9ce4d6]  "
                "[dim]SECURITY ASSESSMENT FRAMEWORK[/dim]\n"
                "[dim]Reconnaissance  /  Vulnerability intelligence  /  Exploitation  /  Validation[/dim]",
                id="brand",
            )
            yield Static(
                f"[bold #9ce4d6]WORKSPACE[/bold]  {self.workspace.name}    "
                f"[bold #9ce4d6]PROFILE[/bold]  {self.workspace.policy.profile}\n"
                f"[bold #9ce4d6]SCOPE[/bold]  {', '.join(targets) or 'not configured'}\n"
                f"[bold #9ce4d6]PORTS[/bold]  {ports}",
                id="context",
            )
            yield Static("MAIN MENU  /  SELECT A WORKFLOW", id="screen-title")
            yield Static(self.MENU, id="screen-content")
            table = DataTable(id="records", cursor_type="row", zebra_stripes=True)
            table.display = False
            yield table
            yield Static(
                "[bold #8bd49c]● READY[/bold #8bd49c]  Workspace loaded. No assessment is running.",
                id="task-panel",
            )
            yield Static("[dim]Activity log is ready. Workflow events will appear here.[/dim]", id="activity")
            yield Static("[bold #9ce4d6]MSFAuto[/bold #9ce4d6]  [dim]Select 1–8  ·  H/ESC Main menu  ·  R Refresh  ·  Q Quit[/dim]", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#records", DataTable)
        table.add_columns("#", "Target / ID", "Port / Type", "Service / State", "Details")
        self._load_targets()
        self.set_interval(0.15, self._tick)
        self._record_activity("READY", "Workspace loaded; terminal interface initialized.")

    def _record_activity(self, stage: str, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self._activity_lines.append(
            f"[dim]{stamp}[/dim]  [bold #9ce4d6]{stage.upper()}[/bold #9ce4d6]  {message}"
        )
        self._activity_lines = self._activity_lines[-4:]
        self.query_one("#activity", Static).update("\n".join(self._activity_lines))

    def _set_status(self, message: str, level: str = "info") -> None:
        palette = {
            "info": ("#72b7ff", "INFO"),
            "success": ("#8bd49c", "COMPLETED"),
            "warning": ("#e8c879", "NOTICE"),
            "error": ("#f08b86", "FAILED"),
        }
        color, label = palette.get(level, palette["info"])
        self.query_one("#task-panel", Static).update(
            f"[bold {color}]● {label}[/bold {color}]  {message}"
        )

    def _tick(self) -> None:
        if not self._task_active or self._task_started is None:
            return
        glyphs = ("◐", "◓", "◑", "◒")
        self._spinner_index = (self._spinner_index + 1) % len(glyphs)
        elapsed = int(time.monotonic() - self._task_started)
        minutes, seconds = divmod(elapsed, 60)
        self.query_one("#task-panel", Static).update(
            f"[bold #55d6c2]{glyphs[self._spinner_index]} RUNNING[/bold #55d6c2]  "
            f"Assessment workflow active  [dim]Elapsed {minutes:02d}:{seconds:02d}[/dim]"
        )

    def _begin_task(self, message: str) -> None:
        self._task_started = time.monotonic()
        self._task_active = True
        self._record_activity("START", message)
        self._tick()

    def _finish_task(self) -> str:
        elapsed = 0 if self._task_started is None else int(time.monotonic() - self._task_started)
        self._task_active = False
        self._task_started = None
        return f"{elapsed // 60:02d}:{elapsed % 60:02d}"

    def _show_view(self, title: str, content: str, view: str, rows=()) -> None:
        self._current_view = view
        self.query_one("#screen-title", Static).update(title)
        self.query_one("#screen-content", Static).update(content)
        table = self.query_one("#records", DataTable)
        table.clear()
        if rows:
            for index, row in enumerate(rows, start=1):
                table.add_row(str(index), *[str(value) for value in row], key=f"{row[0]}|{index}" if view == "targets" else f"{view}-{index}")
            table.display = True
            self.query_one("#screen-content", Static).styles.height = 5
        else:
            table.display = False
            self.query_one("#screen-content", Static).styles.height = "1fr"

    def _load_targets(self) -> tuple[Host, ...]:
        hosts = self.services.targets()
        self._hosts = {str(host.address): host for host in hosts}
        return hosts

    def action_home(self) -> None:
        self._show_view(
            "MAIN MENU  /  SELECT A WORKFLOW",
            self.MENU,
            "home",
        )
        self.query_one("#prompt", Static).update(
            "[bold #9ce4d6]MSFAuto[/bold #9ce4d6]  [dim]Select 1–8  ·  H/ESC Main menu  ·  R Refresh  ·  Q Quit[/dim]"
        )

    def action_start_assessment(self) -> None:
        if self._task_active:
            self._set_status("An assessment is already running.", "warning")
            return
        self.run_worker(self.run_discovery(), name="assessment", exclusive=True)

    def action_targets(self) -> None:
        hosts = self._load_targets()
        rows = []
        for host in hosts:
            if not host.services:
                rows.append((str(host.address), "—", host.status, host.hostname or "No service records"))
            for service in host.services:
                rows.append((
                    str(host.address),
                    f"{service.port}/{service.protocol}",
                    service.name or service.state,
                    " ".join(part for part in (service.product, service.version) if part) or "Fingerprint pending",
                ))
        self._show_view(
            "TARGET INVENTORY  /  HOSTS & SERVICES",
            f"Stored hosts: {len(hosts)}    Service records: {sum(len(host.services) for host in hosts)}\n"
            "Select a target row to inspect its recorded service inventory.",
            "targets",
            rows,
        )
        self._record_activity("INVENTORY", f"Loaded {len(hosts)} stored host(s).")

    def action_vulnerabilities(self) -> None:
        items = self.store.get_vulnerability_candidates(self.workspace.name)
        rows = [
            (
                f"{item.target}",
                f"{item.port}/{item.protocol}",
                f"{item.advisory_id} · {item.status}",
                f"{item.product} {item.observed_version} · confidence {item.confidence}%",
            )
            for item in items
        ]
        self._show_view(
            "VULNERABILITY ASSESSMENT  /  CANDIDATES",
            f"Persisted candidates: {len(items)}\n"
            "Candidates are leads, not confirmed vulnerabilities. Review status and evidence before conclusions.",
            "vulnerabilities",
            rows,
        )
        self._record_activity("VULNERABILITY", f"Loaded {len(items)} candidate(s).")

    def action_exploits(self) -> None:
        items = self.store.get_exploit_opportunities(self.workspace.name)
        rows = [
            (
                item.target,
                f"{item.port}/{item.protocol}",
                f"{item.rank} · {item.status}",
                f"{item.module_name} · {item.confidence}% · {item.risk}",
            )
            for item in items
        ]
        self._show_view(
            "EXPLOIT INTELLIGENCE  /  APPLICABILITY",
            f"Matched opportunities: {len(items)}\n"
            "An identified opportunity is not approval or execution authorization.",
            "exploits",
            rows,
        )
        self._record_activity("EXPLOITS", f"Loaded {len(items)} exploit opportunity/opportunities.")

    def action_executions(self) -> None:
        items = self.store.get_exploit_executions(workspace=self.workspace.name)
        rows = [
            (
                item.execution_id[:12],
                f"{item.port}/{item.protocol}",
                item.state,
                f"{item.target} · {item.module_name}",
            )
            for item in items
        ]
        self._show_view(
            "EXECUTION MANAGER  /  EXPLOIT LIFECYCLE",
            f"Persisted executions: {len(items)}\n"
            "Dispatch-uncertain states require reconciliation; never retry them automatically.",
            "executions",
            rows,
        )
        self._record_activity("EXECUTION", f"Loaded {len(items)} execution record(s).")

    def action_evidence(self) -> None:
        findings = self.store.get_findings(self.workspace.name)
        evidence = self.store.get_evidence_records(self.workspace.name)
        rows = [
            (item.finding_id[:12], item.severity, item.status, item.title)
            for item in findings
        ]
        rows.extend(
            (item.evidence_id[:12], item.evidence_type, "EVIDENCE", f"{item.target} · {item.summary}")
            for item in evidence
        )
        self._show_view(
            "FINDINGS & EVIDENCE  /  RECORDED RESULTS",
            f"Findings: {len(findings)}    Evidence records: {len(evidence)}\n"
            "Evidence records retain provenance and integrity metadata; framework completion alone is not target-side confirmation.",
            "evidence",
            rows,
        )
        self._record_activity("EVIDENCE", f"Loaded {len(findings)} finding(s) and {len(evidence)} evidence record(s).")

    def action_scope(self) -> None:
        targets = [
            str(item)
            for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)
        ]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "all discovered ports"
        self._show_view(
            "WORKSPACE  /  AUTHORIZATION SCOPE",
            f"[bold #9ce4d6]Workspace[/bold]  {self.workspace.name}\n"
            f"[bold #9ce4d6]Profile[/bold]  {self.workspace.policy.profile}\n"
            f"[bold #9ce4d6]Authorized targets[/bold]  {', '.join(targets) or 'none'}\n"
            f"[bold #9ce4d6]Allowed ports[/bold]  {ports}\n\n"
            "[bold #e8c879]NOTE[/bold #e8c879]  Discovery does not authorize intrusive actions. "
            "Exploit actions require their own exact, current authorization.",
            "scope",
        )
        self._record_activity("SCOPE", "Displayed saved workspace policy.")

    def action_history(self) -> None:
        items = self.store.get_assessment_runs(self.workspace.name)
        rows = [
            (item.run_id[:12], item.stage, item.status, f"{item.started_at} · {item.error or '—'}")
            for item in items
        ]
        self._show_view(
            "ASSESSMENT HISTORY  /  PREVIOUS RUNS",
            f"Recorded assessment runs: {len(items)}",
            "history",
            rows,
        )
        self._record_activity("HISTORY", f"Loaded {len(items)} assessment run(s).")

    def action_refresh(self) -> None:
        actions = {
            "home": self.action_home,
            "targets": self.action_targets,
            "vulnerabilities": self.action_vulnerabilities,
            "exploits": self.action_exploits,
            "executions": self.action_executions,
            "evidence": self.action_evidence,
            "scope": self.action_scope,
            "history": self.action_history,
        }
        actions.get(self._current_view, self.action_home)()

    async def run_discovery(self) -> None:
        self._begin_task("Starting saved-scope discovery and assessment planning.")
        self._show_view(
            "ASSESSMENT RUN  /  LIVE ACTIVITY",
            "Discovery, service enumeration and read-only planning are running.\n"
            "Progress is indeterminate because the workflow does not expose a reliable percentage.",
            "assessment",
        )
        try:
            workflow, plan = await asyncio.to_thread(
                self.services.run_assessment,
                lambda item: self.call_from_thread(
                    self._record_activity, item.stage, item.message
                ),
            )
            hosts = self.services.targets()
        except (DiscoveryError, WorkflowError, OSError, sqlite3.Error) as exc:
            elapsed = self._finish_task()
            self._set_status(f"Assessment failed after {elapsed}: {exc}", "error")
            self._record_activity("FAILED", str(exc))
            self.query_one("#screen-content", Static).update(
                "[bold #f08b86]ASSESSMENT FAILED[/bold #f08b86]\n"
                f"{exc}\n\nReview the saved scope, scanner availability and assessment data before retrying."
            )
        else:
            elapsed = self._finish_task()
            self._set_status(
                f"Run {workflow.run_id[:8]} completed in {elapsed} — {len(hosts)} host(s), "
                f"{len(plan.recommendations)} recommendation(s).",
                "success",
            )
            self._record_activity(
                "COMPLETE",
                f"Run {workflow.run_id[:8]} · {len(hosts)} host(s) · {len(plan.recommendations)} recommendation(s).",
            )
            self._show_view(
                "ASSESSMENT COMPLETE  /  RUN SUMMARY",
                f"Run ID: {workflow.run_id}\n"
                f"Elapsed: {elapsed}\n"
                f"Discovered hosts: {len(hosts)}\n"
                f"Read-only recommendations: {len(plan.recommendations)}\n\n"
                "No active checks were dispatched by discovery or planning.\n"
                "Press 2 to inspect targets, 3 for vulnerability candidates, or 4 for exploit intelligence.",
                "assessment",
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "records" or self._current_view != "targets":
            return
        address = str(event.row_key.value).split("|", 1)[0]
        host = self._hosts.get(address)
        if host is None:
            return
        services = [
            f"{service.port}/{service.protocol}  {service.state}  "
            f"{service.name} {service.product} {service.version}".rstrip()
            for service in host.services
        ]
        self.query_one("#screen-content", Static).update(
            f"[bold #9ce4d6]TARGET[/bold #9ce4d6]  {host.address}\n"
            f"State: {host.status}    Hostname: {host.hostname or 'not identified'}\n\n"
            "[bold #9ce4d6]SERVICES[/bold #9ce4d6]\n"
            + ("\n".join(services) if services else "No service records.")
        )
        self._record_activity("TARGET", f"Selected {host.address}.")
