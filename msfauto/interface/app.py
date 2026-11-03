from __future__ import annotations

import asyncio
import sqlite3
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Static

from ..core import AssessmentApplication, WorkflowError
from ..discovery import DiscoveryError
from ..storage import WorkspaceStore
from ..storage.models import Host, Workspace


class Dashboard(App[None]):
    """Terminal-native, keyboard-driven assessment console."""

    TITLE = "MSFAuto"
    SUB_TITLE = "LOCAL ASSESSMENT CONSOLE"

    CSS = """
    Screen {
        background: #0b1014;
        color: #d7e1e7;
        padding: 0 1;
    }

    Header {
        background: #101a20;
        color: #d7e1e7;
    }

    Footer {
        background: #101a20;
        color: #91a4ad;
    }

    #brand {
        height: 5;
        padding: 0 2;
        border: round #287c78;
        background: #101a20;
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

    #toolbar {
        height: 3;
        margin-bottom: 1;
    }

    #toolbar Button {
        min-width: 15;
        margin-right: 1;
        border: tall #344750;
        background: #152129;
        color: #d7e1e7;
    }

    #toolbar Button:focus {
        border: tall #59b9a8;
    }

    #activity {
        height: 3;
        padding: 0 2;
        border: round #344750;
        background: #101a20;
        margin-bottom: 1;
    }

    #targets {
        height: 1fr;
        min-height: 8;
        border: round #344750;
        background: #0e151a;
    }

    #details {
        height: 10;
        min-height: 6;
        padding: 1 2;
        border: round #287c78;
        background: #101a20;
        margin-top: 1;
        overflow-y: auto;
    }

    DataTable > .datatable--header {
        background: #16262c;
        color: #9ce4d6;
    }

    DataTable > .datatable--cursor {
        background: #17413f;
        color: #ffffff;
    }
    """

    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        ("d", "discover", "Discover"),
        ("t", "targets", "Targets"),
        ("p", "plan", "Plan"),
        ("s", "scope", "Scope"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, workspace: Workspace, store: WorkspaceStore) -> None:
        super().__init__()
        self.workspace = workspace
        self.store = store
        self.services = AssessmentApplication(workspace, store)
        self._hosts: dict[str, Host] = {}

    def compose(self) -> ComposeResult:
        targets = [
            str(item)
            for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)
        ]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "discovered ports"
        yield Header()
        with Vertical():
            yield Static(
                "[b]███╗   ███╗███████╗███████╗[/b]  [bold #9ce4d6]MSFAuto[/bold #9ce4d6]  "
                "[dim]v0.1.0  /  ASSESSMENT CONSOLE[/dim]\n"
                "[dim]Scope-aware discovery  •  Explainable planning  •  Evidence-led review[/dim]",
                id="brand",
            )
            yield Static(
                f"[bold #9ce4d6]WORKSPACE[/bold #d7e1e7]  {self.workspace.name}    "
                f"[bold #9ce4d6]PROFILE[/bold #d7e1e7]  {self.workspace.policy.profile}\n"
                f"[bold #9ce4d6]AUTHORIZED SCOPE[/bold #d7e1e7]  "
                f"{', '.join(targets) or 'not configured'}\n"
                f"[bold #9ce4d6]PORT POLICY[/bold #d7e1e7]  {ports}",
                id="context",
            )
            with Horizontal(id="toolbar"):
                yield Button("Discover  (D)", id="discover", variant="success")
                yield Button("Targets  (T)", id="targets")
                yield Button("Plan  (P)", id="plan")
                yield Button("Scope  (S)", id="scope")
                yield Button("Exit  (Q)", id="exit", variant="error")
            yield Static(
                "[bold #9ce4d6]READY[/bold #9ce4d6]  Workspace loaded. "
                "Choose an action or use the keyboard shortcuts.",
                id="activity",
            )
            yield DataTable(id="targets", cursor_type="row", zebra_stripes=True)
            yield Static(
                "[bold #9ce4d6]DETAILS[/bold #9ce4d6]\n"
                "Target information and assessment output will appear here.",
                id="details",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#targets", DataTable)
        table.add_columns("#", "Address", "State", "Hostname", "Open services")
        table.display = False
        self._load_targets()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = event.button.id
        if action == "discover":
            self.run_worker(self.run_discovery(), name="discovery", exclusive=True)
        elif action == "targets":
            self.show_targets()
        elif action == "plan":
            self.show_plan()
        elif action == "scope":
            self.show_scope()
        elif action == "exit":
            self.exit()

    def action_discover(self) -> None:
        self.run_worker(self.run_discovery(), name="discovery", exclusive=True)

    def action_targets(self) -> None:
        self.show_targets()

    def action_plan(self) -> None:
        self.show_plan()

    def action_scope(self) -> None:
        self.show_scope()

    def _set_status(self, message: str, level: str = "info") -> None:
        colors = {"info": "#9ce4d6", "success": "#8bd49c", "warning": "#e8c879", "error": "#f08b86"}
        label = {"info": "INFO", "success": "OK", "warning": "NOTICE", "error": "ERROR"}.get(
            level, "INFO"
        )
        self.query_one("#activity", Static).update(
            f"[bold {colors.get(level, colors['info'])}]{label}[/bold]  {message}"
        )

    def _load_targets(self) -> tuple[Host, ...]:
        hosts = self.services.targets()
        self._hosts = {str(host.address): host for host in hosts}
        table = self.query_one("#targets", DataTable)
        table.clear()
        for index, host in enumerate(hosts, start=1):
            open_services = [
                f"{service.port}/{service.protocol} {service.name or 'unknown'}"
                for service in host.services
                if service.state == "open"
            ]
            table.add_row(
                str(index),
                str(host.address),
                host.status,
                host.hostname or "—",
                ", ".join(open_services) or "—",
                key=str(host.address),
            )
        return hosts

    async def run_discovery(self) -> None:
        button = self.query_one("#discover", Button)
        button.disabled = True
        self._set_status("Discovery is running within the workspace authorization policy.")
        try:
            workflow, plan = await asyncio.to_thread(
                self.services.run_assessment,
                lambda item: self.call_from_thread(
                    self._set_status, f"{item.stage.upper()}  {item.message}"
                ),
            )
            hosts = self.services.targets()
        except (DiscoveryError, WorkflowError, OSError, sqlite3.Error) as exc:
            self._set_status(f"Assessment failed: {exc}", "error")
            self.query_one("#details", Static).update(
                "[bold #f08b86]ASSESSMENT ERROR[/bold #f08b86]\n"
                "Review the saved scope, scanner availability, and assessment data before retrying."
            )
        else:
            self._load_targets()
            self.query_one("#targets", DataTable).display = True
            self._set_status(
                f"Run {workflow.run_id[:8]} completed — {len(hosts)} host(s), "
                f"{len(plan.recommendations)} recommendation(s).",
                "success",
            )
            self.query_one("#details", Static).update(
                "[bold #9ce4d6]RUN SUMMARY[/bold #9ce4d6]\n"
                f"Run ID: {workflow.run_id}\n"
                f"Discovered hosts: {len(hosts)}\n"
                f"Read-only recommendations: {len(plan.recommendations)}\n\n"
                "No active checks were dispatched by discovery or planning."
            )
        finally:
            button.disabled = False

    def show_targets(self) -> None:
        hosts = self._load_targets()
        table = self.query_one("#targets", DataTable)
        table.display = True
        if hosts:
            self._set_status(
                f"{len(hosts)} stored target(s) in workspace {self.workspace.name}.",
                "success",
            )
            self.query_one("#details", Static).update(
                "[bold #9ce4d6]TARGET DETAILS[/bold #9ce4d6]\n"
                "Select a row to inspect recorded services, products, and versions."
            )
        else:
            self._set_status("No discovered targets are stored in this workspace.", "warning")
            self.query_one("#details", Static).update(
                "Run discovery to populate this workspace with observations from its saved scope."
            )

    def show_plan(self) -> None:
        plan = self.services.build_assessment_plan()
        self.query_one("#targets", DataTable).display = False
        if not plan.recommendations:
            self._set_status("No recommendations match the current stored observations.", "warning")
            self.query_one("#details", Static).update(
                "[bold #e8c879]PLAN IS EMPTY[/bold #e8c879]\n"
                "The planner needs open services and matching module metadata. "
                "An empty plan does not indicate that a host is secure."
            )
            return
        lines = [
            f"[bold #9ce4d6]{index:02d}[/bold #9ce4d6]  "
            f"{item.target}:{item.port}/{item.protocol}  "
            f"{item.module_type}/{item.module_name}\n"
            f"     confidence {item.confidence}%  |  risk {item.risk}\n"
            f"     {item.reason}"
            for index, item in enumerate(plan.recommendations, start=1)
        ]
        self._set_status(
            f"Generated {len(plan.recommendations)} read-only recommendation(s).",
            "success",
        )
        self.query_one("#details", Static).update(
            "[bold #9ce4d6]ASSESSMENT PLAN[/bold #9ce4d6]\n\n" + "\n\n".join(lines)
        )

    def show_scope(self) -> None:
        self.query_one("#targets", DataTable).display = False
        targets = [
            str(item)
            for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)
        ]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "all discovered ports"
        self._set_status("Reviewing the saved authorization policy.")
        self.query_one("#details", Static).update(
            "[bold #9ce4d6]AUTHORIZATION POLICY[/bold #9ce4d6]\n"
            f"Workspace: {self.workspace.name}\n"
            f"Profile: {self.workspace.policy.profile}\n"
            f"Authorized targets: {', '.join(targets) or 'none'}\n"
            f"Allowed ports: {ports}\n\n"
            "[bold #e8c879]IMPORTANT[/bold #e8c879]  Discovery observations do not authorize "
            "intrusive operations."
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "targets":
            return
        host = self._hosts.get(str(event.row_key.value))
        if host is None:
            return
        service_lines = [
            f"  {service.port}/{service.protocol}  {service.state}  "
            f"{service.name} {service.product} {service.version}".rstrip()
            for service in host.services
        ]
        detail = (
            "[bold #9ce4d6]SELECTED TARGET[/bold #9ce4d6]\n"
            f"Address: {host.address}\n"
            f"State: {host.status}\n"
            f"Hostname: {host.hostname or 'not identified'}\n"
            "Services:\n"
            + ("\n".join(service_lines) if service_lines else "  No service details recorded.")
        )
        self.query_one("#details", Static).update(detail)
        self._set_status(f"Selected {host.address}.")
