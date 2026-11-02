from __future__ import annotations

import asyncio

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Static

from ..core import AssessmentApplication
from ..discovery import DiscoveryError
from ..storage.models import Host, Workspace
from ..storage import WorkspaceStore


class Dashboard(App[None]):
    """Guided, keyboard-driven assessment interface."""

    TITLE = "MSFAuto"
    SUB_TITLE = "Automated Security Assessment"

    CSS = """
    Screen {
        padding: 1 2;
    }

    #workspace-banner {
        height: auto;
        padding: 1 2;
        border: round $accent;
        margin-bottom: 1;
    }

    #menu {
        height: auto;
        margin-bottom: 1;
    }

    #menu Button {
        margin-right: 1;
    }

    #status {
        height: auto;
        padding: 1 2;
        border: round $primary;
        margin-bottom: 1;
    }

    #targets {
        height: 1fr;
        min-height: 8;
    }

    #details {
        height: auto;
        min-height: 5;
        padding: 1 2;
        border: round $secondary;
        margin-top: 1;
    }
    """

    BINDINGS = [
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
        targets = [str(item) for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "all discovered ports"
        yield Header()
        with Vertical():
            yield Static(
                f"[b]Workspace[/b]  {self.workspace.name}    "
                f"[b]Profile[/b]  {self.workspace.policy.profile}\n"
                f"[b]Authorized scope[/b]  {', '.join(targets) or 'not configured'}\n"
                f"[b]Ports[/b]  {ports}",
                id="workspace-banner",
            )
            with Horizontal(id="menu"):
                yield Button("Start assessment", id="discover", variant="success")
                yield Button("Browse targets", id="targets")
                yield Button("Assessment plan", id="plan")
                yield Button("Scope", id="scope")
                yield Button("Exit", id="exit", variant="error")
            yield Static("Ready. Start an assessment or browse previously discovered targets.", id="status")
            yield DataTable(id="targets", cursor_type="row", zebra_stripes=True)
            yield Static(
                "Select a target row to inspect its discovered services. Discovery uses the saved scope.",
                id="details",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#targets", DataTable)
        table.add_columns("Target", "State", "Hostname", "Open services")
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

    def _set_status(self, message: str) -> None:
        self.query_one("#status", Static).update(message)

    def _load_targets(self) -> tuple[Host, ...]:
        hosts = self.services.targets()
        self._hosts = {str(host.address): host for host in hosts}
        table = self.query_one("#targets", DataTable)
        table.clear()
        for host in hosts:
            open_services = [
                f"{service.port}/{service.protocol} {service.name or 'unknown'}"
                for service in host.services
                if service.state == "open"
            ]
            table.add_row(
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
        self._set_status("Discovery running. Scanning only the workspace's authorized scope…")
        try:
            workflow, plan = await asyncio.to_thread(
                self.services.run_assessment,
                lambda item: self.call_from_thread(
                    self._set_status, f"{item.stage}: {item.message}"
                ),
            )
            hosts = self.services.targets()
        except DiscoveryError as exc:
            self._set_status(f"[bold red]Discovery did not complete:[/bold red] {exc}")
            self.query_one("#details", Static).update(
                "Review the scope, scanner installation, and discovery error before retrying."
            )
        except Exception as exc:
            self._set_status(f"[bold red]Unexpected discovery error:[/bold red] {exc}")
        else:
            self._load_targets()
            self.query_one("#targets", DataTable).display = True
            self._set_status(
                f"Assessment {workflow.run_id[:8]} completed: {len(hosts)} host(s), "
                f"{len(plan.recommendations)} read-only recommendation(s)."
            )
            self.query_one("#details", Static).update(
                "The assessment plan is saved. Review it before taking further action; no checks were executed."
            )
        finally:
            button.disabled = False

    def show_targets(self) -> None:
        hosts = self._load_targets()
        table = self.query_one("#targets", DataTable)
        table.display = True
        if hosts:
            self._set_status(f"{len(hosts)} discovered target(s) in workspace {self.workspace.name}.")
            self.query_one("#details", Static).update("Select a row to inspect target services.")
        else:
            self._set_status("No discovered targets are stored in this workspace yet.")
            self.query_one("#details", Static).update("Use Start assessment to run discovery within the saved scope.")

    def show_plan(self) -> None:
        plan = self.services.build_assessment_plan()
        self.query_one("#targets", DataTable).display = False
        if not plan.recommendations:
            self._set_status("Assessment plan generated: no recommendations for the current observations.")
            self.query_one("#details", Static).update(
                "Import or discover hosts with identifiable services, then generate the plan again."
            )
            return
        lines = [
            f"{index}. {item.target}:{item.port}/{item.protocol}  "
            f"{item.module_type}/{item.module_name}  "
            f"[confidence {item.confidence}% | risk {item.risk}]\n   {item.reason}"
            for index, item in enumerate(plan.recommendations, start=1)
        ]
        self._set_status(f"Read-only assessment plan generated: {len(plan.recommendations)} recommendation(s).")
        self.query_one("#details", Static).update("\n\n".join(lines))

    def show_scope(self) -> None:
        self.query_one("#targets", DataTable).display = False
        targets = [str(item) for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "all discovered ports"
        self._set_status("Authorization scope — read-only review")
        self.query_one("#details", Static).update(
            f"Workspace: {self.workspace.name}\n"
            f"Profile: {self.workspace.policy.profile}\n"
            f"Authorized targets: {', '.join(targets) or 'none'}\n"
            f"Allowed ports: {ports}\n\n"
            "Discovery results do not grant permission for intrusive operations."
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
            f"Target: {host.address}\n"
            f"State: {host.status}\n"
            f"Hostname: {host.hostname or 'not identified'}\n"
            f"Services:\n"
            + ("\n".join(service_lines) if service_lines else "  No service details recorded.")
        )
        self.query_one("#details", Static).update(detail)
        self._set_status(f"Selected target {host.address}.")
