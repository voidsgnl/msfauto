from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Label, Static

from .models import Workspace
from .storage import WorkspaceStore


class Dashboard(App[None]):
    """Initial Textual dashboard; actions remain safe and informational."""

    TITLE = "MSFAuto"
    CSS = """
    Screen {
        padding: 1 2;
    }

    #content {
        height: auto;
        border: round $accent;
        padding: 1 2;
    }

    .muted {
        color: $text-muted;
    }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self, workspace: Workspace, store: WorkspaceStore) -> None:
        super().__init__()
        self.workspace = workspace
        self.store = store

    def compose(self) -> ComposeResult:
        targets = [str(item) for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "all discovered ports"
        hosts = self.store.get_hosts(self.workspace.name)
        plan = self.store.get_plan(self.workspace.name)
        jobs = self.store.get_jobs(self.workspace.name)
        with Vertical(id="content"):
            yield Label(f"Workspace: {self.workspace.name}")
            yield Label(f"Profile: {self.workspace.policy.profile}")
            yield Label(f"Authorized targets: {', '.join(targets)}")
            yield Label(f"Allowed ports: {ports}")
            yield Static("")
            yield Label(f"Stored hosts: {len(hosts)}")
            yield Label(f"Stored plan recommendations: {len(plan.recommendations) if plan else 0}")
            yield Label(f"Check jobs: {len(jobs)}")
            if jobs:
                for job in jobs[:5]:
                    yield Label(f"{job.status}: {job.target}:{job.port} -> {job.module_name}")
                    for event in self.store.get_job_events(job.job_id)[-2:]:
                        yield Label(f"  [{event.level}] {event.message}", classes="muted")
            yield Static("")
            yield Label("Only scope-checked, non-invasive check adapters may be connected.", classes="muted")
            yield Label("Press q to exit.", classes="muted")
        yield Footer()
