from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Header, Label, Static

from .models import Workspace


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

    def __init__(self, workspace: Workspace) -> None:
        super().__init__()
        self.workspace = workspace

    def compose(self) -> ComposeResult:
        targets = [str(item) for item in (*self.workspace.policy.networks, *self.workspace.policy.addresses)]
        ports = ", ".join(map(str, self.workspace.policy.allowed_ports)) or "all discovered ports"
        with Vertical(id="content"):
            yield Label(f"Workspace: {self.workspace.name}")
            yield Label(f"Profile: {self.workspace.policy.profile}")
            yield Label(f"Authorized targets: {', '.join(targets)}")
            yield Label(f"Allowed ports: {ports}")
            yield Static("")
            yield Label("Discovery, planning, and execution are not enabled in this MVP.", classes="muted")
            yield Label("Press q to exit.", classes="muted")
        yield Footer()

