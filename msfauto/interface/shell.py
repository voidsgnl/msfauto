from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
import time
from ipaddress import ip_address
from pathlib import Path

try:
    import prompt_toolkit as _prompt_toolkit
    from prompt_toolkit.completion import WordCompleter as _WordCompleter
    from prompt_toolkit.history import FileHistory as _FileHistory
except ModuleNotFoundError:
    _prompt_toolkit = None
    _WordCompleter = None
    _FileHistory = None

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if _prompt_toolkit is None:
    class _FallbackPromptSession:
        """Minimal stdlib fallback when prompt-toolkit is not installed."""

        def __init__(self, **_: object) -> None:
            pass

        def prompt(self, message: object = "") -> str:
            if isinstance(message, list):
                message = "".join(str(part[1]) for part in message)
            return input(str(message))

    class _FallbackWordCompleter:
        def __init__(self, *_: object, **__: object) -> None:
            pass

    class _FallbackFileHistory:
        def __init__(self, *_: object, **__: object) -> None:
            pass

    PromptSession = _FallbackPromptSession
    WordCompleter = _FallbackWordCompleter
    FileHistory = _FallbackFileHistory
else:
    PromptSession = _prompt_toolkit.PromptSession
    WordCompleter = _WordCompleter
    FileHistory = _FileHistory

from ..assessment.approval import record_decision
from ..assessment.planner import build_plan
from ..cli import display_plan, run_safe_checks
from ..core import AssessmentApplication
from ..discovery import DiscoveryError, parse_nmap_xml
from ..execution import (
    ExploitDispatchUncertain,
    ExploitExecutionError,
    ExploitOutcomeValidator,
    MetasploitExploitDispatcher,
    MetasploitExploitReconciler,
    prepare_exploit_execution,
    reconcile_uncertain_execution,
    request_exploit_cancellation,
)
from ..exploitation import authorize_opportunity, review_opportunity
from ..integrations.metasploit import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MsgpackHttpTransport,
)
from ..reporting import ReportError, write_report
from ..scope import ScopeError, build_policy
from ..storage import WorkspaceStore
from ..storage.models import DiscoveryRun, Workspace, utc_now
from .tasks import ConsoleTask, TaskManager

COMMANDS = {
    "workspace": ("create", "list", "show", "use"),
    "scope": ("show", "validate", "update"),
    "discovery": ("run", "import", "show", "history", "compare", "observations"),
    "plan": ("build", "show"),
    "checks": ("list", "review", "approve", "run"),
    "vulnerabilities": ("list", "show"),
    "exploits": ("list", "opportunities", "review", "authorize", "executions", "prepare", "dispatch", "poll", "cancel", "reconcile", "outcome"),
    "findings": ("list", "show"),
    "report": ("generate", "show"),
    "tasks": ("list", "show"),
    "dashboard": (),
    "help": (),
    "exit": (),
    "quit": (),
}
MODES = {
    "discovery": {
        "description": "Host discovery, Nmap imports, service inventory and scan comparisons.",
        "commands": {"run": "discovery run", "scan": "discovery run", "import": "discovery import", "show": "discovery show", "history": "discovery history", "compare": "discovery compare", "observations": "observations"},
    },
    "exploit": {
        "description": "Metasploit module inventory and the controlled exploit lifecycle.",
        "commands": {"list": "exploits list", "opportunities": "exploits opportunities", "review": "exploits review", "authorize": "exploits authorize", "executions": "exploits executions", "prepare": "exploits prepare", "dispatch": "exploits dispatch", "poll": "exploits poll", "cancel": "exploits cancel", "reconcile": "exploits reconcile", "outcome": "exploits outcome"},
    },
    "analysis": {
        "description": "Assessment planning, vulnerability intelligence, checks, findings and reports.",
        "commands": {"plan": "plan", "checks": "checks", "vulnerabilities": "vulnerabilities", "findings": "findings", "report": "report", "tasks": "tasks", "dashboard": "dashboard"},
    },
    "workspace": {
        "description": "Workspace selection and authorized scope configuration.",
        "commands": {"workspace": "workspace", "scope": "scope"},
    },
}

def _ping_target(target: str) -> str:
    """Perform one bounded ICMP echo for a single address; CIDRs are not probed."""
    try:
        address = ip_address(target)
    except ValueError:
        return "not attempted (network range)"

    command = ["ping"]
    if address.version == 6:
        command.append("-6")
    command.extend(["-c", "1", "-W", "1", str(address)])
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2.0,
        )
    except FileNotFoundError:
        return "unavailable (ping command not installed)"
    except subprocess.TimeoutExpired:
        return "timed out"
    return "reachable" if result.returncode == 0 else "no reply"


COMMAND_WORDS = [
    "use", "show modes", "back", "help", "exit", "quit",
    *[command for mode in MODES.values() for command in mode["commands"]],
    *[f"{root} {sub}" for root, children in COMMANDS.items() for sub in children],
]


class CommandShell:
    """Metasploit-style persistent command console for MSFAuto."""

    def __init__(self, store: WorkspaceStore, workspace: Workspace) -> None:
        self.store = store
        self.workspace = workspace
        self.console = Console()
        history_path = Path(self.store.path).parent / "command_history"
        history_path.parent.mkdir(parents=True, exist_ok=True)
        self.session: PromptSession[str] = PromptSession(
            completer=WordCompleter(COMMAND_WORDS, sentence=True, ignore_case=True),
            complete_while_typing=True,
            history=FileHistory(str(history_path)),
        )
        if PromptSession.__module__ == __name__:
            self.console.print(
                "[yellow][!][/yellow] prompt_toolkit is unavailable; using basic input "
                "without command completion or persistent history. Install project "
                "dependencies to enable the enhanced prompt."
            )
        self.running = True
        self.mode: str | None = None
        self.tasks = TaskManager()

    def banner(self) -> None:
        logo = Text(
            "███╗   ███╗███████╗███████╗ █████╗ ██╗   ██╗████████╗ ██████╗\n"
            "████╗ ████║██╔════╝██╔════╝██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗\n"
            "██╔████╔██║███████╗█████╗  ███████║██║   ██║   ██║   ██║   ██║\n"
            "██║╚██╔╝██║╚════╝██╔══╝  ██╔══██║██║   ██║   ██║   ██║   ██║\n"
            "██║ ╚═╝ ██║███████║███████╗██║  ██║╚██████╔╝   ██║    ╚██████╔╝",
            style="bold bright_cyan",
        )
        self.console.print(Panel(
            logo,
            subtitle="AUTOMATED METASPLOIT SECURITY ASSESSMENT FRAMEWORK  •  v0.1.0",
            border_style="bright_cyan",
            padding=(1, 2),
        ))
        self._show_context()
        self.console.print("\n[dim]Type 'help' to display available commands.[/dim]\n")

    def _show_context(self) -> None:
        policy = self.workspace.policy
        targets = [str(item) for item in (*policy.networks, *policy.addresses)]
        ports = ", ".join(map(str, policy.allowed_ports)) or "discovered ports"
        rpc_connected = os.environ.get("MSFAUTO_METASPLOIT_CONNECTED") == "1"
        rpc_label = "[green]connected[/green]" if rpc_connected else "[yellow]unavailable[/yellow]"
        self.console.print(
            f"[bright_cyan][*][/bright_cyan] Metasploit RPC : {rpc_label}\n"
            f"[bright_cyan][*][/bright_cyan] Workspace      : [bold]{self.workspace.name}[/bold]\n"
            f"[bright_cyan][*][/bright_cyan] Profile        : {policy.profile}\n"
            f"[bright_cyan][*][/bright_cyan] Scope          : {', '.join(targets) or 'not configured'}\n"
            f"[bright_cyan][*][/bright_cyan] Ports          : {ports}"
        )

    def help(self) -> None:
        table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
        table.add_column("Command", style="bright_cyan", no_wrap=True)
        table.add_column("Description", style="white")
        if self.mode is None:
            rows = [
                ("use discovery", "Enter host and service discovery mode"),
                ("use exploit", "Enter exploit and Metasploit mode"),
                ("use analysis", "Enter assessment analysis mode"),
                ("use workspace", "Manage workspaces and authorized scope"),
                ("workspace create", "Create and activate a workspace with a validated target scope"),
                ("show modes", "List available operation modes"),
                ("help", "Display root-console commands"),
                ("exit", "Exit MSFAuto"),
            ]
            self.console.print("\n[bold bright_cyan]MSFAUTO ROOT CONSOLE[/bold bright_cyan]")
        else:
            descriptions = {
                "discovery": [
                    ("run", "Run discovery, enumeration and read-only planning"),
                    ("import <nmap.xml>", "Import an Nmap XML file"),
                    ("show", "Show discovered hosts and services"),
                    ("history", "List scan history"),
                    ("compare <old-id> <new-id>", "Compare two scan snapshots"),
                ],
                "exploit": [
                    ("list [filter]", "List live Metasploit exploit modules"),
                    ("opportunities", "List target-matched exploit opportunities"),
                    ("review <id> <decision> <reviewer> <rationale>", "Review one opportunity"),
                    ("authorize <id> <approver> <rationale>", "Authorize an accepted opportunity"),
                    ("executions", "List exploit execution records"),
                    ("prepare <opportunity> <authorization> <actor>", "Prepare an execution"),
                    ("dispatch <execution> <actor>", "Dispatch after exact confirmation"),
                    ("poll <execution> <actor>", "Poll a framework job"),
                    ("cancel <execution> <actor> <reason>", "Request job cancellation"),
                    ("reconcile <execution> ...", "Reconcile an uncertain dispatch"),
                    ("outcome list|record ...", "Inspect or record target-side outcomes"),
                ],
                "analysis": [
                    ("plan build|show", "Build or inspect assessment plans"),
                    ("checks list|review|approve|run", "Review and run approved checks"),
                    ("vulnerabilities list|show", "Inspect vulnerability candidates"),
                    ("findings list|show", "Inspect persisted findings"),
                    ("report generate|show", "Generate or locate reports"),
                    ("tasks list|show", "Inspect background tasks"),
                    ("dashboard", "Show workspace assessment summary"),
                ],
                "workspace": [
                    ("workspace create|list|show|use", "Manage saved workspaces"),
                    ("scope show|validate|update", "Inspect or update authorized scope"),
                ],
            }
            self.console.print(f"\n[bold bright_cyan]{self.mode.upper()} MODE[/bold bright_cyan]")
            rows = descriptions[self.mode]
            rows.extend([("back", "Return to the root console"), ("help", "Display this mode's commands"), ("exit", "Exit MSFAuto")])
        for command, description in rows:
            table.add_row(command, description)
        self.console.print(table)

    def _resolve_mode_command(self, parts: list[str]) -> tuple[str, list[str]]:
        mode = getattr(self, "mode", None)
        if mode is None:
            first = parts[0].casefold()
            if first == "use":
                return "use", parts[1:]
            if first == "show" and len(parts) > 1 and parts[1].casefold() == "modes":
                return "show modes", parts[2:]
            return (" ".join(parts[:2]) if len(parts) > 1 else parts[0], parts[2:] if len(parts) > 1 else [])
        first = parts[0].casefold()
        if first in {"help", "back", "exit", "quit"}:
            return first, parts[1:]
        commands = MODES[mode]["commands"]
        if first not in commands:
            return first, parts[1:]
        root = commands[first]
        if root in {"plan", "checks", "vulnerabilities", "findings", "report", "tasks", "workspace", "scope"}:
            if len(parts) < 2:
                return root, []
            return f"{root} {parts[1]}", parts[2:]
        return root, parts[1:]

    def _rows(self, title: str, columns: tuple[str, ...], rows: list[tuple[object, ...]]) -> None:
        table = Table(title=title, header_style="bold bright_cyan", border_style="cyan")
        for column in columns:
            table.add_column(column, overflow="fold")
        for row in rows:
            table.add_row(*(str(value) for value in row))
        self.console.print(table)
        self.console.print(f"[dim]{len(rows)} record(s)[/dim]")

    def _hosts(self) -> None:
        hosts = self.store.get_hosts(self.workspace.name)
        rows = []
        for host in hosts:
            if not host.services:
                rows.append((host.address, "—", host.status, host.hostname or "—"))
            for service in host.services:
                rows.append((host.address, f"{service.port}/{service.protocol}", service.name, " ".join(filter(None, (service.product, service.version))) or "—"))
        self._rows("DISCOVERED HOSTS & SERVICES", ("TARGET", "PORT", "SERVICE", "FINGERPRINT"), rows)

    def _observations(self, args: list[str]) -> None:
        """Inspect persisted service observations without initiating network activity."""
        action = args[0].casefold() if args else "list"
        if action == "list":
            observations = self.store.get_service_observations(self.workspace.name)
            rows = [
                (
                    item.observation_id[:8], item.target,
                    f"{item.port}/{item.transport}", item.protocol,
                    item.kind[:16], item.status, item.observed_at[:10],
                )
                for item in observations
            ]
            self._rows(
                "STORED SERVICE OBSERVATIONS",
                ("ID", "TARGET", "PORT", "PROTOCOL", "KIND", "STATUS", "OBSERVED"),
                rows,
            )
            return
        if action == "host":
            if len(args) != 2:
                self.console.print("[yellow]Usage: observations host <ip>[/yellow]")
                return
            observations = self.store.get_service_observations(
                self.workspace.name, target=args[1],
            )
            self._rows(
                f"SERVICE OBSERVATIONS — {args[1]}",
                ("ID", "PORT", "PROTOCOL", "KIND", "STATUS", "OBSERVED"),
                [
                    (
                        item.observation_id[:8], f"{item.port}/{item.transport}",
                        item.protocol, item.kind[:16], item.status, item.observed_at[:10],
                    )
                    for item in observations
                ],
            )
            return
        if action == "show":
            if len(args) != 2:
                self.console.print("[yellow]Usage: observations show <id>[/yellow]")
                return
            matches = [
                item for item in self.store.get_service_observations(self.workspace.name)
                if item.observation_id == args[1]
                or item.observation_id.startswith(args[1])
            ]
            if len(matches) != 1:
                reason = "No observation matches that ID." if not matches else "ID prefix is ambiguous; use a longer prefix."
                self.console.print(f"[yellow]{reason}[/yellow]")
                return
            item = matches[0]
            self.console.print(Panel(
                json.dumps(item.attributes, indent=2, sort_keys=True, default=str),
                title=f"{item.protocol.upper()} / {item.kind}",
                subtitle=f"{item.target}:{item.port}/{item.transport} • {item.status} • {item.observation_id}",
                border_style="cyan",
            ))
            self._rows("OBSERVATION METADATA", ("FIELD", "VALUE"), [
                ("Workspace", item.workspace),
                ("Source", item.source),
                ("Confidence", f"{item.confidence}/10"),
                ("Observed at", item.observed_at or "—"),
            ])
            return
        self.console.print(
            "[yellow]Usage: observations [list|show <id>|host <ip>][/yellow]"
        )

    def _plan(self):
        plan = self.store.get_plan(self.workspace.name)
        if plan is None:
            plan = build_plan(self.workspace.name, self.store.get_hosts(self.workspace.name), self.store.get_all_module_metadata(self.workspace.name))
            self.store.save_plan(plan)
        return plan

    def _wait_task(self, task: ConsoleTask) -> None:
        self.console.print(f"[bright_cyan][*][/bright_cyan] Task {task.task_id}: {task.name}")
        try:
            with self.console.status("[bold bright_cyan]Working…[/bold bright_cyan]", spinner="dots"):
                while task.future is not None and not task.future.done():
                    self._drain_task_events(task)
                    time.sleep(0.08)
                self._drain_task_events(task)
        except KeyboardInterrupt:
            if self.tasks.cancel(task.task_id):
                self.console.print("[yellow][!][/yellow] Cancellation requested; waiting for Nmap to stop.")
            else:
                self.console.print("[yellow][!][/yellow] This task is not cancellable.")
            while task.future is not None and not task.future.done():
                self._drain_task_events(task)
                time.sleep(0.08)
            self._drain_task_events(task)
        if task.status == "completed":
            self.console.print(f"[green][+][/green] Task {task.task_id} completed.")
        else:
            self.console.print(f"[red][!][/red] Task {task.task_id} {task.status}: {task.error or 'No additional details.'}")

    def _drain_task_events(self, task: ConsoleTask) -> None:
        while not task.events.empty():
            event = task.events.get_nowait()
            style = {"error": "red", "warning": "yellow", "success": "green"}.get(event.level, "white")
            self.console.print(f"[{style}][{event.level}][/{style}] {event.message}")

    def _metasploit_client(self) -> MetasploitClient:
        username = os.environ.get("MSFAUTO_METASPLOIT_USERNAME", "")
        password = os.environ.get("MSFAUTO_METASPLOIT_PASSWORD", "")
        if not username or not password:
            raise MetasploitError(
                "Metasploit RPC credentials are not configured. Set "
                "MSFAUTO_METASPLOIT_USERNAME and MSFAUTO_METASPLOIT_PASSWORD "
                "to connect to an existing Metasploit RPC service. "
                "For local endpoints, MSFAuto starts and supervises msfrpcd automatically "
                "when it is available."
            )
        config = MetasploitConfig(
            url=os.environ.get("MSFAUTO_METASPLOIT_URL", "http://127.0.0.1:55553/api/1.0"),
            timeout=5.0,
        )
        return MetasploitClient(
            MsgpackHttpTransport(config), username=username, password=password,
        )

    def _dashboard(self) -> None:
        hosts = self.store.get_hosts(self.workspace.name)
        vulnerabilities = self.store.get_vulnerability_candidates(self.workspace.name)
        exploits = self.store.get_exploit_opportunities(self.workspace.name)
        findings = self.store.get_findings(self.workspace.name)
        self._rows("ASSESSMENT OVERVIEW", ("METRIC", "COUNT"), [
            ("Hosts", len(hosts)),
            ("Services", sum(len(host.services) for host in hosts)),
            ("Vulnerability candidates", len(vulnerabilities)),
            ("Exploit opportunities", len(exploits)),
            ("Findings", len(findings)),
        ])

    def execute(self, line: str) -> bool:
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self.console.print(f"[red]Parse error:[/red] {exc}")
            return True
        if not parts:
            return True
        command, args = self._resolve_mode_command(parts)
        try:
            if command in {"exit", "quit"}:
                self.running = False
            elif command == "back":
                if self.mode is None:
                    self.console.print("[yellow]Already at the root console.[/yellow]")
                else:
                    self.console.print(f"[bright_cyan][*][/bright_cyan] Leaving {self.mode} mode.")
                    self.mode = None
            elif command == "use":
                if self.mode is not None:
                    self.console.print("[yellow]Use 'back' before switching operation modes.[/yellow]")
                elif len(args) != 1 or args[0].casefold() not in MODES:
                    self.console.print("[yellow]Usage: use <discovery|exploit|analysis|workspace>[/yellow]")
                else:
                    self.mode = args[0].casefold()
                    self.console.print(f"[bright_cyan][*][/bright_cyan] Entered {self.mode} mode.")
                    self.help()
            elif command == "show modes":
                self._rows("OPERATION MODES", ("MODE", "DESCRIPTION", "ACTIVE"), [
                    (name, details["description"], "*" if name == self.mode else "")
                    for name, details in MODES.items()
                ])
            elif command == "help":
                self.help()
            elif command == "workspace show":
                self._show_context()
            elif command == "workspace list":
                with sqlite3.connect(self.store.path) as db:
                    names = [row[0] for row in db.execute("SELECT name FROM workspaces ORDER BY name")]
                self._rows("WORKSPACES", ("NAME", "ACTIVE"), [(name, "*" if name == self.workspace.name else "") for name in names])
            elif command == "workspace create":
                name = " ".join(args).strip() if args else self.session.prompt("New workspace name: ").strip()
                if not name:
                    self.console.print("[yellow]Workspace name cannot be empty.[/yellow]")
                elif self.store.get(name) is not None:
                    self.console.print(f"[yellow]Workspace already exists: {name}. Use 'workspace use {name}'.[/yellow]")
                else:
                    raw_target = self.session.prompt("Target IP address or CIDR: ").strip()
                    target_policy = build_policy(
                        [raw_target], profile=self.workspace.policy.profile
                    )
                    target = str(target_policy.addresses[0]) if target_policy.addresses else str(target_policy.networks[0])
                    self.console.print(f"[green][+][/green] Valid target address/scope: {target}")
                    reachability = _ping_target(target) if target_policy.addresses else "not attempted (CIDR target)"
                    if reachability == "reachable":
                        self.console.print("[green][+][/green] Ping: host is reachable.")
                    elif reachability == "no reply":
                        self.console.print("[yellow][!][/yellow] Ping: no reply. The IP is valid; ICMP may be filtered.")
                    elif reachability == "timed out":
                        self.console.print("[yellow][!][/yellow] Ping timed out. The IP is valid; continuing.")
                    elif reachability.startswith("unavailable"):
                        self.console.print(f"[yellow][!][/yellow] Ping check {reachability}; continuing.")
                    else:
                        self.console.print(f"[dim]Ping check: {reachability}.[/dim]")
                    raw_ports = self.session.prompt("Allowed ports (comma-separated, blank for all): ")
                    policy = build_policy([raw_target], raw_ports, self.workspace.policy.profile)
                    created = Workspace(name=name, policy=policy)
                    self.store.save(created)
                    self.workspace = created
                    self.console.print(f"[green][+][/green] Workspace created and activated: {name}")
                    self._show_context()
            elif command == "workspace use":
                if not args:
                    self.console.print("[yellow]Usage: workspace use <name>[/yellow]")
                else:
                    selected = self.store.get(args[0])
                    if selected is None:
                        self.console.print(f"[red]Workspace not found: {args[0]}[/red]")
                    else:
                        self.workspace = selected
                        self.console.print(f"[green][+][/green] Active workspace: {selected.name}")
                        self._show_context()
            elif command == "scope show":
                self._show_context()
            elif command == "scope validate":
                policy = self.workspace.policy
                build_policy([*(str(item) for item in policy.networks), *(str(item) for item in policy.addresses)], ",".join(map(str, policy.allowed_ports)), policy.profile)
                self.console.print("[green][+][/green] Saved scope is valid.")
            elif command == "scope update":
                if not args:
                    self.console.print("[yellow]Usage: scope update <IP/CIDR[,IP/CIDR...]> [ports=80,443][/yellow]")
                else:
                    targets = args[0].split(",")
                    ports = next((item.split("=", 1)[1] for item in args[1:] if item.startswith("ports=")), "")
                    policy = build_policy(targets, ports, self.workspace.policy.profile)
                    self.workspace = Workspace(self.workspace.name, policy)
                    self.store.save(self.workspace)
                    self.console.print("[green][+][/green] Scope updated.")
                    self._show_context()
            elif command == "discovery run":
                application = AssessmentApplication(self.workspace, self.store)
                task = self.tasks.submit(
                    "assessment",
                    lambda cancel, emit: application.run_assessment(
                        lambda event: emit(f"[{event.stage}] {event.message}", event.level),
                        cancel_event=cancel,
                    ),
                    cancellable=True,
                )
                self._wait_task(task)
            elif command == "discovery import":
                if not args:
                    self.console.print("[yellow]Usage: discovery import <nmap.xml>[/yellow]")
                else:
                    source_path = Path(args[0]).expanduser().resolve()
                    hosts = parse_nmap_xml(source_path, self.workspace.policy)
                    timestamp = utc_now()
                    run = DiscoveryRun(
                        workspace=self.workspace.name,
                        scanner="nmap-import",
                        command=("import", str(source_path)),
                        output_path=str(source_path),
                        status="completed",
                        started_at=timestamp,
                        finished_at=timestamp,
                    )
                    self.store.save_discovery_run(run, hosts)
                    self.store.save_hosts(self.workspace.name, hosts)
                    self.console.print(
                        f"[green][+][/green] Imported {len(hosts)} host(s); "
                        f"scan ID {run.scan_id[:12]}."
                    )
            elif command == "discovery show":
                self._hosts()
            elif command == "observations":
                self._observations(args)
            elif command == "discovery history":
                runs = self.store.get_discovery_runs(self.workspace.name)
                self._rows(
                    "DISCOVERY SCAN HISTORY",
                    ("SCAN ID", "SCANNER", "STATUS", "STARTED", "FINISHED", "XML ARTIFACT"),
                    [
                        (
                            item.scan_id[:12], item.scanner, item.status,
                            item.started_at, item.finished_at,
                            item.output_path,
                        )
                        for item in runs
                    ],
                )
            elif command == "discovery compare":
                if len(args) < 2:
                    self.console.print(
                        "[yellow]Usage: discovery compare <older-scan-id> <newer-scan-id>[/yellow]"
                    )
                else:
                    runs = self.store.get_discovery_runs(self.workspace.name)
                    matches = [
                        [item for item in runs if item.scan_id.startswith(prefix)]
                        for prefix in args[:2]
                    ]
                    if any(len(items) != 1 for items in matches):
                        self.console.print(
                            "[red]Each scan ID must uniquely identify one scan in this workspace.[/red]"
                        )
                    else:
                        older, newer = matches[0][0], matches[1][0]
                        changes = self.store.compare_discovery_runs(
                            self.workspace.name, older.scan_id, newer.scan_id
                        )
                        for category, title in (
                            ("added_hosts", "NEW HOSTS"),
                            ("removed_hosts", "MISSING HOSTS"),
                            ("changed_hosts", "CHANGED HOST IDENTITY / STATE"),
                            ("added", "ADDED SERVICES"),
                            ("removed", "REMOVED SERVICES"),
                            ("changed", "CHANGED SERVICES"),
                        ):
                            self._rows(
                                title, ("ENDPOINT", "FINGERPRINT / CHANGE"),
                                changes[category],
                            )
                        total = sum(len(items) for items in changes.values())
                        if not total:
                            self.console.print("[green]No service changes between these snapshots.[/green]")
            elif command == "plan build":
                display_plan(self.store, self.workspace)
            elif command == "plan show":
                plan = self._plan()
                self._rows("ASSESSMENT PLAN", ("#", "TARGET", "PORT", "MODULE", "RISK", "CONFIDENCE"), [
                    (i, item.target, f"{item.port}/{item.protocol}", f"{item.module_type}/{item.module_name}", item.risk, f"{item.confidence}%")
                    for i, item in enumerate(plan.recommendations, 1)
                ])
            elif command in {"checks list", "checks review"}:
                plan = self._plan()
                self._rows("CHECK RECOMMENDATIONS", ("#", "TARGET", "PORT", "MODULE", "RISK", "REASON"), [
                    (i, item.target, f"{item.port}/{item.protocol}", f"{item.module_type}/{item.module_name}", item.risk, item.reason)
                    for i, item in enumerate(plan.recommendations, 1)
                ])
            elif command == "checks approve":
                if len(args) < 2:
                    self.console.print("[yellow]Usage: checks approve <recommendation#> <approver> [rationale][/yellow]")
                else:
                    plan = self._plan()
                    try:
                        recommendation = plan.recommendations[int(args[0]) - 1]
                    except (ValueError, IndexError):
                        self.console.print("[red]Recommendation number is not present in the current plan.[/red]")
                    else:
                        rationale = " ".join(args[2:]).strip() or "Explicit console approval."
                        record = record_decision(
                            self.store, self.workspace.name, recommendation,
                            "approved", args[1], rationale,
                        )
                        self.console.print(f"[green][+][/green] Approval recorded: {record.action_id[:12]}")
            elif command == "checks run":
                run_safe_checks(
                    self.store, self.workspace, 10, 2,
                    use_metasploit=False, prompt_for_approval=False,
                )
            elif command in {"vulnerabilities list", "vulnerabilities show"}:
                items = self.store.get_vulnerability_candidates(self.workspace.name)
                if args and command.endswith("show"):
                    items = [item for item in items if args[0] in item.candidate_id or args[0].lower() in item.advisory_id.lower()]
                self._rows("VULNERABILITY CANDIDATES", ("ID", "TARGET", "PORT", "ADVISORY", "STATUS", "CONFIDENCE"), [
                    (item.candidate_id[:12], item.target, f"{item.port}/{item.protocol}", item.advisory_id, item.status, f"{item.confidence}%") for item in items
                ])
            elif command == "exploits list":
                modules = self._metasploit_client().exploit_modules()
                if args:
                    query = " ".join(args).casefold()
                    modules = [name for name in modules if query in name.casefold()]
                self._rows(
                    "METASPLOIT EXPLOIT MODULE CATALOG",
                    ("#", "MODULE"),
                    [(index, name) for index, name in enumerate(modules, 1)],
                )
                if not modules:
                    self.console.print(
                        "[yellow]No modules matched. Check the filter or Metasploit RPC catalog.[/yellow]"
                    )
                self.console.print(
                    "[dim]Module inventory is not a target match or execution approval. "
                    "Use exploits opportunities to view matched targets.[/dim]"
                )
            elif command in {"exploits opportunities", "exploits review"}:
                items = self.store.get_exploit_opportunities(self.workspace.name)
                if command == "exploits review":
                    if not args:
                        self.console.print("[yellow]Usage: exploits review <id> <accepted|rejected|deferred> <reviewer> <rationale>[/yellow]")
                    else:
                        opportunity = next((item for item in items if item.opportunity_id.startswith(args[0])), None)
                        if opportunity is None:
                            self.console.print("[red]Exploit opportunity not found.[/red]")
                        elif len(args) < 4:
                            self.console.print("[yellow]Usage: exploits review <id> <accepted|rejected|deferred> <reviewer> <rationale>[/yellow]")
                        else:
                            review = review_opportunity(opportunity, args[2], args[1], " ".join(args[3:]))
                            self.store.save_exploit_review(review)
                            self.console.print(f"[green][+][/green] Review recorded: {review.review_id[:12]}")
                self._rows("EXPLOIT OPPORTUNITIES", ("ID", "TARGET", "PORT", "MODULE", "RANK", "STATUS"), [
                    (item.opportunity_id, item.target, f"{item.port}/{item.protocol}", item.module_name, item.rank, item.status) for item in items
                ])
            elif command == "exploits authorize":
                if len(args) < 3:
                    self.console.print("[yellow]Usage: exploits authorize <id> <approver> <rationale>[/yellow]")
                else:
                    opportunity = next((item for item in self.store.get_exploit_opportunities(self.workspace.name) if item.opportunity_id.startswith(args[0])), None)
                    if opportunity is None:
                        self.console.print("[red]Exploit opportunity not found.[/red]")
                    else:
                        reviews = [item for item in self.store.get_exploit_reviews(self.workspace.name) if item.opportunity_id == opportunity.opportunity_id]
                        latest = reviews[-1] if reviews else None
                        if latest is None or latest.decision != "accepted":
                            self.console.print("[red]Authorization denied: the latest review must be accepted.[/red]")
                        else:
                            authorization = authorize_opportunity(
                                opportunity, self.workspace.policy, args[1],
                                " ".join(args[2:]), review=latest,
                            )
                            self.store.save_exploit_authorization(authorization)
                            self.console.print(f"[green][+][/green] Authorization recorded: {authorization.authorization_id} (expires {authorization.expires_at}).")
            elif command == "exploits executions":
                records = self.store.get_exploit_executions(self.workspace.name)
                self._rows("EXPLOIT EXECUTIONS", ("ID", "TARGET", "PORT", "MODULE", "STATE", "JOB"), [
                    (
                        item.execution_id, item.target, item.port,
                        item.module_name, item.state, item.external_job_id or "—",
                    )
                    for item in records
                ])
            elif command == "exploits outcome":
                if not args or args[0] not in {"list", "record"}:
                    self.console.print(
                        "[yellow]Usage: exploits outcome list <execution-id> | "
                        "exploits outcome record <execution-id> <confirmed|not_confirmed|inconclusive> "
                        "<verifier> <method> <evidence-id[,id]|-> <actor> <rationale>[/yellow]"
                    )
                elif len(args) < 2:
                    self.console.print("[yellow]An execution ID is required.[/yellow]")
                else:
                    record = self.store.get_exploit_execution(args[1])
                    if record is None or record.workspace != self.workspace.name:
                        self.console.print("[red]Execution record not found in this workspace.[/red]")
                    elif args[0] == "list":
                        assessments = ExploitOutcomeValidator(
                            self.store
                        ).get_for_execution(record.execution_id)
                        self._rows(
                            "INDEPENDENT TARGET OUTCOME ASSESSMENTS",
                            ("ID", "VERDICT", "VERIFIER", "METHOD", "EVIDENCE", "ACTOR", "ASSESSED"),
                            [
                                (
                                    item.assessment_id, item.verdict, item.verifier,
                                    item.method, ", ".join(item.evidence_ids) or "—",
                                    item.actor, item.assessed_at,
                                )
                                for item in assessments
                            ],
                        )
                    elif len(args) < 8:
                        self.console.print(
                            "[yellow]Usage: exploits outcome record <execution-id> "
                            "<confirmed|not_confirmed|inconclusive> <verifier> <method> "
                            "<evidence-id[,id]|-> <actor> <rationale>[/yellow]"
                        )
                    else:
                        evidence_ids = () if args[5] == "-" else tuple(
                            item for item in args[5].split(",") if item
                        )
                        assessment = ExploitOutcomeValidator(self.store).record(
                            record.execution_id,
                            verdict=args[2],
                            verifier=args[3],
                            method=args[4],
                            evidence_ids=evidence_ids,
                            actor=args[6],
                            rationale=" ".join(args[7:]),
                        )
                        self.console.print(
                            f"[green][+][/green] Target outcome recorded: "
                            f"{assessment.assessment_id} ({assessment.verdict}). "
                            "Framework execution state was not changed."
                        )
            elif command == "exploits prepare":
                if len(args) < 3:
                    self.console.print("[yellow]Usage: exploits prepare <opportunity-id> <authorization-id> <actor>[/yellow]")
                else:
                    opportunity_matches = [
                        item for item in self.store.get_exploit_opportunities(self.workspace.name)
                        if item.opportunity_id.startswith(args[0])
                    ]
                    authorization_matches = [
                        item for item in self.store.get_exploit_authorizations(self.workspace.name)
                        if item.authorization_id.startswith(args[1])
                    ]
                    if len(opportunity_matches) > 1 or len(authorization_matches) > 1:
                        self.console.print("[red]Identifier prefix is ambiguous; use a longer ID.[/red]")
                    elif not opportunity_matches or not authorization_matches:
                        self.console.print("[red]Opportunity or authorization not found in this workspace.[/red]")
                    else:
                        opportunity = opportunity_matches[0]
                        authorization = authorization_matches[0]
                        record = prepare_exploit_execution(
                            self.store, opportunity, authorization, actor=args[2],
                        )
                        self.console.print(
                            f"[green][+][/green] Prepared execution {record.execution_id} "
                            f"for {record.target}:{record.port}. No module dispatched."
                        )
            elif command == "exploits dispatch":
                if len(args) < 2:
                    self.console.print("[yellow]Usage: exploits dispatch <execution-id> <actor>[/yellow]")
                else:
                    record = self.store.get_exploit_execution(args[0])
                    if record is None or record.workspace != self.workspace.name:
                        self.console.print("[red]Execution record not found in this workspace.[/red]")
                    elif record.state != "prepared":
                        self.console.print(f"[red]Execution is {record.state}; only prepared records can be dispatched.[/red]")
                    else:
                        self.console.print(
                            f"[bold yellow]Dispatch confirmation required[/bold yellow]\n"
                            f"Module: {record.module_name}\nTarget: {record.target}:{record.port}/{record.protocol}\n"
                            f"Authorization: {record.authorization_id[:12]}"
                        )
                        confirmation = self.session.prompt("Type DISPATCH to make the single Metasploit RPC attempt: ").strip()
                        if confirmation != "DISPATCH":
                            self.console.print("[yellow]Dispatch cancelled; execution remains prepared.[/yellow]")
                        else:
                            client = self._metasploit_client()
                            dispatcher = MetasploitExploitDispatcher(self.store, client)
                            try:
                                updated = dispatcher.dispatch(record.execution_id, actor=args[1])
                                self.console.print(
                                    f"[green][+][/green] Metasploit acknowledged job {updated.external_job_id} "
                                    f"(UUID {updated.external_uuid}); state={updated.state}."
                                )
                            except ExploitDispatchUncertain as exc:
                                self.console.print(
                                    f"[red][!][/red] {exc} Execution remains {exc.execution.state}; "
                                    "do not retry. Use exploits reconcile only after checking Metasploit."
                                )
            elif command == "exploits poll":
                if len(args) < 2:
                    self.console.print("[yellow]Usage: exploits poll <execution-id> <actor>[/yellow]")
                else:
                    record = self.store.get_exploit_execution(args[0])
                    if record is None or record.workspace != self.workspace.name:
                        self.console.print("[red]Execution record not found in this workspace.[/red]")
                    else:
                        result = MetasploitExploitReconciler(
                            self.store, self._metasploit_client()
                        ).poll(record.execution_id, actor=args[1])
                        self.console.print(
                            f"[bright_cyan][*][/bright_cyan] Framework={result.framework_status}; "
                            f"active={result.job_active}; lifecycle={result.execution.state}\n{result.detail}"
                        )
            elif command == "exploits cancel":
                if len(args) < 3:
                    self.console.print("[yellow]Usage: exploits cancel <execution-id> <actor> <reason>[/yellow]")
                else:
                    record = self.store.get_exploit_execution(args[0])
                    if record is None or record.workspace != self.workspace.name:
                        self.console.print("[red]Execution record not found in this workspace.[/red]")
                    elif not record.external_job_id:
                        self.console.print("[red]Execution has no persisted Metasploit job ID; cancellation cannot be sent.[/red]")
                    else:
                        cancelling = request_exploit_cancellation(
                            self.store, record.execution_id, actor=args[1],
                            detail="Operator requested Metasploit job cancellation: " + " ".join(args[2:]),
                        )
                        try:
                            self._metasploit_client().stop_job(int(cancelling.external_job_id))
                            self.console.print(
                                f"[yellow][!][/yellow] Stop request acknowledged for job "
                                f"{cancelling.external_job_id}. Poll to reconcile terminal state."
                            )
                        except (MetasploitError, ValueError) as exc:
                            self.console.print(
                                f"[yellow][!][/yellow] Stop outcome not confirmed: {exc}. "
                                "Lifecycle remains cancelling until reconciliation."
                            )
            elif command == "exploits reconcile":
                if len(args) < 4:
                    self.console.print(
                        "[yellow]Usage: exploits reconcile <execution-id> "
                        "<not_dispatched|running|completed|failed|timed_out|cancelled> "
                        "<actor> <reason>[/yellow]"
                    )
                else:
                    record = self.store.get_exploit_execution(args[0])
                    if record is None or record.workspace != self.workspace.name:
                        self.console.print("[red]Execution record not found in this workspace.[/red]")
                    elif record.state != "dispatch_uncertain":
                        self.console.print("[red]Only dispatch_uncertain records can be operator-reconciled.[/red]")
                    elif args[1] == "running" and len(args) < 6:
                        self.console.print(
                            "[yellow]Usage for running: exploits reconcile <id> running "
                            "<actor> <job-id> <uuid> <reason>[/yellow]"
                        )
                    else:
                        running_references = args[1] == "running"
                        updated = reconcile_uncertain_execution(
                            self.store, record.execution_id, args[1], actor=args[2],
                            external_job_id=args[3] if running_references else "",
                            external_uuid=args[4] if running_references else "",
                            rationale=" ".join(args[5:] if running_references else args[3:]),
                        )
                        self.console.print(
                            f"[green][+][/green] Reconciliation recorded: {updated.execution_id[:12]} "
                            f"-> {updated.state}."
                        )
            elif command in {"findings list", "findings show"}:
                items = self.store.get_findings(self.workspace.name)
                if args and command.endswith("show"):
                    items = [item for item in items if args[0] in item.finding_id]
                self._rows("FINDINGS", ("ID", "SEVERITY", "STATUS", "CONFIDENCE", "TITLE"), [
                    (item.finding_id[:12], item.severity, item.status, f"{item.confidence}%", item.title) for item in items
                ])
            elif command == "report generate":
                output_format = args[0] if args else "markdown"
                destination = write_report(self.store, self.workspace.name, output_format)
                self.console.print(f"[green][+][/green] Report written: {destination}")
            elif command == "report show":
                report_dir = self.store.path.parent / "reports"
                reports = sorted(report_dir.glob(f"{self.workspace.name}-*")) if report_dir.exists() else []
                self._rows("GENERATED REPORTS", ("FILE",), [(path,) for path in reports])
            elif command == "tasks list":
                self._rows("CONSOLE TASKS", ("ID", "NAME", "STATUS", "ERROR"), [
                    (task.task_id, task.name, task.status, task.error or "—")
                    for task in self.tasks.list()
                ])
            elif command == "tasks show":
                if not args:
                    self.console.print("[yellow]Usage: tasks show <id>[/yellow]")
                else:
                    task = self.tasks.get(args[0])
                    if task is None:
                        self.console.print("[red]Task not found.[/red]")
                    else:
                        self._drain_task_events(task)
                        self._rows("TASK DETAIL", ("FIELD", "VALUE"), [
                            ("ID", task.task_id), ("Name", task.name),
                            ("Status", task.status), ("Error", task.error or "—"),
                        ])
            elif command == "dashboard":
                self._dashboard()
            else:
                self.console.print(f"[red]Unknown command:[/red] {line}. Type [bright_cyan]help[/bright_cyan].")
        except (ScopeError, DiscoveryError, ReportError, MetasploitError, ExploitExecutionError, OSError, ValueError, RuntimeError) as exc:
            self.console.print(f"[red]Command failed:[/red] {exc}")
        return True

    def run(self) -> None:
        self.banner()
        while self.running:
            try:
                prompt = f"[{self.mode}] msfauto > " if self.mode else "msfauto > "
                line = self.session.prompt([("class:prompt", prompt)])
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[dim]Use 'exit' to close MSFAuto.[/dim]")
                continue
            self.execute(line)
        self.tasks.close()
        self.console.print("[bright_cyan][*][/bright_cyan] MSFAuto session closed.")
