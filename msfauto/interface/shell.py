from __future__ import annotations

import shlex
import sqlite3
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..assessment.approval import record_decision
from ..assessment.planner import build_plan
from ..cli import display_plan, run_discovery, run_safe_checks
from ..discovery import DiscoveryError, parse_nmap_xml
from ..exploitation import authorize_opportunity, review_opportunity
from ..reporting import ReportError, write_report
from ..scope import ScopeError, build_policy
from ..storage import WorkspaceStore
from ..storage.models import Workspace

COMMANDS = {
    "workspace": ("create", "list", "show", "use"),
    "scope": ("show", "validate", "update"),
    "discovery": ("run", "import", "show"),
    "plan": ("build", "show"),
    "checks": ("list", "review", "approve", "run"),
    "vulnerabilities": ("list", "show"),
    "exploits": ("list", "review", "authorize"),
    "findings": ("list", "show"),
    "report": ("generate", "show"),
    "dashboard": (),
    "help": (),
    "exit": (),
    "quit": (),
}
COMMAND_WORDS = [
    f"{root} {sub}" for root, children in COMMANDS.items() for sub in children
] + ["help", "exit", "quit", "dashboard"]


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
        self.running = True

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
        self.console.print(
            f"[bright_cyan][*][/bright_cyan] Metasploit RPC : [green]configured[/green]\n"
            f"[bright_cyan][*][/bright_cyan] Workspace      : [bold]{self.workspace.name}[/bold]\n"
            f"[bright_cyan][*][/bright_cyan] Profile        : {policy.profile}\n"
            f"[bright_cyan][*][/bright_cyan] Scope          : {', '.join(targets) or 'not configured'}\n"
            f"[bright_cyan][*][/bright_cyan] Ports          : {ports}"
        )

    def help(self) -> None:
        table = Table(show_header=False, box=None, padding=(0, 2), expand=False)
        table.add_column("Command", style="bright_cyan", no_wrap=True)
        table.add_column("Description", style="white")
        groups = [
            ("WORKSPACE", [("workspace create", "Create a workspace"), ("workspace list", "List saved workspaces"), ("workspace show", "Show current workspace"), ("workspace use", "Switch workspace")]),
            ("SCOPE", [("scope show", "Display authorized scope"), ("scope validate", "Validate saved scope"), ("scope update", "Replace scope and port limits")]),
            ("DISCOVERY", [("discovery run", "Run discovery, enumeration and read-only planning"), ("discovery import", "Import an Nmap XML file"), ("discovery show", "Show discovered hosts and services")]),
            ("PLANNING", [("plan build", "Build an assessment plan"), ("plan show", "Display the current plan")]),
            ("SECURITY CHECKS", [("checks list", "List planned checks"), ("checks review", "Review check recommendations"), ("checks approve <#>", "Approve one exact planned check"), ("checks run", "Run approved bounded checks")]),
            ("VULNERABILITIES", [("vulnerabilities list", "List vulnerability candidates"), ("vulnerabilities show", "Show candidate details")]),
            ("EXPLOIT INTELLIGENCE", [("exploits list", "List matched exploit opportunities"), ("exploits review <id>", "Record an explicit opportunity review"), ("exploits authorize <id>", "Authorize an accepted opportunity")]),
            ("FINDINGS", [("findings list", "List recorded findings"), ("findings show", "Show finding details")]),
            ("REPORTING", [("report generate", "Generate a JSON or Markdown report"), ("report show", "Show the latest report location")]),
            ("GENERAL", [("dashboard", "Show workspace assessment summary"), ("help", "Display this command reference"), ("exit", "Exit MSFAuto")]),
        ]
        for heading, commands in groups:
            self.console.print(f"\n[bold bright_cyan]{heading}[/bold bright_cyan]")
            for command, description in commands:
                table.add_row(command, description)
        self.console.print(table)

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

    def _plan(self):
        plan = self.store.get_plan(self.workspace.name)
        if plan is None:
            plan = build_plan(self.workspace.name, self.store.get_hosts(self.workspace.name), self.store.get_all_module_metadata(self.workspace.name))
            self.store.save_plan(plan)
        return plan

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
        command = " ".join(parts[:2]) if len(parts) > 1 else parts[0]
        args = parts[2:] if len(parts) > 1 else []
        try:
            if command in {"exit", "quit"}:
                self.running = False
            elif command == "help":
                self.help()
            elif command == "workspace show":
                self._show_context()
            elif command == "workspace list":
                with sqlite3.connect(self.store.path) as db:
                    names = [row[0] for row in db.execute("SELECT name FROM workspaces ORDER BY name")]
                self._rows("WORKSPACES", ("NAME", "ACTIVE"), [(name, "*" if name == self.workspace.name else "") for name in names])
            elif command == "workspace create":
                if not args:
                    name = self.session.prompt("New workspace name: ").strip()
                else:
                    name = args[0]
                raw_targets = self.session.prompt("Authorized IPs/CIDRs (comma-separated): ")
                raw_ports = self.session.prompt("Allowed ports (comma-separated, blank for all): ")
                policy = build_policy(raw_targets.split(","), raw_ports, self.workspace.policy.profile)
                self.store.save(Workspace(name=name, policy=policy))
                self.console.print(f"[green][+][/green] Workspace created: {name}")
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
                run_discovery(self.store, self.workspace)
            elif command == "discovery import":
                if not args:
                    self.console.print("[yellow]Usage: discovery import <nmap.xml>[/yellow]")
                else:
                    hosts = parse_nmap_xml(Path(args[0]), self.workspace.policy)
                    self.store.save_hosts(self.workspace.name, hosts)
                    self.console.print(f"[green][+][/green] Imported {len(hosts)} host(s).")
            elif command == "discovery show":
                self._hosts()
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
            elif command in {"exploits list", "exploits review"}:
                items = self.store.get_exploit_opportunities(self.workspace.name)
                if command == "exploits review" and args:
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
                    (item.opportunity_id[:12], item.target, f"{item.port}/{item.protocol}", item.module_name, item.rank, item.status) for item in items
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
                            self.console.print(f"[green][+][/green] Authorization recorded: {authorization.authorization_id[:12]} (expires {authorization.expires_at}).")
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
            elif command == "dashboard":
                self._dashboard()
            else:
                self.console.print(f"[red]Unknown command:[/red] {line}. Type [bright_cyan]help[/bright_cyan].")
        except (ScopeError, DiscoveryError, ReportError, OSError, ValueError) as exc:
            self.console.print(f"[red]Command failed:[/red] {exc}")
        return True

    def run(self) -> None:
        self.banner()
        while self.running:
            try:
                line = self.session.prompt([("class:prompt", "msfauto > ")])
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[dim]Use 'exit' to close MSFAuto.[/dim]")
                continue
            self.execute(line)
        self.console.print("[bright_cyan][*][/bright_cyan] MSFAuto session closed.")
