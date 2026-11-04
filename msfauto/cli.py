from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path

from .assessment.approval import action_id, record_decision
from .assessment.planner import build_plan
from .core import AssessmentApplication
from .discovery import DiscoveryError, parse_nmap_xml
from .evidence import EvidenceCollector
from .execution import CheckRequest, JobError, JobManager, MetasploitSafeAdapter
from .integrations.metasploit import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MsgpackHttpTransport,
)
from .reporting import ReportError, write_report
from .scope import PROFILES, ScopeError, build_policy
from .storage import WorkspaceStore
from .storage.models import ScopePolicy, Workspace


def default_store() -> WorkspaceStore:
    root = Path(os.environ.get("MSFAUTO_HOME", Path.home() / ".msfauto"))
    return WorkspaceStore(root / "workspaces.sqlite3")


def display_policy(policy: ScopePolicy) -> None:
    targets = [str(item) for item in (*policy.networks, *policy.addresses)]
    print(f"Profile: {policy.profile}")
    if policy.allows_dangerous_actions:
        print("Warning: dangerous actions profile selected; actions still require explicit future approval.")
    print(f"Targets: {', '.join(targets) or 'not configured'}")
    print(f"Ports: {', '.join(map(str, policy.allowed_ports)) or 'all discovered ports'}")


def display_next_steps(workspace: Workspace) -> None:
    print("\nType 'help' at the MSFAuto prompt to see available commands.")


def display_plan(store: WorkspaceStore, workspace: Workspace) -> None:
    plan = build_plan(
        workspace.name,
        store.get_hosts(workspace.name),
        store.get_all_module_metadata(workspace.name),
    )
    store.save_plan(plan)
    print(f"Plan for workspace {workspace.name}: {len(plan.recommendations)} recommendation(s)")
    for index, recommendation in enumerate(plan.recommendations, start=1):
        print(
            f"{index}. {recommendation.target}:{recommendation.port}/{recommendation.protocol} "
            f"-> {recommendation.module_type}/{recommendation.module_name} "
            f"[confidence={recommendation.confidence}% risk={recommendation.risk}]"
        )
        print(f"   {recommendation.reason}")


def run_discovery(store: WorkspaceStore, workspace: Workspace) -> int:
    application = AssessmentApplication(workspace, store)
    print("Starting the saved-scope assessment workflow (discovery + read-only planning).")
    try:
        run, plan = application.run_assessment(
            lambda event: print(f"[{event.stage}] {event.message}")
        )
    except (DiscoveryError, RuntimeError) as exc:
        print(f"Assessment failed: {exc}")
        return 2
    print(
        f"Assessment {run.run_id} completed: "
        f"{len(store.get_hosts(workspace.name))} host(s), "
        f"{len(plan.recommendations)} read-only recommendation(s)."
    )
    print("No active checks were dispatched.")
    return 0

def run_safe_checks(
    store: WorkspaceStore,
    workspace: Workspace,
    max_checks: int,
    workers: int,
    use_metasploit: bool = False,
    prompt_for_approval: bool = True,
) -> int:
    plan = store.get_plan(workspace.name)
    if plan is None:
        plan = build_plan(
            workspace.name,
            store.get_hosts(workspace.name),
            store.get_all_module_metadata(workspace.name),
        )
        store.save_plan(plan)
    if not plan.recommendations:
        print("No recommendations are available for safe checks.")
        return 0
    if use_metasploit and (
        not os.environ.get("MSFAUTO_METASPLOIT_USERNAME")
        or not os.environ.get("MSFAUTO_METASPLOIT_PASSWORD")
    ):
        print(
            "Metasploit mode requires MSFAUTO_METASPLOIT_USERNAME and "
            "MSFAUTO_METASPLOIT_PASSWORD."
        )
        return 2
    adapter = None
    if use_metasploit:
        username = os.environ.get("MSFAUTO_METASPLOIT_USERNAME", "")
        password = os.environ.get("MSFAUTO_METASPLOIT_PASSWORD", "")
        config = MetasploitConfig(
            url=os.environ.get(
                "MSFAUTO_METASPLOIT_URL",
                "http://127.0.0.1:55553/api/1.0",
            ),
            timeout=5.0,
        )
        try:
            client = MetasploitClient(
                MsgpackHttpTransport(config),
                username=username,
                password=password,
            )
        except MetasploitError as exc:
            print(f"Metasploit connection failed: {exc}")
            return 2
        adapter = MetasploitSafeAdapter(client)

    selected = plan.recommendations[:max_checks]
    approved = []
    if prompt_for_approval:
        print("Each recommendation requires a separate, recorded decision.")
        approver = input("Approver identifier: ").strip()
        if not approver:
            print("No approver identifier supplied; no checks were dispatched.")
            return 2
        for index, recommendation in enumerate(selected, start=1):
            module_name = f"{recommendation.module_type}/{recommendation.module_name}"
            print(
                f"\n[{index}/{len(selected)}] {recommendation.target}:"
                f"{recommendation.port}/{recommendation.protocol} -> {module_name}"
            )
            print(f"Risk: {recommendation.risk} | Confidence: {recommendation.confidence}%")
            print(f"Reason: {recommendation.reason}")
            answer = input("Type APPROVE to authorize this exact action, or anything else to reject: ").strip()
            decision = "approved" if answer == "APPROVE" else "rejected"
            record = record_decision(
                store, workspace.name, recommendation, decision, approver,
                "Operator entered the exact APPROVE confirmation." if decision == "approved"
                else "Operator did not enter the exact APPROVE confirmation.",
            )
            print(f"Decision recorded: {record.decision} ({record.action_id[:12]}).")
            if decision == "approved":
                approved.append(recommendation)
    else:
        for recommendation in selected:
            approval = store.get_approval(action_id(workspace.name, recommendation))
            expected_module = f"{recommendation.module_type}/{recommendation.module_name}"
            if (
                approval is not None
                and approval.decision == "approved"
                and approval.workspace == workspace.name
                and approval.target == recommendation.target
                and approval.port == recommendation.port
                and approval.protocol == recommendation.protocol
                and approval.module_name == expected_module
            ):
                approved.append(recommendation)
        print(
            f"Using persisted approvals: {len(approved)} approved, "
            f"{len(selected) - len(approved)} not approved."
        )

    if not approved:
        print("No recommendations were approved; no checks were dispatched.")
        return 0

    manager = JobManager(
        workspace.policy,
        max_workers=workers,
        adapter=adapter,
        approval_store=store,
    )
    evidence_collector = EvidenceCollector(store)
    job_ids: list[str] = []
    try:
        for recommendation in approved:
            approval = store.get_approval(action_id(workspace.name, recommendation))
            expected_module = f"{recommendation.module_type}/{recommendation.module_name}"
            if (
                approval is None
                or approval.decision != "approved"
                or approval.workspace != workspace.name
                or approval.target != recommendation.target
                or approval.port != recommendation.port
                or approval.protocol != recommendation.protocol
                or approval.module_name != expected_module
            ):
                print("Skipping recommendation: its persisted approval is missing or does not match.")
                continue
            try:
                job_ids.append(
                    manager.submit(
                        CheckRequest(
                            workspace=workspace.name,
                            target=recommendation.target,
                            port=recommendation.port,
                            protocol=recommendation.protocol,
                            module_name=f"{recommendation.module_type}/{recommendation.module_name}",
                            approval_id=approval.action_id,
                            risk=recommendation.risk,
                        )
                    )
                )
            except JobError as exc:
                print(f"Skipping recommendation due to scope or validation error: {exc}")
        counts: Counter[str] = Counter()
        for job_id in job_ids:
            job = manager.wait(job_id, timeout=75 if use_metasploit else 5)
            counts[job.status] += 1
            store.save_job(job)
            events = manager.events(job_id)
            adapter_result = manager.result(job_id)
            result_payload = {
                "status": job.status,
                "error": job.error,
                "adapter_output": adapter_result.output,
                "events": [
                    {
                        "level": event.level,
                        "message": event.message,
                        "timestamp": event.timestamp,
                    }
                    for event in events
                ],
            }
            evidence = evidence_collector.collect(
                workspace=workspace.name,
                source=f"execution:{job.module_name}",
                target=job.target,
                evidence_type="execution-result",
                summary=(
                    f"{job.status} result for {job.module_name} on "
                    f"{job.target}:{job.port}/{job.protocol}."
                ),
                content=json.dumps(result_payload, sort_keys=True).encode("utf-8"),
                metadata={
                    "job_id": job.job_id,
                    "module_name": job.module_name,
                    "port": job.port,
                    "protocol": job.protocol,
                    "status": job.status,
                },
            )
            print(
                f"  Evidence captured: {evidence.evidence_id[:12]} "
                f"(SHA-256 {evidence.sha256[:12]}…)."
            )
            for event in events:
                store.save_job_event(event)
            print(f"{job.job_id[:8]} {job.status}: {job.target}:{job.port} -> {job.module_name}")
        if counts:
            print("Summary:", ", ".join(f"{status}={count}" for status, count in sorted(counts.items())))
    finally:
        manager.close()
    return 0


def configure_workspace(store: WorkspaceStore, name: str, profile: str = "safe") -> Workspace:
    raw_targets = input("Authorized IP addresses or CIDRs (comma-separated): ")
    raw_ports = input("Optional ports (comma-separated, blank for all): ")
    policy = build_policy(raw_targets.split(","), raw_ports, profile)
    workspace = Workspace(name=name, policy=policy)
    store.save(workspace)
    print("\nWorkspace saved.")
    display_policy(policy)
    display_next_steps(workspace)
    return workspace


def interactive(store: WorkspaceStore, workspace_name: str, profile: str) -> int:
    workspace = store.get(workspace_name)
    if workspace is None:
        print(f"Creating workspace: {workspace_name}")
        try:
            workspace = configure_workspace(store, workspace_name, profile)
        except ScopeError as exc:
            print(f"Scope error: {exc}")
            return 2

    from .interface import CommandShell
    from .integrations.metasploit import (
        MetasploitClient,
        MetasploitConfig,
        MsgpackHttpTransport,
    )
    from .integrations.metasploit.process import MetasploitProcessManager

    rpc_url = os.environ.get(
        "MSFAUTO_METASPLOIT_URL", "http://127.0.0.1:55553/api/1.0"
    )
    process_manager = MetasploitProcessManager(rpc_url)
    username = os.environ.get("MSFAUTO_METASPLOIT_USERNAME", "")
    password = os.environ.get("MSFAUTO_METASPLOIT_PASSWORD", "")
    try:
        try:
            username, password = process_manager.start(username, password)
            # Authenticate before advertising the RPC service as ready. This also
            # detects msfrpcd builds that do not support environment credentials.
            MetasploitClient(
                MsgpackHttpTransport(MetasploitConfig(url=rpc_url, timeout=5.0)),
                username=username,
                password=password,
            )
            os.environ["MSFAUTO_METASPLOIT_USERNAME"] = username
            os.environ["MSFAUTO_METASPLOIT_PASSWORD"] = password
            state = "Started local msfrpcd" if process_manager.started else "Using existing Metasploit RPC service"
            print(f"[+] {state} at {rpc_url}")
        except MetasploitError as exc:
            if process_manager.started:
                process_manager.stop()
            print(f"[!] Metasploit RPC unavailable: {exc}")
        CommandShell(store, workspace).run()
    finally:
        process_manager.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local terminal-first assessment orchestrator.")
    parser.add_argument("command", nargs="?", choices=("shell",), help="Open the interactive MSFAuto command shell.")
    parser.add_argument("--workspace", default="default", help="Workspace name to open.")
    parser.add_argument("--show-scope", action="store_true", help="Print the saved scope and exit.")
    parser.add_argument("--shell", action="store_true", help="Open the interactive MSFAuto command shell (the default).")
    parser.add_argument("--import-nmap", type=Path, help="Import an Nmap XML result into the workspace.")
    parser.add_argument("--discover", action="store_true", help="Run the saved-scope discovery and read-only planning workflow.")
    parser.add_argument("--show-plan", action="store_true", help="Build and print a read-only assessment plan.")
    parser.add_argument("--run-safe-checks", action="store_true", help="Run bounded non-invasive checks from the plan.")
    parser.add_argument(
        "--metasploit",
        action="store_true",
        help="Use the allowlisted Metasploit RPC adapter with --run-safe-checks.",
    )
    parser.add_argument("--max-checks", type=int, default=10, help="Maximum recommendations to run with --run-safe-checks.")
    parser.add_argument("--check-workers", type=int, default=2, help="Concurrent workers for --run-safe-checks.")
    parser.add_argument("--report", choices=("json", "markdown"), help="Export a workspace assessment report.")
    parser.add_argument("--report-output", type=Path, help="Optional report destination; extension must match --report.")
    parser.add_argument(
        "--profile",
        choices=PROFILES,
        default="safe",
        help="Workspace action profile. safe is the default; dangerous-actions only enables future gated actions.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    store = default_store()
    if args.report is not None:
        try:
            destination = write_report(store, args.workspace, args.report, args.report_output)
        except ReportError as exc:
            print(f"Report error: {exc}")
            return 2
        print(f"Report written: {destination}")
        return 0
    if args.report_output is not None:
        print("--report-output requires --report json or --report markdown.")
        return 2
    if args.show_scope:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        display_policy(workspace.policy)
        return 0
    if args.import_nmap is not None:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        try:
            hosts = parse_nmap_xml(args.import_nmap, workspace.policy)
            store.save_hosts(workspace.name, hosts)
        except DiscoveryError as exc:
            print(f"Discovery import error: {exc}")
            return 2
        print(f"Imported {len(hosts)} host(s) into workspace {workspace.name}.")
        return 0
    if args.discover:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        return run_discovery(store, workspace)
    if args.show_plan:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        display_plan(store, workspace)
        return 0
    if args.metasploit and not args.run_safe_checks:
        print("--metasploit requires --run-safe-checks.")
        return 2
    if args.run_safe_checks:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        if args.max_checks < 1:
            print("--max-checks must be at least 1.")
            return 2
        if args.check_workers < 1:
            print("--check-workers must be at least 1.")
            return 2
        return run_safe_checks(
            store, workspace, args.max_checks, args.check_workers, args.metasploit
        )
    try:
        return interactive(store, args.workspace, args.profile)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
