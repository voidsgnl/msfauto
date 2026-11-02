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
from .execution import CheckRequest, JobError, JobManager
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
    print("\nWhat to do next:")
    print("  1. Run Nmap automatically using this saved scope.")
    print("  2. Build a read-only assessment plan from discovered services.")
    print("  3. Run bounded non-invasive checks from that plan.")
    print("  4. Open the dashboard to review hosts, plans, and job results.")
    print("\nThe guided terminal interface opens next, so you can perform these steps without memorizing commands.")


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

def run_safe_checks(store: WorkspaceStore, workspace: Workspace, max_checks: int, workers: int) -> int:
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
    selected = plan.recommendations[:max_checks]
    print("Each recommendation requires a separate, recorded decision.")
    approver = input("Approver identifier: ").strip()
    if not approver:
        print("No approver identifier supplied; no checks were dispatched.")
        return 2

    approved = []
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

    if not approved:
        print("No recommendations were approved; no checks were dispatched.")
        return 0

    manager = JobManager(workspace.policy, max_workers=workers, approval_store=store)
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
            job = manager.wait(job_id, timeout=5)
            counts[job.status] += 1
            store.save_job(job)
            events = manager.events(job_id)
            result_payload = {
                "status": job.status,
                "error": job.error,
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

    from .interface import Dashboard

    Dashboard(workspace, store).run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local terminal-first assessment orchestrator.")
    parser.add_argument("--workspace", default="default", help="Workspace name to open.")
    parser.add_argument("--show-scope", action="store_true", help="Print the saved scope and exit.")
    parser.add_argument("--tui", action="store_true", help="Open the interactive terminal interface (now the default).")
    parser.add_argument("--import-nmap", type=Path, help="Import an Nmap XML result into the workspace.")
    parser.add_argument("--discover", action="store_true", help="Run the saved-scope discovery and read-only planning workflow.")
    parser.add_argument("--show-plan", action="store_true", help="Build and print a read-only assessment plan.")
    parser.add_argument("--run-safe-checks", action="store_true", help="Run bounded non-invasive checks from the plan.")
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
        return run_safe_checks(store, workspace, args.max_checks, args.check_workers)
    if args.tui:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        from .interface import Dashboard

        Dashboard(workspace, store).run()
        return 0
    try:
        return interactive(store, args.workspace, args.profile)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
