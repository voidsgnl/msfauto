from __future__ import annotations

import argparse
import os
from collections import Counter
from pathlib import Path

from .discovery import DiscoveryError, parse_nmap_xml, run_nmap
from .jobs import CheckRequest, JobError, JobManager
from .models import ScopePolicy, Workspace
from .planner import build_plan
from .scope import PROFILES, ScopeError, build_policy
from .storage import WorkspaceStore


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
    print("\nThe menu below lets you perform these steps without memorizing commands.")


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
    output_path = store.path.parent / "discovery" / f"{workspace.name}.xml"
    print(f"Running Nmap against the saved scope; XML will be stored at {output_path}.")
    try:
        run, hosts = run_nmap(workspace.name, workspace.policy, output_path)
    except DiscoveryError as exc:
        print(f"Discovery error: {exc}")
        return 2
    store.save_discovery_run(run)
    if run.status != "completed":
        print(f"Nmap discovery {run.status}: {run.error or 'no additional details'}")
        return 2
    store.save_hosts(workspace.name, hosts)
    print(f"Discovery complete: imported {len(hosts)} host(s).")
    print("Next step: choose 'Build and show assessment plan' from the menu.")
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
    manager = JobManager(workspace.policy, max_workers=workers)
    job_ids: list[str] = []
    try:
        for recommendation in selected:
            try:
                job_ids.append(
                    manager.submit(
                        CheckRequest(
                            workspace=workspace.name,
                            target=recommendation.target,
                            port=recommendation.port,
                            protocol=recommendation.protocol,
                            module_name=f"{recommendation.module_type}/{recommendation.module_name}",
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
            for event in manager.events(job_id):
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

    while True:
        print(
            "\nMSFAuto | "
            f"workspace={workspace.name} | profile={workspace.policy.profile}\n"
            "1. Review current scope\n"
            "2. Run Nmap and import results automatically\n"
            "3. Import an existing discovery XML\n"
            "4. Build and show assessment plan\n"
            "5. Run safe checks\n"
            "6. Open dashboard\n"
            "7. Reconfigure scope\n"
            "0. Exit"
        )
        choice = input("Select an option: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            display_policy(workspace.policy)
        elif choice == "2":
            run_discovery(store, workspace)
        elif choice == "3":
            try:
                path = Path(input("Path to authorized Nmap XML file: ").strip()).expanduser()
                hosts = parse_nmap_xml(path, workspace.policy)
                store.save_hosts(workspace.name, hosts)
                print(f"Imported {len(hosts)} host(s). Choose option 4 to build a plan.")
            except DiscoveryError as exc:
                print(f"Discovery import error: {exc}")
        elif choice == "4":
            display_plan(store, workspace)
        elif choice == "5":
            try:
                run_safe_checks(store, workspace, max_checks=10, workers=2)
            except (JobError, TimeoutError) as exc:
                print(f"Safe-check error: {exc}")
        elif choice == "6":
            from .tui import Dashboard

            Dashboard(workspace, store).run()
        elif choice == "7":
            try:
                workspace = configure_workspace(store, workspace.name, workspace.policy.profile)
            except ScopeError as exc:
                print(f"Scope error: {exc}")
        else:
            print("Choose one of the displayed options.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local terminal-first assessment orchestrator.")
    parser.add_argument("--workspace", default="default", help="Workspace name to open.")
    parser.add_argument("--show-scope", action="store_true", help="Print the saved scope and exit.")
    parser.add_argument("--tui", action="store_true", help="Open the Textual dashboard.")
    parser.add_argument("--import-nmap", type=Path, help="Import an Nmap XML result into the workspace.")
    parser.add_argument("--discover", action="store_true", help="Run Nmap using the saved scope and import results.")
    parser.add_argument("--show-plan", action="store_true", help="Build and print a read-only assessment plan.")
    parser.add_argument("--run-safe-checks", action="store_true", help="Run bounded non-invasive checks from the plan.")
    parser.add_argument("--max-checks", type=int, default=10, help="Maximum recommendations to run with --run-safe-checks.")
    parser.add_argument("--check-workers", type=int, default=2, help="Concurrent workers for --run-safe-checks.")
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
        from .tui import Dashboard

        Dashboard(workspace, store).run()
        return 0
    try:
        return interactive(store, args.workspace, args.profile)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
