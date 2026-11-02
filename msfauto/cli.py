from __future__ import annotations

import argparse
import os
from pathlib import Path

from .discovery import DiscoveryError, parse_nmap_xml
from .models import ScopePolicy, Workspace
from .planner import build_plan
from .scope import ScopeError, build_policy
from .storage import WorkspaceStore


def default_store() -> WorkspaceStore:
    root = Path(os.environ.get("MSFAUTO_HOME", Path.home() / ".msfauto"))
    return WorkspaceStore(root / "workspaces.sqlite3")


def display_policy(policy: ScopePolicy) -> None:
    targets = [str(item) for item in (*policy.networks, *policy.addresses)]
    print(f"Profile: {policy.profile}")
    print(f"Targets: {', '.join(targets) or 'not configured'}")
    print(f"Ports: {', '.join(map(str, policy.allowed_ports)) or 'all discovered ports'}")


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


def configure_workspace(store: WorkspaceStore, name: str) -> Workspace:
    raw_targets = input("Authorized IP addresses or CIDRs (comma-separated): ")
    raw_ports = input("Optional ports (comma-separated, blank for all): ")
    policy = build_policy(raw_targets.split(","), raw_ports)
    workspace = Workspace(name=name, policy=policy)
    store.save(workspace)
    print("\nWorkspace saved.")
    display_policy(policy)
    return workspace


def interactive(store: WorkspaceStore, workspace_name: str) -> int:
    workspace = store.get(workspace_name)
    if workspace is None:
        print(f"Creating workspace: {workspace_name}")
        try:
            workspace = configure_workspace(store, workspace_name)
        except ScopeError as exc:
            print(f"Scope error: {exc}")
            return 2

    while True:
        print(
            "\nMSFAuto | "
            f"workspace={workspace.name} | profile={workspace.policy.profile}\n"
            "1. Show scope\n"
            "2. Configure scope\n"
            "3. Discovery (planned)\n"
            "4. Assessment checks (planned)\n"
            "5. Reports (planned)\n"
            "0. Exit"
        )
        choice = input("Select an option: ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            display_policy(workspace.policy)
        elif choice == "2":
            try:
                workspace = configure_workspace(store, workspace.name)
            except ScopeError as exc:
                print(f"Scope error: {exc}")
        elif choice in {"3", "4", "5"}:
            print("This safe MVP does not execute assessment actions yet.")
            print("The policy and execution layers must be completed first.")
        else:
            print("Choose one of the displayed options.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local terminal-first assessment orchestrator.")
    parser.add_argument("--workspace", default="default", help="Workspace name to open.")
    parser.add_argument("--show-scope", action="store_true", help="Print the saved scope and exit.")
    parser.add_argument("--tui", action="store_true", help="Open the Textual dashboard.")
    parser.add_argument("--import-nmap", type=Path, help="Import an Nmap XML result into the workspace.")
    parser.add_argument("--show-plan", action="store_true", help="Build and print a read-only assessment plan.")
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
    if args.show_plan:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        display_plan(store, workspace)
        return 0
    if args.tui:
        workspace = store.get(args.workspace)
        if workspace is None:
            print(f"Workspace not found: {args.workspace}")
            return 1
        from .tui import Dashboard

        Dashboard(workspace).run()
        return 0
    try:
        return interactive(store, args.workspace)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
