# MSFAuto

MSFAuto is a local, terminal-first orchestrator for authorized security assessment workflows. Its interaction model is inspired by Wifite: start the application, define an authorized scope, discover targets, inspect results, review an assessment plan, approve actions, and collect evidence.

The goal is to make complex security tooling approachable without hiding scope, policy, or the operations being requested.

## Current implementation

The current MVP provides foundations for:

- Interactive workspace creation and startup.
- SQLite-backed workspaces, discovery observations, assessment plans, workflow runs, and events.
- Explicit IP/CIDR scope and optional port allowlists.
- Nmap discovery with bounded execution and XML output.
- Scope-enforced Nmap XML import and normalized host/service storage.
- Read-only Metasploit RPC module metadata, search, and option inspection.
- Workspace-persisted module metadata and options.
- Explainable dry-run plans with deterministic service matching.
- A bounded job manager with scope checks, cancellation, concurrency limits, and structured events.
- Bounded safe-check adapter execution and persisted results.
- A guided Textual interface with discovery, target browsing, target details, scope review, and read-only plan display.
- A persisted discovery-to-planning workflow with progress events and recorded failure states.

The interface is an initial workflow-oriented release. It does not yet provide per-action approval records, workflow resumption, evidence management, or report generation. The job/check layer is a controlled foundation; it does not imply that arbitrary Metasploit modules are executable through MSFAuto.

## Planned experience

The intended full workflow is:

1. Select or configure a workspace and authorized scope.
2. Discover hosts, ports, and services.
3. Select a discovered target.
4. Analyze observations and generate recommendations.
5. Review an explainable assessment plan.
6. Approve operations according to policy.
7. Execute supported checks with bounded resources.
8. Collect evidence, review findings, and generate reports.

See [the architecture](docs/architecture/overview.md), [assessment workflow](docs/assessment-workflow.md), [safety model](docs/security/safety-model.md), and [roadmap](ROADMAP.md).

## Run from source

Install the project and its dependencies in a virtual environment, then run:

```bash
python -m msfauto
```

This opens the guided terminal interface. The equivalent module entry point is:

```bash
python -m msfauto.cli
```

On first launch, enter authorized IP/CIDR targets and optional ports. The main interface provides Start assessment, Browse targets, Assessment plan, and Scope. Keyboard shortcuts are shown in the footer; D, T, P, S, and Q are also available.

Existing command-line operations remain available:

```bash
python -m msfauto.cli --workspace lab --discover
python -m msfauto.cli --workspace lab --import-nmap scan.xml
python -m msfauto.cli --workspace lab --show-plan
python -m msfauto.cli --workspace lab --run-safe-checks --max-checks 10 --check-workers 2
python -m msfauto.cli --workspace lab --show-scope
```

The default workspace database is stored at `~/.msfauto/workspaces.sqlite3`. Set `MSFAUTO_HOME` to use another local directory.

The MVP accepts IP addresses and CIDR networks. It does not resolve or scan arbitrary hostnames.

## Safety

MSFAuto is intended for owned systems, isolated labs, and explicitly authorized assessments. Discovery does not grant permission to perform intrusive operations. Scope is enforced independently of the interface, and active operations require policy checks and appropriate approval.

Exploit execution, credential attacks, persistence, pivoting, and destructive actions are not part of the normal automated workflow.

## Code layout

The active code is organized by responsibility: `core/` owns orchestration, `interface/` owns the Textual UI, `discovery/` owns Nmap discovery and parsing, `scope/` owns authorization boundaries, `assessment/` owns read-only planning, `execution/` owns bounded checks, `integrations/` owns external tool clients, and `storage/` owns SQLite persistence and domain models. Tests are grouped under `unit/`, `integration/`, `workflow/`, and `interface/`.

The remaining target areas—configuration, workspace lifecycle, intelligence, approvals, sessions, evidence, findings, and reporting—will be added as real capabilities are implemented, not as empty placeholder modules.

## Development

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

See [the migration plan](docs/development/migration-plan.md) for the development sequence and repository rules. Update `CHANGELOG.md` for meaningful changes.
