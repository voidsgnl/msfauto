# MSFAuto

MSFAuto is a local, terminal-first orchestrator for authorized security assessment workflows. Its interaction model is inspired by Wifite: start the application, define an authorized scope, discover targets, inspect results, review an assessment plan, approve actions, and collect evidence.

The goal is to make complex security tooling approachable without hiding scope, policy, or the operations being requested.

## Current implementation

The current MVP provides foundations for:

- Interactive workspace creation and startup.
- SQLite-backed workspaces and assessment data.
- Explicit IP/CIDR scope and optional port allowlists.
- Nmap discovery with bounded execution and XML output.
- Scope-enforced Nmap XML import and normalized host/service storage.
- Read-only Metasploit RPC module metadata, search, and option inspection.
- Workspace-persisted module metadata and options.
- Explainable dry-run plans with deterministic service matching.
- A bounded job manager with scope checks, cancellation, concurrency limits, and structured events.
- Bounded safe-check adapter execution and persisted results.
- A basic Textual status dashboard.

The current interface and workflow are still early-stage. In particular, the Textual screen is informational rather than a complete navigable operator experience. The job/check layer is a controlled foundation; it does not imply that arbitrary Metasploit modules are executable through MSFAuto.

## Planned experience

The intended primary workflow is:

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

The current supported module entry point is also:

```bash
python -m msfauto.cli
```

On first launch, enter authorized IP/CIDR targets and optional ports. Existing command-line options remain available during the migration:

```bash
python -m msfauto.cli --workspace lab --discover
python -m msfauto.cli --workspace lab --import-nmap scan.xml
python -m msfauto.cli --workspace lab --show-plan
python -m msfauto.cli --workspace lab --run-safe-checks --max-checks 10 --check-workers 2
python -m msfauto.cli --workspace lab --tui
```

The default workspace database is stored at `~/.msfauto/workspaces.sqlite3`. Set `MSFAUTO_HOME` to use another local directory.

The MVP accepts IP addresses and CIDR networks. It does not resolve or scan arbitrary hostnames.

## Safety

MSFAuto is intended for owned systems, isolated labs, and explicitly authorized assessments. Discovery does not grant permission to perform intrusive operations. Scope is enforced independently of the interface, and active operations require policy checks and appropriate approval.

Exploit execution, credential attacks, persistence, pivoting, and destructive actions are not part of the normal automated workflow.

## Development

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

See [development setup](docs/development/migration-plan.md) for the migration plan and repository rules. Update `CHANGELOG.md` for meaningful changes.
