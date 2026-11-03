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
- An explicit Metasploit RPC execution path for a fixed allowlist of passive service-version checks; all other modules remain unsupported by this adapter.
- A terminal-native Textual assessment console with compact workspace context, keyboard-first navigation, target tables, status feedback, selected-target details, and read-only plan display.
- A persisted discovery-to-planning workflow with progress events and recorded failure states.
- Per-recommendation approval decisions persisted in SQLite; safe checks require an exact `APPROVE` confirmation and approver identifier.
- Execution-layer authorization gate that independently verifies the persisted approval, exact workspace/target/port/protocol/module/risk context, and scope both at submission and immediately before adapter dispatch.
- Bounded local evidence artifact collection with SHA-256 integrity verification and SQLite metadata; safe-check outcomes and structured job events are captured automatically.
- Persisted findings with severity, confidence, review status, and evidence references; evidence links are restricted to the same workspace.
- Workspace-scoped JSON and Markdown reports covering scope, discovered assets, execution jobs, findings, and evidence integrity; common secret fields are redacted.

The interface is an initial terminal-native console release. It does not yet provide approval history beyond the latest decision per action, workflow resumption, evidence/finding views, automated evidence-to-finding correlation, HTML reports, and report views in the TUI. The execution layer now accepts bounded textual adapter output, applies best-effort secret redaction, and includes sanitized output in execution evidence. The job/check layer remains a controlled foundation; it does not imply that arbitrary Metasploit modules are executable through MSFAuto.

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

See [the architecture](docs/architecture/overview.md), [assessment workflow](docs/assessment-workflow.md), [evidence and findings guide](docs/evidence-and-findings.md), [safety model](docs/security/safety-model.md), and [roadmap](ROADMAP.md).

## Run from source

Install the project and its dependencies in a virtual environment, then run:

```bash
python -m msfauto
```

This opens the terminal-native assessment console. It keeps the authorized workspace context visible, presents discovery results in a compact table, and provides keyboard shortcuts for the main workflow. The equivalent module entry point is:

```bash
python -m msfauto.cli
```

On first launch, enter authorized IP/CIDR targets and optional ports. The console provides Discover, Targets, Plan, and Scope actions. Keyboard shortcuts are shown in the footer: D, T, P, S, and Q.

Existing command-line operations remain available:

```bash
python -m msfauto.cli --workspace lab --discover
python -m msfauto.cli --workspace lab --import-nmap scan.xml
python -m msfauto.cli --workspace lab --show-plan
python -m msfauto.cli --workspace lab --run-safe-checks --max-checks 10 --check-workers 2
python -m msfauto.cli --workspace lab --run-safe-checks --metasploit --max-checks 10 --check-workers 2
python -m msfauto.cli --workspace lab --show-scope
python -m msfauto.cli --workspace lab --report json
python -m msfauto.cli --workspace lab --report markdown --report-output ./assessment-report.md
```

The default workspace database is stored at `~/.msfauto/workspaces.sqlite3`. Set `MSFAUTO_HOME` to use another local directory.

### Metasploit RPC checks

The `--metasploit` flag opts into real Metasploit RPC execution. Configure the connection before running it:

```bash
export MSFAUTO_METASPLOIT_URL="http://127.0.0.1:55553/api/1.0"
export MSFAUTO_METASPLOIT_USERNAME="your-rpc-user"
export MSFAUTO_METASPLOIT_PASSWORD="your-rpc-password"
python -m msfauto.cli --workspace lab --run-safe-checks --metasploit
```

The URL defaults to the local `msfrpcd` endpoint shown above. MSFAuto currently permits only a fixed set of passive FTP, HTTP, MySQL, PostgreSQL, SMB, SSH, SSL, and Telnet version-identification modules. It checks the live Metasploit module stance before dispatch, passes only the approved target and port, polls the returned run UUID, and stops jobs that exceed the 60-second execution limit. The existing persisted approval and scope checks still run before dispatch. Other modules—including modules merely named `scanner/*`—are reported as unsupported and are not executed. The default `--run-safe-checks` path remains deterministic unless `--metasploit` is explicitly supplied.

The MVP accepts IP addresses and CIDR networks. It does not resolve or scan arbitrary hostnames.

## Safety

MSFAuto is intended for owned systems, isolated labs, and explicitly authorized assessments. Discovery does not grant permission to perform intrusive operations. Scope is enforced independently of the interface, and active operations require policy checks and appropriate approval.

Exploit execution, credential attacks, persistence, pivoting, and destructive actions are not part of the normal automated workflow.

## Code layout

The active code is organized by responsibility: `core/` owns orchestration, `interface/` owns the Textual UI, `discovery/` owns Nmap discovery and parsing, `scope/` owns authorization boundaries, `assessment/` owns read-only planning and approval decisions, `execution/` owns approval-gated bounded checks, `evidence/` owns artifact collection and integrity verification, `findings/` owns evidence-linked assessment conclusions, `reporting/` exports workspace reports, `integrations/` owns external tool clients, and `storage/` owns SQLite persistence and domain models. Tests are grouped under `unit/`, `integration/`, `workflow/`, and `interface/`.

The remaining target areas—configuration, workspace lifecycle, intelligence, approval history, sessions, automatic adapter-to-evidence correlation, HTML reporting, and richer evidence/finding views—will be added as real capabilities are implemented, not as empty placeholder modules.

## Development

Use the project setup script to create an isolated virtual environment and install the project with its development dependencies:

```bash
./scripts/setup_dev.sh
source .venv/bin/activate
```

Do not install project dependencies into Ubuntu's externally managed system Python. The setup script installs into `.venv/` and avoids PEP 668 conflicts.

Run the application and checks from the activated environment:

```bash
python -m msfauto
python -m pytest
python -m ruff check .
```

GitHub Actions runs the test suite and Ruff on pushes to `main`, pull requests, and manual workflow dispatches, using Python 3.10, 3.12, and 3.14.

See [the migration plan](docs/development/migration-plan.md) for the development sequence and repository rules. Update `CHANGELOG.md` for meaningful changes.
