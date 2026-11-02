# Development Migration Plan

## Baseline audit

The existing application has working foundations for workspace onboarding, SQLite persistence, explicit scope, Nmap discovery and XML import, read-only Metasploit metadata, deterministic recommendations, bounded jobs, and a basic Textual screen.

The first interface migration now provides a guided screen for discovery, target browsing, target details, scope review, and read-only plan display. Discovery and planning are called through an application-service boundary rather than being implemented in widget event handlers.

The durable discovery-and-planning lifecycle and structured workflow events are now persisted. Explicit per-action approvals, evidence management, and reporting remain future work.

## Package migration status

The first migration slice is implemented: discovery, scope, assessment planning, storage, core orchestration, interface, execution, and Metasploit integration now have responsibility-based packages. Domain records are split into focused modules under `msfauto/storage/models/`. Tests are grouped into unit, integration, workflow, and interface suites. The CLI, interface, tests, and internal services use canonical package imports. Transitional flat-module shims have been removed.

The existing SQLite schema and table names are intentionally unchanged. This migration does not require deleting or recreating a user's database.

## Existing-code disposition

| Existing module | Decision | Migration target |
|---|---|---|
| `cli.py` | Refactor, retain compatibility | CLI bootstrap and interactive application entry |
| `tui.py` | Migrated | `interface/app.py` |
| `application.py` | Migrated | `core/orchestrator.py` |
| `discovery.py` | Migrated | `discovery/pipeline.py` |
| `scope.py` | Migrated | `scope/manager.py` |
| `models.py` | Split by responsibility | `storage/models/` |
| `storage.py` | Migrated; repository decomposition remains | `storage/database.py` and future repositories |
| `planner.py` | Migrated | `assessment/planner.py` |
| `jobs.py` | Migrated | `execution/manager.py` |
| `metasploit.py` | Migrated | `integrations/metasploit/client.py` |
| Existing tests | Preserve and expand | Unit, integration, workflow, interface, security |

The user-supplied package tree is the required architecture. Implement each package when it has real responsibilities and behavior; do not create empty placeholder files merely to make the tree look complete.

## Phase 0 — Architecture and documentation — complete

- [x] Inspect current package, tests, dependencies, and repository layout.
- [x] Map current modules to target responsibilities.
- [x] Define the operator workflow.
- [x] Define the safety and authorization model.
- [x] Correct README statements that contradict implemented functionality.
- [x] Add repository hygiene rules and remove tracked interpreter caches.
- [x] Add the `python -m msfauto` entry point.

## Phase 1 — Interaction redesign — initial implementation

- [x] Make the guided Textual interface the default interactive entry point.
- [x] Display workspace, profile, authorized scope, and allowed ports.
- [x] Add Start assessment and run discovery away from the UI event loop.
- [x] Add a target table with host state, hostname, and open-service summary.
- [x] Add target detail selection.
- [x] Add scope review and read-only assessment plan display.
- [ ] Add structured progress events and cooperative cancellation.
- [ ] Add job/history/report screens.
- [ ] Add automated Textual pilot tests.

Acceptance criteria still to complete:
- Discovery progress is streamed as meaningful stages and can be cancelled safely.
- The interface exposes recoverable assessment history and job details.
- Interface behavior is tested across supported terminal sizes.

## Phase 2 — Workflow orchestration

- Introduce a durable workflow state model.
- Coordinate scope validation, discovery, analysis, planning, approval, execution, and persistence.
- Publish structured progress events for the interface.
- Persist assessment lifecycle and recoverable failures.
- Ensure CLI and TUI use the same application services.

## Phase 3 — Discovery pipeline

- Separate scanner integration from discovery workflow coordination.
- Improve progress reporting and partial-result handling.
- Normalize observations and preserve source provenance.
- Enforce scope and port policy for each discovery operation.

## Phase 4 — Intelligence and assessment planning

- Improve service fingerprinting and evidence correlation.
- Add confidence and finding-status semantics.
- Generate recommendations automatically after analysis.
- Explain prerequisites, rationale, risk, and expected outcomes.
- Avoid treating version matches as confirmed vulnerabilities.

## Phase 5 — Approval and controlled execution

- Introduce explicit approval records and policy evaluation.
- Revalidate scope immediately before dispatch.
- Harden timeouts, concurrency, cancellation, output capture, and error classification.
- Keep high-impact actions disabled by default.

## Phase 6 — Sessions, evidence, and findings

- Track supported session metadata and lifecycle.
- Store evidence with provenance and integrity metadata.
- Separate evidence artifacts from interpreted findings.
- Redact secrets from ordinary logs and reports.

## Phase 7 — Reporting and stabilization

- Generate JSON and Markdown reports, then HTML.
- Add end-to-end workflow tests.
- Document installation, configuration, integrations, and troubleshooting.
- Add CI checks for tests, linting, and static analysis.

## Repository rules

- Work directly on `main`; do not create feature branches for this migration.
- Do not introduce a large directory tree of empty modules.
- Avoid new dependencies unless they solve a demonstrated requirement.
- Preserve user data and existing SQLite compatibility.
- Update tests and `CHANGELOG.md` with each meaningful change.
- Do not claim tests passed unless they were actually run.
