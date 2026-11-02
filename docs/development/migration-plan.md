# Development Migration Plan

## Baseline audit

The current application is a compact Python package with a useful set of working foundations:

- Interactive CLI and workspace onboarding.
- SQLite workspace, host, plan, job, event, and module-metadata persistence.
- Explicit IP/CIDR scope and optional port allowlists.
- Nmap execution and XML import with scope validation.
- Read-only Metasploit RPC metadata access.
- Deterministic service-to-module recommendations.
- A bounded job manager and a basic Textual dashboard.
- Unit tests covering the existing CLI, discovery, jobs, Metasploit metadata, planning, scope, and storage paths.

The repository does not yet have a workflow orchestrator, a live progress-oriented interface, explicit per-action approval queues, a durable assessment lifecycle, or the full evidence and reporting layers.

## Existing-code disposition

| Existing module | Decision | Migration target |
|---|---|---|
| `cli.py` | Refactor, retain compatibility | CLI bootstrap and interactive application entry |
| `tui.py` | Replace dashboard-only composition | Workflow-oriented Textual interface |
| `discovery.py` | Keep first, split when justified | Discovery service and Nmap integration |
| `scope.py` | Keep and strengthen | Scope and authorization |
| `models.py` | Keep initially, split by domain | Domain model packages |
| `storage.py` | Keep initially, introduce repository boundaries | Storage and repositories |
| `planner.py` | Keep and expand | Assessment planning and recommendation logic |
| `jobs.py` | Keep and harden | Execution manager |
| `metasploit.py` | Keep | Metasploit integration |
| Existing tests | Preserve and expand | Unit, integration, workflow, interface, security |

Do not move modules simply to make the filesystem match a target diagram. A move is justified when it improves ownership, testability, or dependency direction.

## Phase 0 — Architecture and documentation

- [x] Inspect current package, tests, dependencies, and repository layout.
- [x] Map current modules to target responsibilities.
- [x] Define the operator workflow.
- [x] Define the safety and authorization model.
- [ ] Correct README statements that contradict implemented functionality.
- [ ] Add repository hygiene rules and remove tracked interpreter caches.

## Phase 1 — Interaction redesign

- Establish one primary interactive entry point.
- Replace the informational dashboard with a navigable assessment workflow.
- Keep workspace and scope visible.
- Add target list and target detail views.
- Show discovery and execution progress, errors, and cancellation.
- Preserve existing CLI flags until equivalent behavior is covered by tests.
- Add Textual interaction tests.

Acceptance criteria:
- A new user can create/select a workspace and start discovery without memorizing flags.
- The interface presents discovered targets and allows target selection.
- The interface does not directly execute external tools.
- Existing supported CLI operations remain functional.

## Phase 2 — Workflow orchestration

- Introduce application services and a workflow state model.
- Coordinate scope validation, discovery, analysis, planning, approval, execution, and persistence.
- Persist assessment lifecycle and recoverable failures.
- Publish structured progress events for the interface.

Acceptance criteria:
- A complete discovery-to-plan workflow runs through one orchestrated path.
- Interrupted workflows have an explicit state and useful recovery behavior.
- Interface and CLI entry points use the same application services.

## Phase 3 — Discovery pipeline

- Separate scanner integration from discovery workflow coordination.
- Improve progress reporting and partial-result handling.
- Normalize observations and preserve source provenance.
- Enforce scope and port policy for each discovery operation.

Acceptance criteria:
- Discovery results are reproducible and traceable to their source.
- Timeouts and partial results do not corrupt existing workspace data.
- Out-of-scope results are rejected or quarantined with an explanation.

## Phase 4 — Intelligence and assessment planning

- Improve service fingerprinting and evidence correlation.
- Add confidence and finding-status semantics.
- Generate recommendations automatically after analysis.
- Explain prerequisites, rationale, risk, and expected outcomes.
- Avoid treating version matches as confirmed vulnerabilities.

Acceptance criteria:
- Each recommendation can be traced to supporting observations.
- Confirmed facts, potential weaknesses, and hypotheses are visibly distinct.
- Planning remains read-only.

## Phase 5 — Approval and controlled execution

- Introduce explicit approval records and policy evaluation.
- Revalidate scope immediately before dispatch.
- Harden timeouts, concurrency, cancellation, output capture, and error classification.
- Keep high-impact actions disabled by default.

Acceptance criteria:
- No operation requiring approval can run without a matching approval record.
- Changing target or material options invalidates the prior approval.
- Execution results and audit events are persisted.

## Phase 6 — Sessions, evidence, and findings

- Track supported session metadata and lifecycle.
- Store evidence with provenance and integrity metadata.
- Separate evidence artifacts from interpreted findings.
- Redact secrets from ordinary logs and reports.

Acceptance criteria:
- Every finding references supporting evidence or clearly explains its lack of evidence.
- Sensitive data is not emitted into ordinary logs by default.

## Phase 7 — Reporting and stabilization

- Generate JSON and Markdown reports, then HTML.
- Add end-to-end workflow tests.
- Document installation, configuration, integrations, and troubleshooting.
- Add CI checks for tests, linting, and static analysis.

Acceptance criteria:
- A completed assessment can be reopened and reported from persisted data.
- Reports distinguish confirmed, potential, unverified, failed, skipped, and unsupported outcomes.
- The documented installation and main workflow work from a clean environment.

## Repository rules

- Work directly on `main`; do not create feature branches for this migration.
- Do not introduce a large directory tree of empty modules.
- Avoid new dependencies unless they solve a demonstrated requirement.
- Preserve user data and existing SQLite compatibility.
- Update tests and `CHANGELOG.md` with each meaningful change.
- Do not claim tests passed unless they were actually run.
