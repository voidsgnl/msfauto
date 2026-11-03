# MSFAuto Roadmap

MSFAuto is evolving toward a terminal-native, keyboard-driven assessment console. The operator should be able to start one workflow, follow discovery results, select targets, review recommendations, approve permitted actions, and inspect evidence without manually coordinating every underlying tool.

The roadmap preserves working foundations and prioritizes a dependable, explainable workflow over feature accumulation.

## Current baseline

- [x] Interactive terminal startup and workspace onboarding
- [x] `python -m msfauto` application entry point
- [x] SQLite workspace persistence
- [x] Explicit IP/CIDR scope and optional port allowlists
- [x] Scope-enforced Nmap XML import and normalized service storage
- [x] Bounded Nmap execution adapter
- [x] Read-only Metasploit RPC module metadata integration
- [x] Explicit RPC execution for allowlisted passive service-version checks, with stance validation, bounded polling, and timeout cancellation
- [x] Module metadata and options persistence
- [x] Explainable dry-run recommendations
- [x] Bounded job manager with scope checks, cancellation, and concurrency limits
- [x] Structured job events and persisted results
- [x] Per-action approval records and execution-layer approval enforcement
- [x] Bounded evidence artifact collection with integrity verification
- [x] Automatically persist safe-check outcomes and structured job events as evidence
- [x] Persisted evidence-linked findings
- [x] Initial tests for CLI, discovery, planning, scope, jobs, approvals, evidence, findings, Metasploit metadata, and storage

## Current handoff — 2026-11-03

- Authoritative source: GitHub `main`; the local repository was replaced with a clean clone after local Git object corruption.
- Recovery verification: the user confirmed the working tree is clean and reported **66 tests passing** with the reused `.venv`.
- Latest known CI-verified commit: `76b025cf3237de37d896df759f981fb29b6428dd` (Python 3.10, 3.12, and 3.14 test/lint jobs passed).
- Work directly on `main`; do not create feature branches unless explicitly requested.
- For every meaningful implementation change, update this roadmap and `CHANGELOG.md`, run the relevant tests and Ruff, and record the resulting commit and verification status here.

## Verified workflow audit — 2026-11-03

The current implementation has reusable capabilities, but the complete assessment lifecycle is not yet orchestrated as one run.

### Confirmed integration boundaries

- `AssessmentApplication.run_assessment()` persists a run and stage events, validates that scope exists, runs Nmap discovery, stores discovered hosts, builds a read-only plan, and marks the run completed or failed.
- The orchestrator does not currently approve or execute recommendations. This separation is intentional and must remain explicit.
- Per-action approvals and safe-check execution are initiated separately through the CLI's `--run-safe-checks` path.
- Evidence is captured for safe-check outcomes, but evidence records are associated with a workspace and target rather than an assessment run.
- Findings are workspace-scoped and evidence-linked, but are not associated with an assessment run.
- Assessment plans are stored as the latest plan per workspace, not as immutable run-specific plan snapshots.
- Reports aggregate workspace data; they do not yet identify one assessment run and its complete provenance.
- The TUI currently exposes discovery, target browsing, plan display, and scope review; approval, execution, evidence/finding review, and report views are not connected to it.
- Assessment runs and events are persisted, but there is no resume/recovery operation. A process interruption can leave a run in `running`; retry safety and duplicate-dispatch prevention are not implemented.

### Verification

- GitHub Actions run [#180](https://github.com/voidsgnl/msfauto/actions/runs/41651901132) completed successfully on commit `54ec73b48653d81957c79ea068fe7be315e9df50`.
- Python 3.10, 3.12, and 3.14 jobs all passed, including the test suite and Ruff.
- The user should pull the latest `main` and run the local test suite to verify the updated checkout and SQLite migration in their environment.

### Completed slice: run-specific plan snapshots

- [x] Added a dedicated SQLite table for assessment-run plan snapshots; existing workspace-level latest-plan behavior remains intact for compatibility.
- [x] Persisted the generated read-only plan against its originating run.
- [x] Reject snapshots for unknown runs and workspace mismatches.
- [x] Added workflow tests for snapshot retrieval and ownership validation.
- [x] Verify the implementation in GitHub Actions across Python 3.10, 3.12, and 3.14; local checkout verification is pending.

### Implementation implications

- [x] Audit the application-service and orchestrator boundaries.
- [x] Make plans immutable and addressable by assessment run.
- [ ] Add explicit interruption/recovery semantics before supporting resume.
- [ ] Associate downstream approvals, jobs, evidence, and reports with the originating run without weakening workspace isolation.
- [ ] Add idempotency/dispatch tracking so a resumed workflow cannot repeat an operation whose dispatch outcome is uncertain.
- [ ] Only then integrate approval-gated execution into the guided workflow and expose the lifecycle in the TUI.

**Safety constraint:** never automatically resume or retry an operation whose dispatch state is unknown. Mark it for operator reconciliation instead. Existing scope checks, persisted action-specific approvals, adapter allowlists, timeouts, and output sanitization remain mandatory.

## Immediate next milestone: end-to-end assessment workflow

**Goal:** connect the existing discovery, planning, approval, execution, evidence, findings, and reporting capabilities into one traceable operator workflow. Prioritize workflow correctness and recoverability over adding more scanners or check modules.

- [ ] Map the current application-service and orchestrator boundaries; identify which stages are already connected and which are CLI-only or standalone.
- [ ] Define explicit persisted stage transitions and terminal states for success, failure, cancellation, and interruption.
- [ ] Connect scope preflight, discovery, analysis, and plan generation without bypassing existing authorization boundaries.
- [ ] Connect operator review and per-action approval to the persisted plan; never infer approval from workflow progression.
- [ ] Execute only supported checks whose persisted approval and scope are revalidated by the execution layer.
- [ ] Associate execution results and evidence with the originating assessment run.
- [ ] Present candidate findings for analyst review; never infer vulnerabilities from service banners, missing responses, or tool errors alone.
- [ ] Generate a report from the completed assessment run, preserving workspace isolation and evidence-integrity checks.
- [ ] Add deterministic end-to-end tests covering the successful path, rejected approval, scope mismatch, adapter failure, cancellation, and interrupted/resumed workflow behavior.
- [ ] Verify that resuming a workflow cannot silently repeat an already-dispatched operation.

**Acceptance criteria:** a deterministic, testable assessment can be followed from scope validation to report generation; every stage and decision is persisted; failures remain inspectable; approvals remain action-specific; and no execution path bypasses the existing scope, approval, timeout, or output-sanitization controls.

## Phase 0: Architecture and audit — complete

- [x] Begin migration from flat modules into the supplied package architecture.
- [x] Establish core, interface, discovery, scope, assessment, execution, integrations, and storage packages.
- [x] Organize tests by unit, integration, workflow, and interface responsibility.
- [x] Split domain records into focused storage model modules and remove transitional flat-module shims.
- [ ] Implement remaining configuration, workspace, intelligence, approval history, and sessions packages.

- [x] Audit current repository structure and tests
- [x] Map current modules to target responsibilities
- [x] Define the guided assessment workflow
- [x] Document architecture and component boundaries
- [x] Document authorization and safety model
- [x] Correct README statements about implemented and planned functionality
- [x] Add repository hygiene rules and remove tracked Python bytecode caches

## Phase 1: Terminal-native interface

- [x] Establish `python -m msfauto` as the primary interactive entry point
- [x] Replace the informational dashboard with a workflow-oriented screen
- [x] Establish a terminal-native visual identity, compact action bar, activity feedback, target table, and detail panel
- [x] Keep workspace and authorized scope visible
- [x] Add target list and target detail display
- [x] Connect discovery and plan display through application services
- [x] Keep discovery work off the Textual event loop
- [ ] Add explicit progress events and cancellation for long-running discovery
- [ ] Add assessment history, jobs, findings, and report views
- [ ] Add broader Textual interaction tests and accessibility/terminal-size checks

## Phase 2: Workflow orchestrator

- [x] Introduce an initial application-service boundary for discovery, targets, and planning
- [x] Introduce a durable workflow state model
- [ ] Coordinate scope validation, discovery, analysis, planning, approval, execution, and persistence
- [x] Persist structured workflow events and expose a progress callback
- [x] Persist assessment lifecycle and failure state
- [x] Expose the workflow through shared application services

## Phase 3: Discovery pipeline

- [x] Nmap XML import with scope enforcement
- [x] Bounded Nmap execution adapter
- [ ] Separate scanner integration from discovery coordination
- [ ] Improve live progress and partial-result handling
- [ ] Preserve observation timestamps and source provenance
- [ ] Enforce target and port policy for every discovery operation

## Phase 4: Intelligence and assessment planning

- [x] Correlate discovered services with relevant module metadata
- [x] Deterministic recommendations with confidence and rationale
- [x] Read-only plan generation
- [ ] Improve service fingerprinting and evidence correlation
- [ ] Distinguish confirmed observations, potential weaknesses, and hypotheses
- [ ] Add explicit prerequisites, operation classes, and risk explanations
- [ ] Generate plans automatically after analysis

## Phase 5: Approval and controlled execution

- [x] Bounded job manager foundation
- [x] Scope-checked job submission
- [x] Cancellation and concurrency limits
- [x] Add explicit per-action approval records
- [x] Revalidate persisted approval and scope immediately before adapter dispatch
- [x] Add bounded execution timeouts, sanitized output capture, and structured RPC failure states for the allowlisted Metasploit adapter
- [ ] Add recoverable job resumption and broader adapter error recovery
- [ ] Keep high-impact actions disabled by default

## Phase 6: Sessions, evidence, and findings

- [ ] Track supported session metadata and lifecycle
- [x] Collect bounded evidence artifacts with source, target, timestamp, metadata, and SHA-256 integrity verification
- [x] Capture safe-check execution outcomes and job events as evidence artifacts
- [x] Verify evidence integrity and workspace ownership before linking it to a finding
- [x] Separate evidence artifacts from interpreted findings
- [x] Persist findings with severity, confidence, evidence references, and potential/confirmed/unverified/false-positive review states
- [x] Capture bounded, sanitized textual adapter output as execution evidence
- [ ] Automatically correlate validated observations with findings
- [ ] Generate candidate findings from validated evidence with analyst review; never infer vulnerabilities from banners or tool errors alone
- [x] Redact common secret fields from report exports
- [ ] Expand secret redaction for ordinary logs and arbitrary adapter output

## Phase 7: Reporting and stabilization

- [x] Generate workspace-scoped JSON reports
- [x] Generate workspace-scoped Markdown reports
- [x] Include scope, assets, jobs, findings, and evidence integrity in report exports
- [x] Redact common secret fields in report data
- [ ] Add HTML reports and report views in the TUI
- [ ] Add end-to-end workflow tests
- [ ] Document installation, configuration, integrations, and troubleshooting
- [x] Add CI for tests and linting
- [ ] Add static analysis to CI

## Phase 8: Expert features and extensibility

- [ ] Add searchable advanced module metadata controls
- [ ] Support custom profiles and policy files
- [ ] Add documented integration boundaries
- [ ] Add plan import/export
- [ ] Consider third-party extensions only when a concrete use case exists

## Non-goals

MSFAuto will not silently attack arbitrary targets, bypass scope controls, or hide operations from the operator. Discovery does not imply authorization. Exploitation, credential attacks, persistence, pivoting, and destructive actions remain disabled by default and outside the normal automated workflow.
