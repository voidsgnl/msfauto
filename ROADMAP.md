# MSFAuto Roadmap

MSFAuto is evolving toward a Wifite-inspired, terminal-first guided assessment experience. The operator should be able to start one workflow, follow discovery results, select targets, review recommendations, approve permitted actions, and inspect evidence without manually coordinating every underlying tool.

The roadmap preserves working foundations and prioritizes a dependable, explainable workflow over feature accumulation.

## Current baseline

- [x] Interactive terminal startup and workspace onboarding
- [x] `python -m msfauto` application entry point
- [x] SQLite workspace persistence
- [x] Explicit IP/CIDR scope and optional port allowlists
- [x] Scope-enforced Nmap XML import and normalized service storage
- [x] Bounded Nmap execution adapter
- [x] Read-only Metasploit RPC module metadata integration
- [x] Module metadata and options persistence
- [x] Explainable dry-run recommendations
- [x] Bounded job manager with scope checks, cancellation, and concurrency limits
- [x] Structured job events and persisted results
- [x] Initial tests for CLI, discovery, planning, scope, jobs, Metasploit metadata, and storage

## Phase 0: Architecture and audit — complete

- [x] Begin migration from flat modules into the supplied package architecture.
- [x] Establish core, interface, discovery, scope, assessment, execution, integrations, and storage packages.
- [x] Organize tests by unit, integration, workflow, and interface responsibility.
- [x] Split domain records into focused storage model modules and remove transitional flat-module shims.
- [ ] Implement remaining configuration, workspace, intelligence, approval history, sessions, evidence, findings, and reporting packages.

- [x] Audit current repository structure and tests
- [x] Map current modules to target responsibilities
- [x] Define the guided assessment workflow
- [x] Document architecture and component boundaries
- [x] Document authorization and safety model
- [x] Correct README statements about implemented and planned functionality
- [x] Add repository hygiene rules and remove tracked Python bytecode caches

## Phase 1: Wifite-inspired interface — initial implementation

- [x] Establish `python -m msfauto` as the primary interactive entry point
- [x] Replace the informational dashboard with a workflow-oriented screen
- [x] Keep workspace and authorized scope visible
- [x] Add target list and target detail display
- [x] Connect discovery and plan display through application services
- [x] Keep discovery work off the Textual event loop
- [ ] Add explicit progress events and cancellation for long-running discovery
- [ ] Add assessment history, jobs, findings, and report views
- [ ] Add Textual interaction tests and accessibility/terminal-size checks

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
- [ ] Add robust timeouts, output capture, and recoverable errors
- [ ] Keep high-impact actions disabled by default

## Phase 6: Sessions, evidence, and findings

- [ ] Track supported session metadata and lifecycle
- [ ] Collect evidence with provenance and integrity metadata
- [ ] Separate evidence artifacts from interpreted findings
- [ ] Distinguish confirmed, potential, unverified, failed, skipped, and unsupported outcomes
- [ ] Redact secrets from ordinary logs and reports

## Phase 7: Reporting and stabilization

- [ ] Generate JSON reports
- [ ] Generate Markdown reports
- [ ] Add HTML reports
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
