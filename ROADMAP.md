# MSFAuto Roadmap

MSFAuto is evolving toward a Wifite-inspired, terminal-first guided assessment experience. The operator should be able to start one workflow, follow discovery results, select targets, review recommendations, approve permitted actions, and inspect evidence without manually coordinating every underlying tool.

The roadmap preserves working foundations and prioritizes a dependable, explainable workflow over feature accumulation.

## Current baseline

- [x] Interactive terminal startup and workspace onboarding
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

The current Textual screen is a basic informational dashboard. The current job adapter is a bounded foundation and does not make arbitrary Metasploit modules executable.

## Phase 0: Architecture and audit

- [x] Audit current repository structure and tests
- [x] Map current modules to target responsibilities
- [x] Define the guided assessment workflow
- [x] Document architecture and component boundaries
- [x] Document authorization and safety model
- [ ] Correct remaining documentation inconsistencies
- [ ] Remove tracked Python bytecode and add repository hygiene rules

## Phase 1: Wifite-inspired interface

- [ ] Establish one primary interactive entry point
- [ ] Replace the informational dashboard with a navigable workflow
- [ ] Keep workspace and authorized scope visible
- [ ] Add target list and target detail screens
- [ ] Show live discovery and execution progress
- [ ] Add clear cancellation, failure, and completion states
- [ ] Preserve CLI compatibility and test both entry points

## Phase 2: Workflow orchestrator

- [ ] Introduce application services and a workflow state model
- [ ] Coordinate scope validation, discovery, analysis, planning, approval, and execution
- [ ] Publish structured progress events to the interface
- [ ] Persist assessment lifecycle and recoverable failures
- [ ] Ensure CLI and TUI use the same application services

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
- [ ] Add explicit per-action approval records
- [ ] Revalidate scope and policy immediately before dispatch
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
- [ ] Add CI for tests, linting, and static analysis

## Phase 8: Expert features and extensibility

- [ ] Add searchable advanced module metadata controls
- [ ] Support custom profiles and policy files
- [ ] Add documented integration boundaries
- [ ] Add plan import/export
- [ ] Consider third-party extensions only when a concrete use case exists

## Non-goals

MSFAuto will not silently attack arbitrary targets, bypass scope controls, or hide operations from the operator. Discovery does not imply authorization. Exploitation, credential attacks, persistence, pivoting, and destructive actions remain disabled by default and outside the normal automated workflow.
