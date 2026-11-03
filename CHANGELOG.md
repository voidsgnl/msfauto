# Changelog

All notable changes to MSFAuto are documented here.

## Unreleased

### Assessment run provenance
- Added immutable, run-specific SQLite snapshots of generated assessment plans while preserving the existing workspace-level latest-plan API.
- Validated that a snapshot belongs to an existing assessment run in the same workspace.
- Added workflow tests for run-plan retrieval and rejection of missing or cross-workspace run references.

### Assessment workflow audit
- Audited the current application-service, orchestrator, CLI, storage, and reporting boundaries.
- Documented that approval, safe-check execution, evidence, findings, and reporting remain separate from the discovery-and-planning run.
- Recorded the missing run-level provenance and interruption-recovery safeguards as prerequisites to end-to-end orchestration.

### Assessment workflow audit
- Audited the current application-service, orchestrator, CLI, storage, and reporting boundaries.
- Documented that approval, safe-check execution, evidence, findings, and reporting remain separate from the discovery-and-planning run.
- Recorded the missing run-level provenance and interruption-recovery safeguards as prerequisites to end-to-end orchestration.

### Roadmap and handoff
- Recorded the clean-clone recovery state and the latest locally reported test result (66 passed).
- Defined the next milestone: connect the existing assessment capabilities into a persisted, recoverable end-to-end workflow, with explicit acceptance criteria and safety invariants.

### Terminal interface transformation
- Replaced the generic dashboard presentation with a compact, terminal-native assessment console.
- Added a custom MSFAuto identity panel, persistent workspace and authorization context, compact action bar, color-coded activity feedback, target table, and structured detail panel.
- Kept discovery, target browsing, plan generation, scope review, keyboard shortcuts, and backend service boundaries intact.
- Used original MSFAuto terminology and copy; the visual reference informed presentation only.

### Terminal interface transformation
- Replaced the generic dashboard presentation with a compact, terminal-native assessment console.
- Added a custom MSFAuto identity panel, persistent workspace and authorization context, compact action bar, color-coded activity feedback, target table, and structured detail panel.
- Kept discovery, target browsing, plan generation, scope review, keyboard shortcuts, and backend service boundaries intact.
- Used original MSFAuto terminology and copy; the visual reference informed presentation only.


### Metasploit execution
- Added an explicit `--metasploit` CLI mode backed by the MessagePack RPC client.
- Added a fixed allowlist of passive service-version modules; module names containing `scanner/` are not trusted as a safety signal.
- Revalidated live Metasploit module stance before dispatch and passed only the approved target address and port as module options.
- Added bounded UUID polling, cancellation via `job.stop`, a 60-second execution timeout, and structured execution errors.
- Kept the deterministic adapter as the default; real Metasploit execution requires explicit opt-in and RPC credentials from environment variables.

### Approval and execution controls
- Added a bounded textual adapter-output contract with a 256 KB UTF-8 limit and best-effort secret redaction before output is exposed or persisted.
- Added job-result retrieval so the CLI can include sanitized adapter output in execution evidence.
- Added stable action identifiers and SQLite-persisted per-recommendation approval decisions.
- Required an approver identifier and exact `APPROVE` confirmation for each recommendation before CLI safe-check dispatch.
- Recorded rejections as well as approvals; unapproved recommendations are not dispatched.
- Enforced approval verification inside the job manager, including a second approval and scope check immediately before adapter dispatch; missing, rejected, mismatched, or revoked approvals fail closed.
- Bound approval records to the operation risk classification and added an in-place SQLite migration for existing approval tables.
- Added bounded local evidence artifact storage with SHA-256 integrity metadata and verification.
- Added SQLite-backed findings with severity, confidence, review status, and same-workspace evidence references.
- Automatically captured safe-check outcomes and structured job events as bounded evidence artifacts.
- Required evidence integrity and workspace ownership verification before evidence can be linked to a finding; did not auto-classify execution outcomes or banners as vulnerabilities.
- Added workspace-scoped JSON and Markdown assessment reports with scope, asset, job, finding, and evidence registers.
- Added report-time SHA-256 evidence integrity checks and redaction of common secret fields; raw evidence artifacts are not embedded in reports.


### Reporting
- Added `--report json` and `--report markdown` CLI exports with optional explicit output paths.
- Added report schema versioning, atomic file replacement, workspace isolation, and tests for redaction and tampered evidence.

### Quality and developer experience
- Added GitHub Actions CI for the test suite and Ruff across Python 3.10, 3.12, and 3.14.
- Added a project-local virtual environment setup script to avoid PEP 668 conflicts with externally managed Python installations.
- Updated development instructions to use the setup script and the project's virtual environment.

### Architecture alignment
- Moved discovery, scope management, assessment planning, SQLite persistence, orchestration, terminal interface, job execution, and Metasploit RPC into responsibility-based packages.
- Split domain records into focused modules under `msfauto/storage/models/` and removed transitional flat-module shims.
- Organized tests into unit, integration, workflow, and interface suites.
- Updated the CLI, interface, tests, and internal services to use canonical package imports.
- Preserved the existing SQLite schema and database initialization behavior.

### Workflow orchestration
- Added durable assessment-run records and timestamped workflow events in SQLite.
- Added a shared discovery-to-read-only-plan orchestrator with scope preflight, stage transitions, progress callbacks, and persisted failure states.
- Kept active checks out of the automated workflow; recommendations remain review-only.

### Interface
- Replaced the static Textual dashboard with a guided assessment screen.
- Added workspace/scope context, target browsing, selected-target details, and read-only plan display.
- Made the guided Textual interface the default interactive launch experience.
- Added keyboard shortcuts for discovery, targets, plans, scope, and exit.

### Application services
- Added an application-service boundary for discovery, target retrieval, and plan generation.
- Run discovery off the Textual event loop so the interface remains responsive.

### Documentation
- Updated the README, roadmap, and migration plan to reflect the initial interface implementation.

### Planning and architecture
- Defined a Wifite-inspired, terminal-first guided assessment experience.
- Documented component boundaries, data flow, and incremental migration strategy.
- Defined the assessment lifecycle from scope validation through reporting.
- Documented authorization, approval, execution, and evidence-handling requirements.
- Audited existing modules and mapped them to target responsibilities.

### Maintenance
- Added Python, virtual environment, local database, cache, and secret exclusions to `.gitignore`.
- Removed tracked Python bytecode cache files from the repository.
- Added `python -m msfauto` as a short entry point.
