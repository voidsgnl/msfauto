# Changelog

All notable changes to MSFAuto are documented here.

## Unreleased

### Architecture alignment
- Moved discovery, scope management, assessment planning, SQLite persistence, orchestration, terminal interface, job execution, and Metasploit RPC into responsibility-based packages.
- Centralized domain records under `msfauto/storage/models.py` while retaining a compatibility import module during migration.
- Organized tests into unit, integration, workflow, and interface suites.
- Updated the CLI and interface to use canonical package imports.
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
- Audited existing modules and mapped them to the target architecture.

### Maintenance
- Added Python, virtual environment, local database, cache, and secret exclusions to `.gitignore`.
- Removed tracked Python bytecode cache files from the repository.
- Added `python -m msfauto` as a short entry point.
