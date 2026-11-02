# Changelog

All notable changes to MSFAuto are documented here.

## Unreleased

### Planning and architecture
- Defined a Wifite-inspired, terminal-first guided assessment experience.
- Documented component boundaries, data flow, and incremental migration strategy.
- Defined the assessment lifecycle from scope validation through reporting.
- Documented authorization, approval, execution, and evidence-handling requirements.
- Audited existing modules and mapped them to the target architecture.

### Application entry point
- Added `python -m msfauto` as a short entry point while retaining `python -m msfauto.cli`.

### Maintenance
- Added Python, virtual environment, local database, cache, and secret exclusions to `.gitignore`.
- Removed tracked Python bytecode cache files from the repository.
- Corrected README descriptions of implemented functionality and planned workflow.
