# Development Migration Plan

## Product and interface alignment

MSFAuto is an automated security assessment platform. Development priority is the capability to discover and enumerate assets, assess vulnerabilities, support authorized exploitation, assess authorized post-exploitation impact, validate outcomes, and correlate evidence.

The intended primary interface is a terminal-only, full-screen Textual application with numbered menus and keyboard navigation. There is no web interface or native desktop GUI in the product plan. Keep domain and application services independent of Textual widgets so the terminal presentation can evolve without rewriting assessment logic.

## Baseline audit

The repository has working foundations for workspace onboarding, SQLite persistence, explicit scope, Nmap discovery and XML import, read-only Metasploit metadata, deterministic recommendations, bounded jobs, approvals, evidence, findings, reporting, and run-specific plan snapshots.

The current Metasploit execution adapter is deliberately limited to a fixed passive service-version allowlist. A general exploit catalog, exploit execution lifecycle, vulnerability assessment engine, post-exploitation/session management, and evidence-backed validation are not yet implemented. These are core product capabilities and should be built as real domain behavior rather than represented by placeholder packages.

## Package migration status

The first migration slice is implemented: discovery, scope, assessment planning, storage, core orchestration, interface, execution, and Metasploit integration have responsibility-based packages. Domain records are split into focused modules under `msfauto/storage/models/`. Tests are grouped into unit, integration, workflow, and interface suites.

Keep the application and domain services decoupled from the current Textual interface. Introduce new packages only when there is concrete behavior and tests. Preserve existing SQLite data through explicit schema migrations.

## Existing-code disposition

| Existing area | Current responsibility | Direction |
|---|---|---|
| `cli.py` | CLI bootstrap and current interactive entry | Retain for scripting and diagnostics |
| `interface/app.py` | Full-screen Textual terminal application | Evolve the menu-driven terminal workflows; keep domain behavior in application services |
| `core/` | Workflow coordination and persisted events | Evolve into assessment orchestration across all engines |
| `discovery/` | Nmap discovery and XML parsing | Expand into reconnaissance and service observation pipeline |
| `scope/` | Scope policy and validation | Retain as a mandatory execution boundary |
| `assessment/` | Read-only planning and approvals | Expand to vulnerability assessment and exploit review domain services |
| `execution/` | Bounded safe-check job lifecycle | Separate passive checks from first-class exploit execution |
| `integrations/` | Nmap and Metasploit clients | Add service enumeration and exploit adapters behind explicit contracts |
| `evidence/`, `findings/` | Evidence artifacts and reviewed findings | Add run provenance and validation/correlation links |
| `storage/` | SQLite persistence and domain models | Add explicit models/migrations for vulnerabilities, exploit attempts, sessions, and run provenance |

## Phase 0 — Product architecture
- [x] Correct product definition to prioritize assessment capability.
- [x] Make exploitation and post-exploitation explicit core capabilities.
- [x] Confirm terminal-only product direction and replace the button dashboard with a numbered, keyboard-driven Textual interface.
- [ ] Audit current code against the intended capability model.
- [ ] Define domain contracts for enumeration, vulnerability assessment, exploit catalog/matching, exploit execution, sessions, and validation.

## Phase 1 — Reconnaissance and service enumeration
- [x] Nmap discovery and XML import.
- [x] Normalized host and service persistence.
- [ ] Improve service fingerprinting and version identification.
- [ ] Add service-specific enumeration integrations and structured parsers.
- [ ] Preserve source provenance, timestamps, and confidence.
- [ ] Test partial, malformed, and representative service responses.

## Phase 2 — Vulnerability assessment
- [ ] Create a vulnerability knowledge/check registry.
- [ ] Correlate service and configuration observations with candidate weaknesses.
- [ ] Model prerequisites, evidence requirements, confidence, and coverage.
- [ ] Distinguish candidate, unverified, validated, and disproven outcomes.
- [ ] Prioritize using technical relevance and evidence.

## Phase 3 — Exploit intelligence and execution
- [ ] Create a first-class exploit catalog separate from passive checks.
- [ ] Normalize affected targets, prerequisites, options, compatibility, and expected outcomes.
- [ ] Match candidate techniques against observed target intelligence.
- [ ] Add operator review and action-specific authorization.
- [ ] Implement bounded exploit execution through supported integrations.
- [ ] Persist dispatch state and outcomes; require reconciliation for uncertain dispatch.
- [ ] Validate in controlled labs before broadening supported operations.

## Phase 4 — Post-exploitation and sessions
- [ ] Add session domain models and lifecycle.
- [ ] Link sessions to target, assessment run, originating operation, and evidence.
- [ ] Add separately authorized post-exploitation assessment capabilities.
- [ ] Keep persistence, stealth, pivoting, and destructive actions outside default workflows.

## Phase 5 — Validation and analysis
- [ ] Validate candidate weaknesses with evidence-backed checks.
- [ ] Verify exploit outcomes independently where possible.
- [ ] Correlate results across discovery, enumeration, vulnerability assessment, exploitation, and sessions.
- [ ] Produce evidence-linked findings with confidence, limitations, and analyst review.
- [ ] Identify relationships and potential attack paths from validated observations.

## Phase 6 — Workflow reliability
- [x] Persist assessment runs, workflow events, and immutable run-specific plan snapshots.
- [ ] Associate approvals, jobs, evidence, findings, and sessions with originating runs.
- [ ] Add explicit interruption and recovery semantics.
- [ ] Add dispatch tracking and operator reconciliation; never blindly retry uncertain operations.
- [ ] Orchestrate the complete assessment lifecycle.
- [ ] Add end-to-end success and failure-path tests.

## Phase 7 — Terminal interaction
- [x] Define terminal interaction architecture around numbered menus and keyboard navigation.
- [x] Make the Textual application the primary operator interface.
- [ ] Build connected asset, service, vulnerability, exploit, execution/session, evidence, and findings views.
- [ ] Add interactive assessment workflows and clear execution progress.
- [ ] Retain CLI for scripting, automation, imports, and diagnostics.

## Phase 8 — Reporting and extensibility
- [x] JSON and Markdown workspace reports.
- [ ] Run-specific reports with full provenance.
- [ ] HTML reports and export templates.
- [ ] Cross-run history and comparison.
- [ ] Document extension points for assessment modules and integrations.

## Repository rules

- Work directly on `main`; do not create feature branches unless explicitly requested.
- Do not introduce empty placeholder packages.
- Avoid new dependencies unless they solve a demonstrated requirement.
- Preserve user data and existing SQLite compatibility.
- Update tests and `CHANGELOG.md` with each meaningful implementation change.
- Update `ROADMAP.md` whenever the milestone or next step changes.
- Do not claim tests passed unless they were actually run.
