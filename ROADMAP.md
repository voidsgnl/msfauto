# MSFAuto Roadmap

## Product definition

**MSFAuto is an automated security assessment platform for discovering, enumerating, assessing, exploiting, and validating security weaknesses in explicitly authorized environments.**

Its primary value is the assessment work it can perform and the quality of the technical intelligence it produces. Safety controls, evidence integrity, workflow orchestration, and reporting are essential supporting capabilities; they are not the product's central purpose.

MSFAuto should not become merely a graphical wrapper around Metasploit. Metasploit is an important integration and execution engine within a broader platform that owns discovery, service intelligence, vulnerability assessment, exploit orchestration, result validation, and analysis.

## Product and interface direction

- The intended product interface is a **graphical application**, not a terminal UI or TUI.
- The user-supplied UI reference informs visual language and interaction feel; it is not a literal terminal implementation specification or a source of copied terminology, commands, payloads, or workflow steps.
- A dense security-console aesthetic may inform the graphical presentation: strong status hierarchy, clear target/service tables, activity feedback, compact technical detail, and operator-visible progress.
- The current Textual interface is an existing prototype, not the intended final interface. Do not expand it into a larger TUI or treat its layout as the target product.
- Keep the assessment domain, orchestration, integrations, and persistence independent of the interface so a graphical frontend can use the same application services.
- CLI commands may remain useful for scripting, automation, and diagnostics, but they are not the primary user experience.

## Core assessment capabilities

These are first-class product capabilities, not optional add-ons:

1. **Reconnaissance and discovery** — identify in-scope assets, hosts, ports, and exposed services.
2. **Service enumeration and intelligence** — fingerprint services, identify versions and technologies, inspect configurations, and gather useful context beyond open-port detection.
3. **Vulnerability assessment** — map observations to potential vulnerabilities and weaknesses, distinguish evidence from hypotheses, and prioritize assessment opportunities.
4. **Exploitation** — research and select applicable exploit techniques, check prerequisites, configure and execute explicitly authorized exploit attempts, and capture outcomes. Exploitation must be a distinct engine and workflow, not buried inside generic safe checks.
5. **Post-exploitation assessment** — where separately authorized, assess achieved access, privilege context, host information, and security impact. This does not imply persistence, stealth, lateral movement, or destructive behavior as default features.
6. **Validation and verification** — determine whether suspected weaknesses are actually present, whether an exploit attempt succeeded, and what the evidence supports.
7. **Analysis and correlation** — correlate results across assets and stages, identify relationships and potential attack paths, assess confidence, and prioritize meaningful findings.

Supporting platform capabilities:
- Assessment orchestration and durable run history.
- Explicit authorization, scope enforcement, and action-specific approvals.
- Session and job lifecycle management.
- Evidence provenance and integrity.
- Findings review and reporting.
- Graphical interaction, configuration, and visualization.

## Current implementation baseline

- [x] Interactive application entry point and workspace onboarding.
- [x] SQLite workspace persistence.
- [x] Explicit IP/CIDR scope and optional port allowlists.
- [x] Scope-enforced Nmap XML import and normalized service storage.
- [x] Bounded Nmap execution adapter.
- [x] Read-only Metasploit RPC module metadata integration.
- [x] Explicit RPC execution for an allowlist of passive service-version checks.
- [x] Module metadata and options persistence.
- [x] Explainable read-only recommendations.
- [x] Bounded job manager with scope checks, cancellation, and concurrency limits.
- [x] Structured job events and persisted results.
- [x] Per-action approval records and execution-layer approval enforcement.
- [x] Bounded evidence collection with integrity verification.
- [x] Persisted evidence-linked findings.
- [x] Workspace-scoped JSON and Markdown reports.
- [x] Assessment-run records, events, and immutable run-specific plan snapshots.
- [x] CI coverage for Python 3.10, 3.12, and 3.14.

These foundations do **not** mean the platform already provides a complete vulnerability assessment or exploitation lifecycle. The current Metasploit execution adapter supports only its fixed passive-check allowlist; arbitrary exploit modules are not executable through the current workflow.

## Current handoff — 2026-11-03\n\n### Latest implementation milestone: Nmap service fingerprint enrichment\n- Nmap discovery now requests service/version detection with -sV --version-light, still constrained by the workspace target and port scope.\n- Parsed service records retain product/version, Nmap probe method and confidence, extra information, TLS tunnel metadata, CPE identifiers, source, and observation timestamp.\n- SQLite schema upgrades add these fields in place; legacy service rows receive conservative unknown/zero defaults and remain readable.\n- Added tests for enriched XML parsing, confidence validation, enriched persistence round-trip, legacy database migration, and version-detection command flags.\n- Remote CI status for this code change is pending until the new workflow run completes; local tests have not been run by the assistant.

- Repository: `voidsgnl/msfauto`, working branch: `main`.
- The local repository was replaced with a clean clone after local Git object corruption; the user reported **66 tests passing** on the recovered checkout before the most recent documentation changes.
- Work directly on `main`; do not create feature branches unless explicitly requested.
- The previous roadmap incorrectly defined the product as terminal-first and treated the Textual interface as the intended experience. This has been corrected: the intended interface is graphical; the current Textual screen is a prototype to be superseded.
- The previous roadmap also underrepresented exploitation. Exploitation and separately authorized post-exploitation assessment are now explicit core capabilities.
- After each meaningful implementation milestone, update this roadmap and `CHANGELOG.md`; update `README.md` and architecture/workflow docs when product behavior or direction changes.
- Record test and CI status accurately. Do not claim local tests passed unless actually run.

## Immediate next milestone: make the assessment engine useful

The next implementation work should improve actual assessment capability, not add more policy/reporting scaffolding or expand the Textual UI.

### Work sequence

1. **Service enumeration foundation**
   - Extend the Nmap fingerprint baseline with structured service-specific enumeration adapters (begin with HTTP/HTTPS and SSH).
   - Define probe/result contracts, normalized attributes, source provenance, timestamps, and confidence.
   - Preserve raw tool output as evidence while parsing structured observations for later stages.
   - Keep per-service timeouts, output limits, concurrency bounds, and scope/port checks.

2. **Vulnerability assessment foundation**
   - Build a capability/knowledge model that maps observed products, versions, configurations, and behaviors to candidate checks.
   - Distinguish confirmed observations, candidate weaknesses, and unverified hypotheses.
   - Track prerequisites, evidence requirements, confidence, and assessment coverage.
   - Avoid declaring a vulnerability solely from a banner or a version string.

3. **Exploit intelligence and execution architecture**
   - Introduce a first-class exploit catalog/registry, separate from passive checks.
   - Represent affected products/versions, prerequisites, required options, target compatibility, expected outcome, risk, and supporting references.
   - Add explicit exploit review and action-specific authorization before dispatch.
   - Build an execution lifecycle that records preparation, dispatch, running, completion, failure, timeout, cancellation, and uncertain dispatch state.
   - Start with controlled lab validation and a small, testable integration slice; do not expose arbitrary module execution as a shortcut.

4. **Post-exploitation and session management**
   - Define session records and lifecycle separately from generic jobs.
   - Support only explicitly authorized, bounded post-exploitation assessment actions.
   - Associate every session and resulting observation with its originating assessment run and evidence.

5. **Validation, correlation, and useful results**
   - Verify suspected weaknesses and exploit outcomes using independent evidence where possible.
   - Correlate observations, candidate vulnerabilities, exploit attempts, sessions, and findings.
   - Make confidence and limitations visible.
   - Generate findings from validated evidence with analyst review.

6. **End-to-end workflow and reliability**
   - Connect discovery, enumeration, vulnerability assessment, exploit review/approval, execution, validation, evidence, findings, and reporting into one traceable run.
   - Add interruption/recovery and dispatch reconciliation before any resume/retry behavior.
   - Never automatically retry an operation whose dispatch outcome is unknown.

7. **Graphical application**
   - Replace the Textual prototype with a graphical interface using shared application services.
   - Design the interface around assets, services, assessment results, exploit opportunities, execution/session activity, evidence, and findings.
   - Keep dense technical detail accessible without making the product a terminal emulator.
   - Do not begin by merely porting the current TUI screen layout.

## Roadmap phases

### Phase 0 — Product and architecture alignment
- [x] Correct product definition to focus on security assessment capability.
- [x] Make exploitation and post-exploitation explicit first-class capabilities.
- [x] Correct the intended interface direction to graphical, not TUI.
- [ ] Audit the current implementation against the core capability model.
- [ ] Define domain boundaries and contracts for enumeration, vulnerability assessment, exploit intelligence, exploit execution, sessions, and validation.

### Phase 1 — Reconnaissance and service enumeration
- [x] Nmap discovery and XML import.
- [x] Normalized host and service persistence.
- [x] Enable bounded Nmap service/version detection (-sV --version-light).\n- [x] Preserve product, version, probe method, confidence, extra info, tunnel, CPEs, source, and observation timestamp in normalized service records.\n- [ ] Expand fingerprinting with service-specific enumeration beyond Nmap version probes.
- [ ] Add service-specific enumeration modules and structured parsers.
- [x] Preserve observation provenance and confidence for Nmap service fingerprints.
- [x] Add representative Nmap XML parsing, malformed-confidence, persistence round-trip, and legacy-schema migration tests.\n- [ ] Add service-specific enumeration integrations and tests for partial protocol responses.

### Phase 2 — Vulnerability assessment
- [ ] Establish a vulnerability knowledge and check registry.
- [ ] Map service/product/configuration observations to candidate weaknesses.
- [ ] Model prerequisites, evidence, confidence, and coverage.
- [ ] Distinguish detected, suspected, unverified, confirmed, and disproven results.
- [ ] Add prioritization based on technical relevance and evidence, not severity labels alone.

### Phase 3 — Exploit intelligence and execution
- [ ] Establish a first-class exploit catalog separate from passive checks.
- [ ] Normalize exploit metadata, affected targets, prerequisites, options, and expected outcomes.
- [ ] Match candidate exploits to observed target intelligence.
- [ ] Add explicit operator review and action-specific authorization.
- [ ] Add bounded exploit execution through supported integrations.
- [ ] Persist dispatch state and execution outcomes; handle uncertain dispatch through operator reconciliation.
- [ ] Add controlled lab integration tests before enabling broader use.

### Phase 4 — Post-exploitation and sessions
- [ ] Introduce session domain models and lifecycle tracking.
- [ ] Associate sessions with target, assessment run, originating operation, and evidence.
- [ ] Add separately authorized post-exploitation assessment capabilities.
- [ ] Keep persistence, stealth, pivoting, and destructive actions out of default workflows.

### Phase 5 — Validation and analysis
- [ ] Validate candidate vulnerabilities with evidence-backed checks.
- [ ] Verify exploit outcomes and distinguish tool success from security impact.
- [ ] Correlate results across discovery, enumeration, vulnerability checks, exploitation, and sessions.
- [ ] Build evidence-linked findings with confidence, limitations, and analyst review.
- [ ] Identify relationships and potential attack paths from validated observations.

### Phase 6 — Workflow orchestration and reliability
- [x] Persist assessment runs, workflow events, and immutable run-specific plan snapshots.
- [ ] Associate jobs, approvals, evidence, findings, and sessions with the originating run.
- [ ] Define explicit lifecycle transitions for failure, cancellation, interruption, and completion.
- [ ] Add safe recovery and dispatch reconciliation; never blindly retry uncertain operations.
- [ ] Integrate all assessment engines into one traceable workflow.
- [ ] Add end-to-end tests across successful and failure paths.

### Phase 7 — Graphical application
- [ ] Define graphical application architecture and frontend/backend boundary.
- [ ] Replace the Textual prototype as the primary interface.
- [ ] Build asset, service, vulnerability, exploit, execution/session, evidence, and findings views.
- [ ] Add interactive assessment workflows and visible execution progress.
- [ ] Keep CLI support for scripting and diagnostics, not as the primary UX.

### Phase 8 — Reporting and extensibility
- [x] JSON and Markdown workspace reports.
- [ ] Run-specific reports with full provenance.
- [ ] HTML reports and export templates.
- [ ] Searchable assessment history and cross-run analysis.
- [ ] Documented extension points for assessment modules and integrations.

## Engineering invariants

- Scope and authorization are enforced in the execution layer, not only in the interface.
- Discovery does not imply authorization for exploitation.
- Exploitation requires explicit, action-specific authorization and a supported execution path.
- Post-exploitation actions require their own authorization; an obtained session is not blanket permission.
- Recommendations are not findings; tool invocation success is not proof of vulnerability or impact.
- Preserve raw evidence, provenance, and integrity; do not silently rewrite source observations.
- Bound execution time, concurrency, output size, and resource use.
- Never automatically resume or retry an operation whose dispatch state is unknown; require operator reconciliation.
- Keep domain and application services independent of the UI framework.
- Preserve workspace isolation and existing user data during schema changes.
