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
- [x] Bounded HTTP/HTTPS and SSH service enumeration with append-only structured observations.
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

OSV workflow integration is now active when explicit mappings are configured, but this does **not** mean the platform already provides a complete vulnerability assessment or exploitation lifecycle. The current Metasploit execution adapter supports only its fixed passive-check allowlist; arbitrary exploit modules are not executable through the current workflow. Exploit catalog matching identifies and persists candidate opportunities. Explicit review/authorization and a durable execution state machine are implemented; actual exploit dispatch integration, framework reconciliation, and session handling remain outstanding.

## Current handoff — 2026-11-03

### Latest implementation milestone: durable exploit execution lifecycle
- Added `msfauto/execution/lifecycle.py` as a separate lifecycle domain; the existing passive-check manager and its fixed Metasploit allowlist are unchanged.
- Added durable SQLite execution records and append-only transition events. State updates use a conditional state update to reject concurrent/stale transitions. A unique database constraint ensures each authorization can create only one execution attempt.
- Lifecycle states include `prepared`, `dispatching`, `dispatch_uncertain`, `running`, `cancelling`, `completed`, `failed`, `timed_out`, and `cancelled`.
- Preparation verifies the stored opportunity, accepted review, persisted authorization, and current workspace scope.
- The pre-dispatch transition re-reads the opportunity, review, authorization, and current workspace policy. The `dispatching` record is persisted before a future external RPC call.
- Recovery converts interrupted `dispatching` and `cancelling` records to `dispatch_uncertain`. Uncertain attempts cannot be dispatched again; operator reconciliation is required. A confirmed non-dispatch closes the attempt and requires a new review/authorization for another attempt.
- Each authorization is single-use, enforced by a SQLite unique index, so one approval cannot be reused to create duplicate execution attempts.
- Terminal states cannot be reopened. No exploit RPC dispatch was added.
- Added lifecycle tests for durable transitions, stale scope, interrupted dispatch, uncertain reconciliation, non-retry behavior, and terminal-state enforcement.

### Previous milestone: exploit review and action-specific authorization
- Added explicit accepted/rejected/deferred human review decisions bound to the exact workspace, opportunity, exploit module, target, port, protocol, product, and observed version.
- Added short-lived authorization records that require an accepted review, explicit approver/rationale, dangerous-actions workspace profile, and an in-scope target/port.
- Authorization binds a scope snapshot and expires after 15 minutes by default (maximum eight hours). Validation fails closed on changed opportunity identity, scope change, expiry, or revocation.
- Persisted review history, authorization records, and revocation state in SQLite.

### Earlier milestone: persistent Metasploit exploit catalog synchronization
- Added the dedicated Metasploit RPC `module.exploits` client method and metadata importer.
- Import is limited to explicitly mapped exploit modules; product/version/advisory applicability is never inferred from module names or descriptions.
- Persisted synchronized catalog definitions by workspace while preserving operator-controlled mappings.
- Assessment merges active synchronized entries with curated JSON definitions. Synchronization is metadata-only and does not approve or execute modules.

## Work sequence

1. **Service enumeration foundation**
   - Extend the Nmap fingerprint baseline with structured service-specific enumeration adapters (HTTP/HTTPS, SSH, FTP, SMB2 negotiation, and TLS-only handshake inspection are implemented; HTTP technology detection remains).
   - Define probe/result contracts, normalized attributes, source provenance, timestamps, and confidence.
   - Preserve raw tool output as evidence while parsing structured observations for later stages.
   - Keep per-service timeouts, output limits, concurrency bounds, and scope/port checks.

2. **Vulnerability assessment foundation**
   - [x] Add normalized advisory and candidate domain records with source provenance, affected-version metadata, prerequisites, references, and evidence requirements.
   - [x] Match observed service products and exact versions to advisory records; retain missing or nonmatching versions as unverified hypotheses.
   - [x] Persist workspace-scoped candidates with evidence references, rationale, and bounded confidence.
   - [x] Add an OSV.dev package-version query adapter and normalized advisory ingestion for explicitly identified package ecosystems.
   - [x] Preserve source IDs, aliases, references, affected versions, and raw affected-range metadata in the advisory registry.
   - [ ] Add maintained bulk/incremental feed synchronization and normalized ecosystem-specific range evaluation.
   - [ ] Add broader CPE normalization and service-to-OS-package identity mappings.
   - [ ] Add configuration/behavior-based checks, coverage accounting, and independent validation.
   - Never declare a vulnerability solely from a banner or a version string.

3. **Exploit intelligence and execution architecture**
   - [x] Introduce a first-class exploit catalog/registry, separate from passive checks.
   - [x] Represent source attribution, affected products/versions, prerequisites, required options, target compatibility metadata, risk, and supporting references.
   - [x] Match exact product aliases and versions, with optional links to known vulnerability candidate IDs; persist workspace-scoped opportunities.
   - [x] Add a Metasploit RPC exploit-module importer with explicit product/version/advisory mappings and normalized module metadata.
   - [x] Persist imported catalog definitions with workspace isolation and explicit refresh/synchronization.
   - [x] Merge active synchronized catalog entries with curated entries in assessment runs while preserving operator-controlled mappings.
   - Add maintained catalog synchronization/import adapters and version-range semantics with source-specific tests.
   - Represent expected outcomes and richer target compatibility metadata as catalog sources are integrated.
   - [x] Add explicit exploit review and action-specific authorization before dispatch.
   - [x] Build a durable execution lifecycle for preparation, dispatch intent, running, completion, failure, timeout, cancellation, and uncertain dispatch. Unknown outcomes remain uncertain and are never automatically retried.
   - Next: add a controlled Metasploit dispatch adapter that can only consume a prepared lifecycle record and its exact authorization; begin with isolated lab validation and explicit module/target selection. Do not expose arbitrary module execution as a shortcut.

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

## Immediate next milestone: controlled Metasploit dispatch integration

The authorization and durable lifecycle layers are implemented, but the lifecycle does not send RPC requests. The next milestone is a narrow adapter that accepts only a prepared execution record, reloads and validates its exact authorization and scope, verifies the module against the synchronized exploit catalog, and makes one dispatch attempt. A lost or ambiguous RPC response must transition to `dispatch_uncertain` and must never trigger an automatic retry. Start with an isolated-lab test harness before enabling real dispatch.

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
- [x] Enable bounded Nmap service/version detection (-sV --version-light).
- [x] Preserve product, version, probe method, confidence, extra info, tunnel, CPEs, source, and observation timestamp in normalized service records.
- [x] Add HTTP/HTTPS and SSH service-specific enumeration beyond Nmap version probes.
- [ ] Expand protocol coverage to additional HTTP technology detection.
- [x] Add bounded FTP greeting and FEAT enumeration with structured observations.
- [x] Add unauthenticated SMB2 NEGOTIATE enumeration for TCP/445 and explicitly fingerprinted SMB services.
- [x] Add HTTP/HTTPS and SSH enumeration modules and structured observations.
- [x] Preserve observation provenance and confidence for Nmap service fingerprints.
- [x] Add representative Nmap XML parsing, malformed-confidence, persistence round-trip, and legacy-schema migration tests.
- [x] Add HTTP and SSH adapter tests, including partial SSH banners and scope filtering.
- [x] Add TLS-only certificate fingerprint inspection and deeper handshake metadata collection.
- [x] Add SMB2 negotiation enumeration and a local fake-server test.
- [x] Add FTP enumeration and a local fake-server test.

### Phase 2 — Vulnerability assessment
- [x] Establish initial advisory and candidate domain records with source attribution.
- [x] Map exact product/version observations to candidate advisories; retain ambiguous matches as unverified.
- [x] Persist candidate status, evidence references, rationale, and confidence by workspace.
- [ ] Integrate a maintained vulnerability knowledge source/feed and normalize CPE identifiers.
- [ ] Add configuration/behavior checks, prerequisites evaluation, and assessment coverage.
- [ ] Distinguish candidate, unverified, confirmed, and disproven results through independent validation.
- [ ] Add prioritization based on technical relevance and evidence, not severity labels alone.

### Phase 3 — Exploit intelligence and execution
- [x] Establish a first-class exploit catalog separate from passive checks.
- [x] Normalize core exploit metadata, affected targets, prerequisites, required options, and references from Metasploit RPC.
- [x] Match candidate exploits to observed target intelligence using explicit product/version/advisory mappings.
- [x] Import mapped Metasploit exploit metadata through the dedicated RPC catalog endpoint.
- [x] Persist imported catalog definitions and support refresh/synchronization into assessment runs.
- [x] Merge synchronized catalog entries into assessment runs while preserving explicit operator mappings.
- [x] Add explicit operator review and action-specific authorization.
- [ ] Add bounded exploit execution through supported integrations.
- [x] Persist dispatch state and execution outcomes; handle uncertain dispatch through operator reconciliation.
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
- [x] Define explicit lifecycle transitions for exploit execution failure, cancellation, interruption, and completion.
- [x] Add recovery and operator reconciliation for uncertain exploit dispatches; broader assessment-run/job recovery remains.
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
