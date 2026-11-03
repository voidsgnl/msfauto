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

OSV workflow integration is now active when explicit mappings are configured, but this does **not** mean the platform already provides a complete vulnerability assessment or exploitation lifecycle. The current Metasploit execution adapter supports only its fixed passive-check allowlist; arbitrary exploit modules are not executable through the current workflow. Exploit catalog matching now identifies and persists candidate opportunities, but explicit review/approval, execution lifecycle, dispatch reconciliation, and session handling remain unimplemented.

## Current handoff — 2026-11-03

### Latest implementation milestone: exploit intelligence catalog and matching
- Nmap discovery now requests service/version detection with -sV --version-light, still constrained by the workspace target and port scope.
- Parsed service records retain product/version, Nmap probe method and confidence, extra information, TLS tunnel metadata, CPE identifiers, source, and observation timestamp.
- SQLite schema upgrades add these fields in place; legacy service rows receive conservative unknown/zero defaults and remain readable.
- Added tests for enriched XML parsing, confidence validation, enriched persistence round-trip, legacy database migration, and version-detection command flags.
- Added protocol-aware HTTP/HTTPS and SSH enumeration adapters. HTTP uses a bounded HEAD request and captures status/headers; HTTPS also records negotiated TLS version, cipher, and certificate SHA-256. SSH captures the server identification banner.
- Enumeration runs only for discovered open services whose Nmap fingerprint identifies HTTP/HTTPS, SSH, or FTP (including conventional FTP ports), and enforces saved address/port scope, bounded timeout, and bounded concurrency. Per-service failures are stored as observations rather than aborting the assessment.
- FTP enumeration captures the server greeting and a bounded FEAT response; FEAT is optional, so a valid greeting remains useful when the command is unsupported.
- SMB enumeration sends an unauthenticated SMB2 NEGOTIATE request only (no session setup or file operations) and records the selected dialect, security mode, server GUID, capabilities, and negotiated size limits.
- FTP and SMB2 adapter tests use local fake servers. CI run #217 passed on Python 3.10, 3.12, and 3.14 (77 tests; Ruff passed).
- Added a local TLS server fixture and tests for certificate fingerprint capture and TLS-vs-HTTP dispatch. GitHub Actions run #231 passed on Python 3.10, 3.12, and 3.14: 79 tests passed; Ruff passed on all three versions.
- Added normalized vulnerability advisory and candidate domain records, strict product/CPE identity and exact version matching, source/evidence provenance, confidence limits, and workspace-scoped candidate persistence.
- Added an OSV.dev client for exact package-ecosystem-version queries, normalizing returned advisory IDs, aliases, references, severity, affected versions, and original OSV affected-range metadata.
- OSV package identity is explicit input (package name + ecosystem); MSFAuto does not guess an operating-system package identity from a network banner. Callers can supply product aliases to map a known package to a discovered service product. OSV query matches are recorded as source-backed matched versions.
- Added persistent advisory registry storage and tests for request shape, package identity filtering, provider failures, metadata normalization, persistence, and end-to-end OSV-to-candidate matching. GitHub Actions run #259 passed on Python 3.10, 3.12, and 3.14: 92 tests passed (plus 2 subtests); Ruff passed on all versions. Product/version matches remain candidates or unverified hypotheses; they cannot become confirmed findings from banner evidence alone.
- Integrated OSV into the actual assessment workflow using explicit JSON-configured service product-to-package/ecosystem mappings (`MSFAUTO_OSV_PACKAGE_MAPPINGS`). Each distinct package/ecosystem/version is queried once; advisory records are merged and persisted; candidate matches are stored per workspace. OSV provider failures are isolated per query and surfaced in workflow events without aborting discovery, enumeration, or planning. Unmapped and unversioned services are skipped rather than guessed.
- Added tests for mapping validation, query deduplication across hosts, candidate persistence, missing-version skips, and provider-failure isolation. GitHub Actions run #274 passed on Python 3.10, 3.12, and 3.14: 96 tests passed (plus 2 subtests); Ruff passed on all versions.
- Added the dedicated `msfauto/exploitation/` package with source-attributed exploit definitions, JSON catalog loading (`MSFAUTO_EXPLOIT_CATALOG`), and exact product/version matching with optional linkage to vulnerability candidate IDs.
- Added deterministic workspace-scoped exploit opportunity records and SQLite persistence, plus the `exploit_intelligence` stage in the assessment workflow. Matches remain `identified`; they do not imply authorization, confirmed exploitability, or execution.
- Added tests for catalog validation, exact/negative matching, advisory-linked matching, storage round-trip, and end-to-end assessment workflow integration. CI verification for the full exploit-intelligence milestone is pending.
- Added unit coverage for exact matches, missing/nonmatching versions, unrelated products, closed services, provenance, confirmation guardrails, and persistence. CI run #244 passed on Python 3.10, 3.12, and 3.14: 87 tests passed (plus 2 subtests); Ruff passed on all versions.
- Added append-only, workspace-scoped service observation persistence and integrated enumeration as an assessment stage after discovery.
- Added local fake-server tests for HTTP and SSH plus scope/port filtering tests. CI run #217 passed on Python 3.10, 3.12, and 3.14 (77 tests; Ruff passed).

- Repository: `voidsgnl/msfauto`, working branch: `main`.
- The local repository was replaced with a clean clone after local Git object corruption; the user reported **66 tests passing** on the recovered checkout before the most recent documentation changes.
- Work directly on `main`; do not create feature branches unless explicitly requested.
- The previous roadmap incorrectly defined the product as terminal-first and treated the Textual interface as the intended experience. This has been corrected: the intended interface is graphical; the current Textual screen is a prototype to be superseded.
- The previous roadmap also underrepresented exploitation. Exploitation and separately authorized post-exploitation assessment are now explicit core capabilities.
- After each meaningful implementation milestone, update this roadmap and `CHANGELOG.md`; update `README.md` and architecture/workflow docs when product behavior or direction changes.
- Record test and CI status accurately. Do not claim local tests passed unless actually run.
- Latest service-fingerprint milestone: CI run #196 passed on commit 1ef0a086509cb88ad7ff2dc51613e2352c7af676; the test commit reported 69 passing tests. The subsequent HTTP/HTTPS and SSH enumeration milestone passed CI on commit `af791bad8975ff0e4cf4889bf1f59e02f0d44f14` with 75 tests and Ruff passing. FTP and SMB2 enumeration are implemented. CI run #217 passed on commit `65785106823f4f2e2c80376e48cab15e86b86e7e`: 77 tests passed and Ruff passed on Python 3.10, 3.12, and 3.14. TLS-only inspection passed CI run #231 on Python 3.10, 3.12, and 3.14 (79 tests; Ruff clean). The initial vulnerability assessment foundation passed CI run #244 on Python 3.10, 3.12, and 3.14 (87 tests; 2 subtests; Ruff clean). CPE 2.2 compatibility passed CI run #248 (88 tests; 2 subtests; Ruff clean). OSV ingestion and matcher integration passed CI run #259 (92 tests; 2 subtests; Ruff clean).

## Immediate next milestone: make the assessment engine useful

The next implementation work should improve actual assessment capability, not add more policy/reporting scaffolding or expand the Textual UI.

### Work sequence

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
   - Add maintained catalog synchronization/import adapters and version-range semantics with source-specific tests.
   - Represent expected outcomes and richer target compatibility metadata as catalog sources are integrated.
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
