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

OSV workflow integration is active when explicit mappings are configured, but this does **not** mean the platform already provides a complete vulnerability assessment or exploitation lifecycle. The Metasploit passive-check adapter still supports only its fixed allowlist. A separate exploit dispatcher now supports a narrow, catalog-bound TCP profile using only persisted RHOSTS/RPORT values after exact review/authorization and scope revalidation. Framework job polling now reconciles UUID-specific terminal results without treating completion as proof of exploit success. Live isolated-lab validation, independent outcome validation, broader option/payload support, and session handling remain outstanding.

## Current handoff — 2026-11-04

### Latest implementation milestone: Metasploit job polling and reconciliation
- Added `MetasploitClient.job_list()` to validate and normalize the active framework job map.
- Added `msfauto/execution/reconciliation.py` with `MetasploitExploitReconciler` and a structured `ExploitPollResult`.
- Polling accepts only persisted `running` or `cancelling` records with both job ID and UUID references. Active jobs remain active; absent jobs are checked against the UUID-specific `module.results` endpoint.
- Only recognized framework states (`completed`, `failed`, `cancelled`) transition to terminal lifecycle states. Missing results, unknown statuses, and contradictory running results remain unresolved and do not alter the execution record.
- Framework completion is explicitly recorded as module execution completion, not proof of exploit success or security impact. Uncertain dispatch records remain on the separate operator-reconciliation path.
- Added fake-RPC tests for active jobs, completed/failed/cancelled results, missing results, unknown statuses, and rejection of uncertain records.
- GitHub Actions run #406 passed on Python 3.10, 3.12, and 3.14: 146 tests passed (plus 2 subtests); Ruff passed on all versions.

### Previous milestone: controlled Metasploit exploit dispatch
- Added `msfauto/execution/exploit_dispatch.py`, a dedicated dispatcher that accepts only an existing `prepared` execution ID; callers cannot pass arbitrary module names, targets, ports, or option dictionaries.
- Dispatch preflight reloads the stored opportunity and active workspace-synchronized catalog definition, confirms exact module identity, verifies live Metasploit module type, and inspects live options.
- The initial supported profile is deliberately narrow: TCP network exploit modules exposing both `RHOSTS` and `RPORT`, with no required options beyond those fields. The adapter supplies only the persisted authorized target and port; it does not expose payload, handler, listener, credential, or arbitrary datastore configuration.
- The dispatcher revalidates persisted opportunity, accepted review, authorization expiry/revocation, and current workspace scope immediately before dispatch intent is committed.
- Added an internal Metasploit RPC primitive for `module.execute`. The dispatcher performs one call only; a valid acknowledgement stores the framework job ID/UUID and moves to `running`.
- Any exception after dispatch intent is persisted becomes `dispatch_uncertain`; the adapter never retries. Preflight failures leave the execution in `prepared`.
- Existing passive-check execution and its fixed auxiliary allowlist are unchanged. No live exploit was run during implementation.
- GitHub Actions run #391 passed on Python 3.10, 3.12, and 3.14: 137 tests passed (plus 2 subtests); Ruff passed on all versions.

### Previous milestone: durable exploit execution lifecycle
- Added `msfauto/execution/lifecycle.py` as a separate lifecycle domain; the existing passive-check manager and its fixed Metasploit allowlist are unchanged.
- Added durable SQLite execution records and append-only transition events. State updates use a conditional state update to reject concurrent/stale transitions. A unique database constraint ensures each authorization can create only one execution attempt.
- Lifecycle states include `prepared`, `dispatching`, `dispatch_uncertain`, `running`, `cancelling`, `completed`, `failed`, `timed_out`, and `cancelled`.
- Preparation verifies the stored opportunity, accepted review, persisted authorization, and current workspace scope.
- The pre-dispatch transition re-reads the opportunity, review, authorization, and current workspace policy. The `dispatching` record is persisted before an external RPC call.
- Recovery converts interrupted `dispatching` and `cancelling` records to `dispatch_uncertain`. Uncertain attempts cannot be dispatched again; operator reconciliation is required. A confirmed non-dispatch closes the attempt and requires a new review/authorization for another attempt.
- Each authorization is single-use, enforced by a SQLite unique index, so one approval cannot create duplicate execution attempts.
- Terminal states cannot be reopened.

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
   - [x] Add a controlled Metasploit dispatch adapter that consumes only prepared lifecycle records and their exact authorization; initial support is restricted to catalog-bound TCP modules using RHOSTS/RPORT.
   - [x] Add framework job polling and UUID-specific result reconciliation; unknown or ambiguous outcomes remain unresolved and are never inferred.
   - Next: validate dispatch and reconciliation against an isolated Metasploit lab, then implement independent exploit-outcome validation before adding session management.

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

## Immediate next milestone: isolated-lab validation and independent outcome verification

The dispatcher and framework reconciler are implemented and covered by fake-RPC tests, but neither has been exercised against a live isolated Metasploit lab. Validate the supported RHOSTS/RPORT profile against a deliberately vulnerable lab target, verify job-list and UUID-result behavior on the connected Metasploit version, and capture the resulting evidence. Then add independent outcome checks so a completed framework run can be classified as successful, unsuccessful, or inconclusive based on target-side evidence. Do not equate a completed module job with exploit success. Session records and post-exploitation actions remain a later, separately authorized milestone.
