### Latest milestone: command-driven approval and exploit authorization

- Connected `checks approve <recommendation#> <approver> [rationale]` to the existing stable recommendation identity and persisted approval records.
- Changed interactive `checks run` to consume only matching persisted approvals; unapproved, rejected, or mismatched recommendations are skipped. The one-shot CLI retains its interactive approval flow.
- Connected `exploits review <id> <accepted|rejected|deferred> <reviewer> <rationale>` to the exact-opportunity review domain and SQLite history.
- Connected `exploits authorize <id> <approver> <rationale>` to the accepted latest review, dangerous-actions profile, current target/port scope, and expiring authorization record.
- These commands create review/authorization records only. Exploit dispatch remains a separate prepared-execution workflow and is not triggered by authorization.
- CI verified after the console redesign: Python 3.10, 3.12, and 3.14 passed.

# MSFAuto Roadmap

## Product definition

**MSFAuto is an automated security assessment platform for discovering, enumerating, assessing, exploiting, and validating security weaknesses in explicitly authorized environments.**

Its primary value is the assessment work it can perform and the quality of the technical intelligence it produces. Safety controls, evidence integrity, workflow orchestration, and reporting are essential supporting capabilities; they are not the product's central purpose.

MSFAuto should not become merely a graphical wrapper around Metasploit. Metasploit is an important integration and execution engine within a broader platform that owns discovery, service intelligence, vulnerability assessment, exploit orchestration, result validation, and analysis.

## Product and interface direction

- MSFAuto is a **terminal-only application**. There is no web interface or mouse-driven desktop GUI in the product plan.
- The primary operator experience is a persistent Metasploit-style command console, with Fluxion-inspired terminal aesthetics rather than a menu-driven TUI.
- Startup is intentionally minimal: MSFAuto branding, compact workspace/profile/scope/RPC context, and a persistent `msfauto >` prompt. The command catalogue is displayed only when the operator enters `help`.
- Operators use concise hierarchical commands such as `discovery run`, `scope show`, `plan build`, and `exploits list`; detailed output appears in the terminal and returns to the prompt.
- `dashboard` is optional and explicitly invoked. One-shot CLI flags remain available for automation.
- Use Rich for terminal rendering and prompt_toolkit for editable input, completion, and persistent command history. Keep assessment services, integrations, persistence, and authorization independent of the shell.

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
- Terminal navigation, configuration prompts, technical tables, and live execution feedback.

### Latest implementation milestone: exploit lifecycle CI correction and cancellation recovery tests
- Inspected the red CI checks on run #529. All three Python versions failed the same pre-existing reconciliation test because it supplied a job ID without the UUID now required for a `running` record.
- Updated that test to provide and assert both framework references; this preserves the stricter lifecycle invariant rather than weakening the implementation.
- Added lifecycle regression tests for running → cancelling → cancelled and for recovery of a process interrupted while cancellation was pending. Interrupted cancellation remains uncertain and retains its Metasploit job ID/UUID for operator reconciliation.
- CI for the reconciliation-test correction and the additional cancellation tests is pending; do not treat this milestone as verified until the run is green.

### Latest implementation milestone: independent outcome verification regression coverage
- Added tests proving target evidence must match both the execution workspace and exact target.
- Added append-only history coverage for multiple independent assessments of one execution.
- Asserted that recording target-side verdicts does not mutate the Metasploit framework execution state.
- The cancellation/recovery test suite and this additional verification coverage are being checked through CI.

## Current implementation baseline

- [x] Interactive application entry point and workspace onboarding.
- [x] SQLite workspace persistence.
- [x] Explicit IP/CIDR scope and optional port allowlists.
- [x] Scope-enforced Nmap XML import and normalized service storage.
- [x] Bounded HTTP/HTTPS and SSH service enumeration with append-only structured observations.
- [x] Bounded HTTP confirmation probes for unrecognized open TCP services, preserving the original Nmap fingerprint and rejecting non-HTTP responses.
- [x] Bounded HTML application fingerprinting for HTTP services: title, selected metadata, server/runtime headers, common framework/library markers, and referenced assets.
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

### Latest implementation milestone: complete Metasploit running references
- Tightened the execution lifecycle invariant: an execution cannot enter `running` unless both a positive-integer Metasploit job ID and a non-empty UUID are persisted.
- Applied the same validation to normal dispatch acknowledgements and operator reconciliation of uncertain dispatches. Malformed acknowledgements after the one RPC attempt become `dispatch_uncertain`; they are never retried. Invalid or incomplete reconciliation references leave the record uncertain.
- Updated lifecycle regression coverage for missing job IDs, missing UUIDs, malformed job IDs, and malformed dispatch acknowledgements.
- This closes a mismatch where an operator could previously reconcile an uncertain dispatch with only a job ID even though the poller requires both references.

### Latest implementation milestone: live discovery cancellation and exploit console lifecycle
- Replaced the blocking Nmap subprocess call with a bounded `Popen` monitor that captures stderr to a temporary file, enforces the existing timeout, and supports cooperative termination. Cancellation sends terminate, waits up to five seconds, then kills the process if required.
- Added a durable `cancelled` discovery-run result and `WorkflowCancelled` assessment state. The orchestrator checks cancellation at stage boundaries; enumeration and external advisory lookups finish their current bounded operation before cancellation is acknowledged.
- Interactive `discovery run` now passes its task cancellation event into the assessment workflow. Press Ctrl-C while the live task indicator is active to request cancellation; the shell waits for the scanner to stop and records the cancelled run.
- Exposed the existing exploit lifecycle through `exploits prepare`, `exploits executions`, `exploits dispatch`, `exploits poll`, `exploits cancel`, and `exploits reconcile`.
- Dispatch requires a prepared record and an exact `DISPATCH` confirmation, then uses the existing narrow Metasploit TCP dispatcher. No arbitrary module/target/port/options are accepted.
- Polling uses the existing active-job and UUID-specific result reconciler. Cancellation records `cancelling` before requesting `job.stop`; a stop acknowledgement is not treated as terminal completion.
- Uncertain dispatch remains a separate operator-only reconciliation path. A manually reconciled running state must include both the Metasploit job ID and UUID. A confirmed non-dispatch closes the attempt; retry requires a new review and authorization.
- No live exploit was dispatched as part of this implementation. GitHub Actions run #520 passed on Python 3.10, 3.12, and 3.14: 164 tests passed (plus 2 subtests) on each version; Ruff passed on all three.


### Latest implementation milestone: bounded HTTP application fingerprinting
- HTTP enumeration now follows its bounded HEAD confirmation with a GET of the same origin, without following redirects.
- The response body is capped at 64 KiB locally even when a server ignores the Range request; request and socket timeouts remain in force.
- HTML responses produce a separate http_application_response observation with page title, selected metadata, server/runtime header hints, framework/library indicators, referenced assets, and truncation state.
- Technology claims include the marker that supports them and a confidence score. Non-HTML responses do not produce application fingerprints.
- This is passive application identification only: it does not crawl routes, fetch robots.txt/sitemaps, or perform vulnerability checks.
- Added unit coverage for title/meta extraction, React/jQuery and Angular indicators, non-HTML rejection, and bounded-body metadata.

### Latest implementation milestone: Metasploit MessagePack response compatibility
- Diagnosed the live RPC authentication failure against the connected local Metasploit service: authentication succeeded, but the framework encoded response keys and text values as MessagePack binary strings.
- Updated the MessagePack transport to recursively decode valid UTF-8 binary strings in map keys and values before processing responses. Non-UTF-8 binary values remain bytes.
- Error maps are normalized before error extraction, so byte-encoded framework errors retain their useful messages.
- Added regression tests covering byte-encoded authentication tokens, nested module-result data, and RPC error responses.
- Local live read-only integration confirmed authentication, discovery of 2,715 exploit modules, and active-job listing. No exploit was executed.

### Latest implementation milestone: Metasploit job polling and reconciliation
- Added `MetasploitClient.job_list()` to validate and normalize the active framework job map.
- Added `msfauto/execution/reconciliation.py` with `MetasploitExploitReconciler` and a structured `ExploitPollResult`.
- Polling accepts only persisted `running` or `cancelling` records with both job ID and UUID references. Active jobs remain active; absent jobs are checked against the UUID-specific `module.results` endpoint.
- Only recognized framework states (`completed`, `failed`, `cancelled`) transition to terminal lifecycle states. Missing results, unknown statuses, and contradictory running results remain unresolved and do not alter the execution record.
- Framework completion is explicitly recorded as module execution completion, not proof of exploit success or security impact. Uncertain dispatch records remain on the separate operator-reconciliation path.
- Added `msfauto/execution/outcome_validation.py` with append-only, workspace/target-bound target outcome assessments (`confirmed`, `not_confirmed`, `inconclusive`). Conclusive verdicts require linked evidence from the exact target and workspace; Metasploit framework status/evidence is explicitly rejected as an independent verifier.
- The new API records an analyst or module-specific verifier's evidence-backed assessment; it does not invent a generic success indicator or automatically probe targets. No module-specific target verifier is configured yet.
- Added fake-RPC tests for active jobs, completed/failed/cancelled results, missing results, unknown statuses, and rejection of uncertain records.
- GitHub Actions run #406 passed on Python 3.10, 3.12, and 3.14: 146 tests passed (plus 2 subtests); Ruff passed on all versions.

### Latest implementation milestone: independent target outcome assessment records
- Added a separate outcome-assessment domain that preserves framework lifecycle state independently from target-side conclusions.
- Added append-only assessments with explicit verifier, method, actor, rationale, timestamp, and evidence references. Verdicts are `confirmed`, `not_confirmed`, or `inconclusive`.
- Conclusive verdicts require evidence records belonging to the same workspace and exact target as the execution. Framework-only sources cannot serve as independent verification evidence.
- The component deliberately records the conclusion supplied by an analyst or a future module-specific verifier; it does not infer exploit success from Metasploit completion or claim a generic target-side indicator exists.
- Added tests for evidence requirements, exact target/workspace binding, framework-source rejection, inconclusive assessments, and persistence round-trip.

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
   - Extend the Nmap fingerprint baseline with structured service-specific enumeration adapters (HTTP/HTTPS, SSH, FTP, SMB2 negotiation, and TLS-only handshake inspection are implemented; HTTP application fingerprinting is now implemented; route/resource crawling and web-specific vulnerability checks remain).
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

7. **Terminal interface**
   - [x] Replace the menu-driven Textual dashboard as the primary entry point with a persistent Rich + prompt_toolkit command console.
   - [x] Add Fluxion-inspired ASCII branding, compact workspace/profile/scope context, and a clean `msfauto >` prompt.
   - [x] Add grouped `help` output for workspace, scope, discovery, planning, checks, vulnerability, exploit, findings, reporting, and dashboard command families.
   - [x] Add command completion and retain one-shot CLI flags for automation.
   - [x] Connect supported commands to existing workspace, discovery, planning, checks, vulnerability, exploit-intelligence, findings, and reporting services.
   - [ ] Complete guided opportunity-bound exploit review and authorization commands without bypassing the existing lifecycle.
- [x] Persist interactive command history under the MSFAuto home directory (`command_history`).
   - [ ] Add responsive asynchronous task streaming/cancellation.
   - [ ] Add session and post-exploitation commands when those domain services are implemented.

## Latest implementation milestone: protocol confirmation for unknown TCP services
- Nmap may return an unrecognized service label even when the endpoint speaks HTTP, as observed with the local OWASP Juice Shop instance on TCP/3000.
- Added a bounded HTTP HEAD confirmation attempt for otherwise-unclassified open TCP services that are not already routed to a known protocol adapter.
- Unknown services are classified as HTTP only when the HTTP client parses a valid HTTP response. Non-HTTP responses are ignored rather than stored as failed HTTP observations.
- Structured observations record the active detection method and retain the original Nmap service name, product, version, probe method, confidence, and tunnel metadata.
- Added local-server tests for successful unknown-port HTTP detection and rejection of non-HTTP responses. The user confirmed a live Juice Shop discovery run produced one completed HTTP observation; this newer application-fingerprinting milestone still requires a live re-test and CI verification.

## Immediate next milestone: live web-application fingerprint validation

Re-run discovery against the local Juice Shop workspace and inspect the persisted http_application_response observation for title, framework markers, assets, confidence, and truncation state. Then expand generic application fingerprint coverage only where supported by repeatable evidence. Route discovery and web vulnerability checks should be separate bounded milestones. Live isolated-Metasploit dispatch validation remains outstanding and must not be conflated with this web-enumeration work.

## Deferred milestone: live isolated-lab validation and module-specific verifiers

The dispatcher, framework reconciler, and evidence-backed outcome-assessment record are implemented and covered by fake-RPC/unit tests, but the dispatcher and reconciler have not been exercised against a live isolated Metasploit lab. Next, validate the supported RHOSTS/RPORT profile against a deliberately vulnerable lab target and verify job-list plus UUID-result behavior on the connected Metasploit version. Then implement opt-in, module-specific target verifiers with explicit expected indicators and bounded checks; a generic verifier must not guess what success looks like. Session records and post-exploitation actions remain a later, separately authorized milestone.


## Latest implementation milestone: Fluxion-inspired terminal interaction

- Replaced the button-oriented dashboard with a full-screen, keyboard-driven Textual terminal application.
- Added a branded startup header, persistent workspace/scope context, numbered main menu, and dedicated views for target/service inventory, vulnerability candidates, exploit intelligence, execution lifecycle, findings/evidence, workspace scope, and assessment history.
- Added direct number-key navigation, Home/Escape return, refresh, and quit bindings. The interface no longer relies on clickable buttons.
- Added a live activity area and animated running indicator with elapsed time. Progress remains indeterminate unless the workflow supplies a real measurable percentage.
- The interface is terminal-only: no browser UI, HTML preview, or native desktop GUI is part of the product direction.
- Follow-up work: deepen each view with focused detail screens and guided review/configuration prompts, then connect execution controls as the underlying lifecycle APIs mature.


## Latest implementation milestone: Metasploit-style command console (2026-11-04)

- Replaced the primary interactive entry point with a persistent Rich + prompt_toolkit command shell; the former numbered Textual dashboard is no longer launched by default.
- Startup is intentionally minimal: MSFAuto ASCII branding, workspace/profile/scope context, and the `msfauto >` prompt. The full catalogue appears only after `help`.
- Added the requested hierarchical command reference: workspace, scope, discovery, plan, checks, vulnerabilities, exploits, findings, report, dashboard, help, and exit.
- Connected supported commands to existing application/storage services and retained one-shot CLI flags for automation.
- Added command-name completion. Persistent command history is stored under the MSFAuto home directory; fully responsive asynchronous task execution remains follow-up work.
- Some commands are informational/reserved where the underlying guided workflow is not yet connected (notably exploit authorization); no placeholder command may bypass persisted authorization.
- Dependencies now include Rich and prompt_toolkit. The previous Textual implementation remains as legacy code pending cleanup; it is not the primary interface.
- Verification status: the previous CI runs passed 159 tests but exposed an import-order lint issue; the import correction and persistent-history update are committed to main and their CI runs are pending.


## Latest implementation milestone: live command-console task output (2026-11-04)

- Added an in-process task registry with task IDs, lifecycle status, queued progress events, captured results/errors, and a cooperative cancellation primitive for future cancellable operations.
- Connected `discovery run` to the shared `AssessmentApplication` service through the task runner. Stage events now stream into the terminal while the assessment is running, with a Rich activity indicator; the shell remains a persistent `msfauto >` command console.
- Added `tasks list` and `tasks show <id>` for inspecting task state and any queued task output.
- Discovery is currently submitted as non-cancellable because the Nmap adapter still uses a blocking subprocess call. Do not present cancellation as available until the scanner process and orchestrator support safe cooperative cancellation.
- Follow-up: implement cancellable Nmap process management and stage-boundary cancellation, add lifecycle tests for the task runner, then expose the existing persisted exploit execution lifecycle through console commands without weakening review, authorization, scope, single-use dispatch, or uncertain-outcome reconciliation.
