### Latest implementation milestone: enriched protocol observations

- TLS handshakes now retain decoded X.509 subject, issuer, common name, SAN entries, validity bounds/current validity, serial number, and signature algorithm/hash alongside existing protocol/cipher/fingerprint metadata. Parsing certificate metadata does not imply trust-chain or hostname validation.
- HTTP observations expose status, bounded headers, redirect destination (without following redirects), and the existing bounded HTML/application technology fingerprint.
- SMTP observations already capture greeting, EHLO capabilities, STARTTLS, and advertised AUTH mechanisms; FTP observations capture greeting and FEAT capabilities. These remain non-authenticating, non-mail-sending probes.
- TLS and HTTP failures now include bounded stage labels to distinguish connect, handshake, request/response, and application-body failures.
- Added `cryptography` as the X.509 parsing dependency and regression tests for certificate fields, redirects, and HTTP response-stage timeouts.
- [x] Surface concise protocol-specific summaries in the numbered observation detail view, retaining the complete raw attributes panel.
- [x] Show TLS/X.509 identity and validity metadata, HTTP response/redirect headers, HTTP application title/technology/assets, SMTP greeting/EHLO/STARTTLS/AUTH capabilities, FTP greeting/FEAT capabilities, SSH banner, SMB2 negotiation details, and failure stage/type/detail.
- [x] Make the exploit-opportunity rationale expose the linked vulnerability-candidate IDs and explain that those candidates retain service-observation evidence references.
- [ ] Next: add richer advisory/exploit source synchronization and explicit evidence-to-module applicability mappings; do not infer vulnerability or exploitability from protocol metadata alone. Certificate metadata alone is not trust validation.

### Latest implementation milestone: numbered service-observation inspection

- Discovery-mode `observations` and `observations list` display a numbered list of stored observations and prompt for a row number; selecting a row opens its full attributes and metadata.
- `observations host <ip>` provides the same numbered selection flow filtered to one target.
- `observations show <number>` opens a row directly; exact IDs and unambiguous ID prefixes remain supported for scripted or precise lookup.
- Inspection remains read-only, workspace-scoped, and performs no network probes or inventory changes. Empty input cancels selection; invalid and out-of-range choices are rejected.
- Next: use these records to improve service-to-vulnerability and exploit-catalog correlation while keeping protocol observations as supporting evidence only.

### Latest implementation milestone: phase-specific FTP and SMTP diagnostics

- FTP and SMTP adapters now separate TCP connection establishment from the protocol greeting read, so failures identify whether the socket connection or server greeting timed out.
- FTP FEAT and SMTP EHLO failures are separately tagged as protocol stages; exception class and bounded detail remain available.
- The adapters retain the same timeout budget and make no automatic retries. No timeout policy changes are made based on one target's behavior.
- Added local fixture tests that deliberately withhold FTP/SMTP greetings and assert the recorded failure stage.

### Latest implementation milestone: open-port inventory and hostname-aware TLS enumeration

- Nmap XML import now stores only ports whose reported state is open. Closed and filtered ports remain available in the raw scan XML and immutable scan history, but are excluded from the current exposed-service inventory and protocol enumeration.
- TLS and HTTPS probes continue connecting directly to the discovered target IP while using the host's discovered DNS name as TLS SNI. This supports virtual-hosted TLS endpoints without resolving the target hostname to a potentially different address.
- FTP, SMTP, HTTP(S), SSH, and TLS adapter failures now retain bounded exception messages as well as exception classes, improving the distinction between connection timeouts, handshake failures, and protocol-level errors. Unexpected adapter failures use the same bounded diagnostic format.
- Added parser coverage for closed/filtered port exclusion and TLS SNI coverage for the direct TLS adapter and hostname forwarding.
- Next validation: pull main, run the affected workspace discovery again, and inspect the newly detailed per-service errors. A failed protocol handshake remains an enumeration failure, not proof that the port is closed.

### Latest implementation milestone: service enumeration failure diagnostics

- Service adapter failures now persist a bounded exception type and diagnostic message rather than only the exception class, making connection refusals, timeouts, TLS negotiation errors, and protocol rejections distinguishable.
- Assessment progress emits a per-endpoint warning for failed or partial observations and reports all three status counts.
- Diagnostic text is whitespace-normalized and capped at 160 characters. Enumeration remains bounded and scope-enforced; no retry or protocol downgrade is introduced.
- Added regression coverage for bounded error details. Re-run the affected workspace assessment to obtain the actual causes of its earlier failed observations.

### Latest implementation milestone: root-level workspace onboarding

- Added `workspace create` to root-console help so a new workspace can be created without first entering workspace mode.
- Creation prompts for a workspace name, one IP address or CIDR, and optional allowed ports; the target is parsed and validated before it is saved.
- A single IP address receives one bounded ICMP ping attempt. CIDR ranges are not pinged. No ping reply, timeout, or missing ping utility does not invalidate a syntactically valid target.
- Existing workspace names are rejected rather than silently overwritten. On success, the new workspace is saved and becomes the active workspace; its scope/profile context is displayed.
- Added tests for successful onboarding, non-responsive hosts, invalid targets, duplicate names, and CIDR ping behavior. CI verification pending.

### Latest implementation milestone: SMTP service intelligence and vulnerability evidence correlation

- Added a bounded SMTP adapter for in-scope open TCP services identified as SMTP or on conventional ports 25/587. It records the greeting, EHLO response, advertised ESMTP capabilities, STARTTLS availability, and advertised AUTH mechanisms.
- The adapter does not authenticate, negotiate credentials, send mail, or automatically upgrade to STARTTLS. SMTPS on port 465 remains in the TLS-handshake path.
- Wired persisted service observations into OSV vulnerability matching. Candidates now retain completed/partial observation IDs and identify correlated protocol context in their rationale.
- Protocol observations remain supporting evidence only: they do not alter exact product/version matching, raise confidence, or turn a candidate into a confirmed vulnerability.
- Added local SMTP fixture coverage and regression tests for observation-to-candidate correlation. CI caught and drove fixes for the SMTP fixture's CRLF framing and one Ruff import-order issue. The corrected commit passes the full test suite on Python 3.10 (192 tests plus 5 subtests); cross-version CI is running.

### Latest implementation milestone: operation modes and host-level discovery diffs

- Split the persistent console into Metasploit-style operation modes: `discovery`, `exploit`, `analysis`, and `workspace`.
- Root prompt now exposes only mode navigation, mode listing, help, and exit. `use <mode>` enters a mode, `back` returns to root, and the prompt reflects the active mode.
- Help and command completion are mode-aware. Short commands in a mode resolve to the existing full command handlers; the assessment, persistence, and exploit lifecycle services were not duplicated.
- Discovery snapshot comparison now reports host additions, host removals, and host identity/state changes (address, hostname, up/down state), alongside existing service-level additions, removals, and fingerprint changes.
- Added regression tests for mode command routing and host-level change detection. All comparisons remain bound to completed snapshots in the active workspace.
- GitHub Actions run #610 passed on Python 3.10, 3.12, and 3.14: 190 tests passed plus 5 subtests; Ruff passed on all three versions.

### Nmap scan history and result provenance

- Every interactive assessment scan now writes XML to a unique workspace-scoped artifact path instead of overwriting the previous scan.
- Discovery records have stable scan IDs and retain scanner, exact command arguments, output path, status, start/finish timestamps, and errors.
- SQLite stores an immutable normalized host/service snapshot for each completed scan and XML import, while the existing workspace host/service tables continue to represent the latest observations.
- Added `discovery history` and `discovery compare <older-scan-id> <newer-scan-id>` commands. Comparison reports added, removed, and changed service fingerprints and rejects cross-workspace comparisons.
- Added tests for scan history ordering, service additions/removals/version changes, and workspace isolation.
- Existing databases receive additive migrations; legacy scan records remain visible, but cannot be compared unless a normalized snapshot exists.
- GitHub Actions run #598 passed on Python 3.10, 3.12, and 3.14: 187 tests passed plus 5 subtests; Ruff passed on all three versions.

### Latest milestone: command-driven approval and exploit authorization

- Connected `checks approve <recommendation#> <approver> [rationale]` to the existing stable recommendation identity and persisted approval records.
- Changed interactive `checks run` to consume only matching persisted approvals; unapproved, rejected, or mismatched recommendations are skipped. The one-shot CLI retains its interactive approval flow.
- Connected `exploits review <id> <accepted|rejected|deferred> <reviewer> <rationale>` to the exact-opportunity review domain and SQLite history.
- Connected `exploits authorize <id> <approver> <rationale>` to the accepted latest review, dangerous-actions profile, current target/port scope, and expiring authorization record.
- These commands create review/authorization records only. Exploit dispatch remains a separate prepared-execution workflow and is not triggered by authorization.
- CI verified after the console redesign: Python 3.10, 3.12, and 3.14 passed.

# MSFAuto Roadmap

### Metasploit RPC automatic startup and lifecycle

- The interactive console now checks the configured RPC endpoint on startup.
- For a local loopback endpoint with no listener, MSFAuto starts `msfrpcd` in the foreground as a supervised child process, binds it to loopback, and waits up to 30 seconds for the RPC socket.
- If a local service is already listening, MSFAuto reuses it and never starts a duplicate. Remote RPC endpoints are never started locally.
- When starting its own daemon without supplied credentials, MSFAuto generates an ephemeral username/password pair. The password is passed through the supported `MSF_RPC_USER`/`MSF_RPC_PASS` child environment variables, not process arguments.
- On normal console exit, MSFAuto terminates only the daemon process it started; external services are left untouched.
- Startup failures are reported while leaving non-Metasploit console commands available.
- Added lifecycle tests for automatic startup, credential handling, existing-service reuse, remote-endpoint restrictions, and owned-process shutdown.
- GitHub Actions run #584 passed on Python 3.10, 3.12, and 3.14: 185 tests passed plus 5 subtests; Ruff passed on all three versions.
- Compatibility note: automatic credential injection requires an msfrpcd build that supports `MSF_RPC_USER` and `MSF_RPC_PASS`; otherwise startup diagnostics identify the daemon failure.


### Latest implementation milestone: live Metasploit exploit inventory in the console

- Corrected the empty-list confusion by separating the live framework module inventory from target-matched exploit opportunities.
- `exploits list [filter]` now calls Metasploit RPC `module.exploits` and lists available exploit module references, with an optional case-insensitive substring filter.
- `exploits opportunities` remains the workspace-scoped list of exact-match applicability leads produced from explicitly mapped catalog entries and discovered service/vulnerability data.
- The framework inventory is metadata discovery only; it does not imply target applicability, approval, or dispatch.
- Added console tests for live inventory listing, filtering, and keeping opportunity retrieval workspace-scoped.
- Next: improve catalog enrichment and operator mapping workflows so module inventory can be converted into reliable target applicability intelligence without guessing product/version identity.


- Console startup now has a standard-library input fallback when `prompt-toolkit` is unavailable; install declared dependencies to restore completion and persistent command history.

### Latest implementation milestone: exact-match module verification registry

- Added a module verifier registry keyed by the exact persisted Metasploit module name; no fuzzy matching or inferred verifier selection is allowed.
- Registered verifiers receive the persisted execution and an explicit bounded timeout budget (0.1–30 seconds) and must return a structured verdict, method, rationale, and target-evidence IDs.
- Verifier timeouts and modules without a registered verifier create an append-only inconclusive target assessment. Unsupported modules send no probe.
- All conclusive results still pass through ExploitOutcomeValidator, which enforces terminal execution state, exact workspace/target evidence binding, and rejection of framework-originated evidence.
- Added tests for exact module selection, evidence-backed results, unsupported modules, timeout handling, and timeout bounds.
- No built-in module verifier is registered yet: a concrete verifier must be based on a documented, non-destructive target-side indicator for a specific module. The registry foundation is complete; first real module-specific verifier remains the next implementation task.

## Product definition

**MSFAuto is a web-first, Metasploit-powered penetration-testing automation platform for explicitly authorized assessments.**

Its primary job is to guide an operator from a target to an evidence-backed understanding of its web attack surface and the next relevant assessment actions. It should not stop after reporting open ports or require the operator to manually assemble every scanner and module invocation.

Metasploit is the primary security-testing and exploitation engine. MSFAuto makes the framework's existing auxiliary modules, check capabilities, exploit metadata, jobs, and supported session operations easier to discover, configure, sequence, and interpret. MSFAuto provides the higher-level target model, orchestration, evidence-driven decision logic, correlation, operator interface, and authorization lifecycle. Reimplement framework capabilities only when a clear gap requires it.

Web applications are the primary assessment domain. Network discovery and supporting-service investigation reveal and contextualize the web application and its infrastructure. Broad port scanning is optional, not the default experience.

The product should behave like an assessment operator: discover the surface, investigate each relevant service, understand the evidence, select the next useful step, and present a defensible path for human review. Automation must not confuse a banner with a vulnerability, a module match with exploitability, or framework completion with verified target impact.

## Product and interface direction

- MSFAuto remains a **terminal-first application** with a persistent Metasploit-style command prompt.
- Keep startup minimal and make the common workflow discoverable through `help`.
- Design the primary workflow around a target and one orchestrated assessment run, not unrelated scanner commands.
- Web application assessment is the default focus. Important web ports and common supporting services belong in the default focused profile; full TCP scanning is explicitly opt-in.
- Treat Nmap as a replaceable discovery provider. Use it for bounded host/port/service discovery where appropriate, but do not make Nmap-specific concepts the centre of the user experience.
- Prefer Metasploit's built-in auxiliary, check, exploit metadata, job, and session capabilities when they fit. MSFAuto wraps them with target-aware selection, bounded defaults, structured evidence, progress, and understandable results.
- Keep raw framework access available for advanced operators while presenting guided workflows to ordinary users.
- The planned web-target model must support an origin (scheme, hostname, port), resolved-address constraints, virtual-host/SNI context, and explicit host/path scope. The current MVP accepts IP/CIDR only; URL/hostname target support is future work.
- Use Rich and prompt_toolkit for terminal rendering, input, completion, and history. Keep assessment services and integrations independent of the shell.

## Core assessment capabilities

Priority order:

1. **Web reconnaissance and application mapping** — identify HTTP/HTTPS endpoints, redirects, virtual hosts, TLS identity, server/framework/CMS indicators, accessible resources, and application entry points. Support non-standard ports and preserve origin/hostname context.
2. **Evidence-driven investigation** — investigate each discovered web service in sequence. Select checks from observed technology and behavior; record why an action was selected, expected evidence, results, and remaining unknowns.
3. **Metasploit-native assessment** — discover relevant built-in auxiliary and exploit module metadata, inspect options and check support, and invoke suitable bounded checks through supported RPC operations. Avoid duplicating maintained framework probes.
4. **Vulnerability intelligence** — correlate application/service evidence with advisories and module applicability requirements. Keep identity, version, affected-range, and prerequisite evidence explicit; never infer a vulnerability from a port or banner alone.
5. **Exploit opportunity and attack-path analysis** — explain candidate entry points, prerequisites, evidence quality, missing information, and plausible next steps. An opportunity is a lead, not proof of exploitability.
6. **Controlled exploitation and validation** — retain review, scope, authorization, single-use, and uncertain-dispatch controls. Independently verify target outcomes; framework job completion is not proof of compromise.
7. **Supporting network assessment** — investigate important remote-access, mail, file-sharing, directory, database, and infrastructure services when relevant. Full all-port scanning remains optional.
8. **Post-exploitation and session management** — add separately authorized, bounded session assessment only after core web investigation and validation are reliable.

Supporting capabilities: durable run history, cancellation/recovery, workspace isolation, evidence provenance/integrity, findings review, reporting, and operator-friendly terminal feedback.

### Latest implementation milestone: exploit lifecycle CI correction and cancellation recovery tests
- Inspected the red CI checks on run #529. All three Python versions failed the same pre-existing reconciliation test because it supplied a job ID without the UUID now required for a `running` record.
- Updated that test to provide and assert both framework references; this preserves the stricter lifecycle invariant rather than weakening the implementation.
- Added lifecycle regression tests for running → cancelling → cancelled and for recovery of a process interrupted while cancellation was pending. Interrupted cancellation remains uncertain and retains its Metasploit job ID/UUID for operator reconciliation.
- GitHub Actions run #535 passed on Python 3.10, 3.12, and 3.14: 170 tests passed plus 5 subtests; Ruff passed on all versions.

### Latest implementation milestone: independent outcome verification regression coverage
- Added tests proving target evidence must match both the execution workspace and exact target.
- Added append-only history coverage for multiple independent assessments of one execution.
- Asserted that recording target-side verdicts does not mutate the Metasploit framework execution state.
- GitHub Actions run #535 passed on Python 3.10, 3.12, and 3.14: 170 tests passed plus 5 subtests; Ruff passed on all versions.

### Latest implementation milestone: command-console target outcome assessment
- Exposed the existing append-only `ExploitOutcomeValidator` through `exploits outcome record` and `exploits outcome list`.
- Recording requires an explicit verdict, independent verifier, method, actor, rationale, and evidence IDs for conclusive verdicts. Use `-` only when recording an inconclusive assessment without evidence.
- Commands resolve the execution in the active workspace before reading or writing assessments.
- Outcome assessments remain separate from Metasploit framework state; the console does not infer exploit success or run generic target probes.
- Added command-level tests for recording, listing, and cross-workspace rejection.
- The latest verified baseline before this console addition is CI run #535 (170 tests, 5 subtests; Ruff passed on Python 3.10, 3.12, and 3.14). The new console change still requires CI verification.

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

1. **Web-first target and scope model**
   - [ ] Extend the current IP/CIDR-only target model to accept an explicitly scoped web origin (scheme, hostname, port), with resolved-IP and DNS-rebinding protections.
   - [ ] Preserve Host header, TLS SNI, redirect, and virtual-host context without silently expanding scope.
   - [ ] Reject out-of-scope redirect destinations and keep workspace authorization authoritative.

2. **Focused discovery and service routing**
   - [x] Provide quick, standard (default), and full TCP discovery profiles; broad all-port discovery is opt-in.
   - [x] Keep explicit workspace port allowlists authoritative.
   - [x] Run discovered-service enumeration sequentially in the full assessment.
   - [x] Rebalance the standard profile to prioritize web ports and high-value supporting services; keep the full scan opt-in.
   - [ ] Route services from observed protocol/tunnel evidence, not port number alone.
   - [ ] Retain Nmap behind a discovery-provider interface; evaluate Metasploit-native discovery/auxiliary capabilities where equivalent.
   - [ ] Preserve unsupported-service records with an explicit manual-inspection next action.

3. **Web reconnaissance and application investigation**
   - [x] Capture bounded HTTP/HTTPS response metadata, redirects, TLS certificate metadata, and basic HTML technology indicators.
   - [ ] Add bounded route/resource discovery with request budgets, same-origin defaults, redirect scope checks, and opt-in for broader crawling.
   - [ ] Add virtual-host and application-origin investigation using authorized hostnames.
   - [ ] Add technology-specific investigation packs for common web servers, frameworks, CMS platforms, and application stacks.
   - [ ] Add authentication-surface mapping without credential guessing or brute force by default.
   - [ ] Store request/response observations with source, timing, status, truncation, and run ID.

4. **Metasploit-native module intelligence and execution**
   - [x] Read live Metasploit module inventories and inspect module metadata/options.
   - [x] Synchronize explicitly mapped exploit metadata into the workspace catalog.
   - [ ] Build a target-aware recommender across relevant auxiliary and exploit modules using module metadata, check support, service evidence, and explicit mappings.
   - [ ] Make suitable auxiliary/check modules guided investigation steps with bounded options and structured results.
   - [ ] Explain why a module was selected and what it can/cannot establish.
   - [ ] Surface unsupported module requirements for manual review rather than silently omitting candidates.
   - [x] Preserve explicit review, authorization, one-shot dispatch, job reconciliation, and independent outcome records.

5. **Evidence-driven decision and vulnerability engine**
   - [x] Define the initial read-only investigation-step contract with observed evidence, next action, rationale, expected evidence, and explicit no-dispatch/no-retry behavior.
   - [ ] Extend the contract with module prerequisites, timeout/request budgets, risk class, and stop conditions.
   - [x] Select initial next actions from service fingerprints and unresolved evidence gaps; avoid blind module sweeps.
   - [ ] Expand selection using live Metasploit auxiliary/check module metadata and web technology packs.
   - [ ] Add bounded, evidence-producing web vulnerability checks before intrusive validation.
   - [ ] Correlate advisory sources and framework metadata without treating a match as confirmation.
   - [ ] Present per-service states READY, NEEDS_REVIEW, INSUFFICIENT, UNSUPPORTED, and COMPLETED with rationale.
   - [ ] Preserve manual inspection and operator override at each decision point.

6. **Unified assessment workflow and operator experience**
   - [x] Provide `discover run` as an end-to-end discovery/enumeration/assessment entry point.
   - [ ] Evolve the primary command into target-centric `assess web` / `assess run` after URL/origin scope exists; retain `discover run` for discovery-only and network workflows.
   - [ ] Stream progress per target, port, service, and investigation action; isolate failures and continue where safe.
   - [ ] Show prioritized findings, evidence gaps, next actions, and manual-inspection references.
   - [ ] Ensure every child action and observation belongs to one durable assessment run.

7. **Validation, execution, and later capabilities**
   - [ ] Validate supported Metasploit dispatch/reconciliation in an isolated lab; never use public third-party systems for exploit testing.
   - [ ] Add narrowly scoped, module-specific outcome verifiers with documented non-destructive indicators.
   - [ ] Add separately authorized session inventory and bounded post-exploitation assessment.
   - [ ] Expand non-web protocol coverage after the web-first workflow is useful end-to-end.

## Latest implementation milestone: protocol confirmation for unknown TCP services
- Nmap may return an unrecognized service label even when the endpoint speaks HTTP, as observed with the local OWASP Juice Shop instance on TCP/3000.
- Added a bounded HTTP HEAD confirmation attempt for otherwise-unclassified open TCP services that are not already routed to a known protocol adapter.
- Unknown services are classified as HTTP only when the HTTP client parses a valid HTTP response. Non-HTTP responses are ignored rather than stored as failed HTTP observations.
- Structured observations record the active detection method and retain the original Nmap service name, product, version, probe method, confidence, and tunnel metadata.
- Added local-server tests for successful unknown-port HTTP detection and rejection of non-HTTP responses. The user confirmed a live Juice Shop discovery run produced one completed HTTP observation; this newer application-fingerprinting milestone still requires a live re-test and CI verification.

## Assessment-first workflow milestone (2026-11-04)

- [x] Add prioritized TCP discovery profiles: quick, standard (default), and full.
- [x] Keep saved workspace port allowlists authoritative; profiles cannot widen scope.
- [x] Add the discover run alias and profile selection to the interactive shell and one-shot CLI.
- [x] Run service enumeration sequentially during the full assessment.
- [ ] Add protocol adapters for the remaining prioritized service families.
- [x] Persist explicit unsupported/manual-review records for open services without an adapter.
- [ ] Add a per-port next-action view connecting collected evidence to analyst review.
- [ ] Validate profile coverage and sequential execution in the authorized lab.

## Immediate next milestone: establish the web-first assessment vertical

1. Validate bounded HTTP application fingerprinting against the local Juice Shop lab and capture actual fields, limitations, and run provenance.
2. Review the standard TCP profile and make web ports dominant while retaining high-value supporting services; keep full TCP scanning opt-in.
3. Inspect Metasploit RPC module inventory and metadata APIs to design a recommender for relevant auxiliary/check modules based on observed web technologies and services. Do not invoke arbitrary modules or perform broad module sweeps.
4. Define the investigation-plan/result contract before adding more probes: selection rationale, prerequisites, expected evidence, bounded request/time budget, result, confidence, and next decision.
5. After validating the current IP/CIDR workflow, design URL/origin target support with DNS pinning, Host/SNI preservation, redirect boundaries, and explicit path scope.

The current implementation accepts IP/CIDR targets, has basic HTTP/HTTPS and application fingerprint observations, and can read Metasploit module metadata. It does not yet provide a complete web crawler, URL-target workflow, technology-specific investigation engine, or broad automatic Metasploit module selection. Keep those gaps explicit.

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


## Latest implementation milestone: reliable Nmap host discovery and current inventory

- Added `-Pn` to the bounded Nmap invocation so targets are scanned even when they do not respond to Nmap's host-discovery probes. The explicit workspace target and port scope remain enforced.
- Changed the workspace's current host/service inventory to replacement semantics on a completed discovery import. Services and hosts absent from the latest result are removed instead of remaining as stale records.
- Historical discovery snapshots remain separate and available for history and comparison.
- Added regression coverage for the `-Pn` command option and removal of stale services/hosts, including an empty completed result.
- Next validation: run discovery against the user's authorized workspace and compare imported services with the same Nmap command using `-Pn`.

## Observation history milestone (2026-11-04)

- [x] Persist the originating discovery scan ID on each newly collected service observation.
- [x] Default `observations` to the latest run; add `observations history`, `observations run <id>`, and `observations all`.
- [x] Keep pre-migration records accessible as legacy/unassigned observations; retain all historical data.
- [ ] Add dedicated shell regression coverage for latest-run, run-specific, and archive views; validate against a workspace with multiple live scans.
- [x] Add elapsed-time and timeout-budget metadata plus connection/timeout/protocol-response failure classification to service observations; expose per-protocol timeout overrides in the enumeration API.


## Assessment-first service investigation milestone (2026-11-04)

- [x] Keep `discover run` as the primary end-to-end assessment entry point, using the prioritized standard port profile by default and all TCP ports only when explicitly requested.
- [x] Investigate discovered open services sequentially within the same persisted assessment run.
- [x] Preserve unsupported services as explicit manual-review records rather than silently skipping them.
- [x] Add a read-only `investigate [target-ip]` view that maps each service's current evidence, vulnerability candidates, and exploit opportunities to a next action and an evidence state (`READY`, `NEEDS_REVIEW`, or `INSUFFICIENT`).
- [x] Add POP3/POP3S and IMAP/IMAPS greeting/capability enumeration without authentication or mailbox access.
- [x] Run SMTP greeting/EHLO enumeration after implicit TLS negotiation on SMTPS endpoints.
- [x] Clarify that configured timeout values apply to individual socket operations rather than the complete multi-operation probe.
- [ ] Expand protocol adapters for DNS, LDAP, database handshakes, and remote-management services using bounded, unauthenticated identification only.
- [ ] Add richer evidence-to-advisory mappings and curated exploit catalog coverage so service investigations can produce more actionable, evidence-backed vulnerability candidates.
- [ ] Validate the complete sequence against authorized local lab services, including Dovecot POP3/IMAP and implicit-TLS variants.

Exploitation remains a separate, explicitly authorized stage. An assessment run may identify and prioritize possible entry points, but it must not automatically dispatch exploit modules. Each candidate requires human review, action-specific authorization, and independent outcome validation.
