# Changelog

All notable changes to MSFAuto are documented here.

## Unreleased
\n### Durable exploit execution lifecycle
- Added durable execution records and append-only transition events, separate from passive-check jobs.
- Added strict lifecycle states for preparation, dispatch intent, uncertain dispatch, running, cancellation, and terminal outcomes.
- Revalidate persisted opportunity, accepted review, authorization, and current workspace scope before dispatch intent is recorded.
- Added recovery that marks interrupted dispatches uncertain, explicit operator reconciliation, optimistic concurrent-transition protection, and terminal-state enforcement.
- Enforced one execution attempt per authorization with a database uniqueness constraint, preventing approval reuse for duplicate dispatch attempts.
- No exploit RPC dispatch was added; uncertain attempts are never automatically retried.


### Exploit review and action-specific authorization
- Added explicit accepted/rejected/deferred human review decisions bound to the exact workspace, opportunity, exploit module, target, service, and observed version.
- Added short-lived, workspace-scoped exploit authorizations that require an accepted review, explicit approver/rationale, dangerous-actions profile, and in-scope target/port.
- Authorization validation fails closed on changed opportunity identity, changed scope snapshot, expiry, or revocation; default lifetime is 15 minutes and maximum lifetime is eight hours.
- Added persistent review history, authorization storage, and revocation support. No exploit dispatch capability was added.
- Added tests for review gating, exact target binding, scope changes, out-of-scope rejection, safe-profile denial, expiry, persistence, and revocation.
- GitHub Actions run #337 passed on Python 3.10, 3.12, and 3.14: 124 tests passed (plus 2 subtests); Ruff passed on all versions.


### Persistent Metasploit exploit catalog synchronization
- Added workspace-scoped SQLite persistence for imported exploit definitions, source metadata, synchronization timestamps, and active/inactive source state.
- Added a synchronization helper and integrated active synchronized definitions into assessment runs alongside curated JSON entries.
- Framework metadata refreshes preserve operator-controlled product aliases, exact affected versions, and advisory mappings; explicit mapping updates use a separate storage method.
- A non-empty refresh deactivates removed entries from the refreshed source, while an empty refresh is a no-op.
- Added tests for persistence, mapping preservation and explicit updates, source refresh behavior, empty refreshes, and workflow integration.

### Metasploit exploit catalog ingestion
- Added the dedicated `module.exploits` RPC method and a metadata importer that fetches only explicitly mapped exploit modules.
- Normalized framework rank, description, platform, architecture, target, required-option, reference, and check-support metadata into first-class exploit definitions.
- Added mandatory explicit product aliases plus exact affected versions or advisory IDs; the importer does not infer applicability from module names or descriptions.
- Added tests for RPC response validation, mapping validation, metadata normalization, module filtering, missing modules, and module-type rejection.

### Exploit intelligence foundation
- Added a first-class `msfauto/exploitation/` package with source-attributed exploit definitions and exact applicability matching against open service product aliases, affected versions, and explicitly linked vulnerability candidate IDs.
- Added JSON catalog loading through `MSFAUTO_EXPLOIT_CATALOG`, stable opportunity identifiers, workspace-scoped opportunity persistence, and an `exploit_intelligence` assessment workflow stage.
- Persisted opportunities remain `identified`; matching cannot approve or dispatch modules. No exploit module execution, payload handling, or post-exploitation behavior was added. Version-range and fuzzy product matching remain unimplemented.
- Added tests for catalog validation, exact and negative matches, advisory-linked matches, persistence round-trip, approval-state guardrails, and end-to-end assessment workflow integration. GitHub Actions run #293 passed on Python 3.10, 3.12, and 3.14 (103 tests; 2 subtests; Ruff passed).


### OSV vulnerability intelligence ingestion
- Added an OSV.dev API client for package name + ecosystem + version queries using the documented `/v1/query` endpoint.
- Normalized returned advisory IDs, CVE/GHSA aliases, severity, references, affected version lists, and original OSV range metadata.
- Added explicit product aliases for mapping known OS package names to service fingerprints; package ecosystem identity is never guessed from a service banner.
- Added persistent advisory registry storage and tests for request payloads, package filtering, provider failures, normalization, persistence, and OSV-to-candidate matching. CI run #259 passed on Python 3.10, 3.12, and 3.14 (92 tests; 2 subtests; Ruff passed).


### Vulnerability assessment foundation
- Added normalized advisory and vulnerability-candidate records with source attribution, affected versions, prerequisites, references, and evidence requirements.
- Added strict product/CPE identity and exact version matching against discovered open services, with exact version matches represented as candidates and missing/ambiguous versions retained as unverified.
- Persisted workspace-scoped candidates with confidence, rationale, and evidence provenance. A service banner or version match cannot mark a vulnerability confirmed.
- Added tests for exact and ambiguous matches, missing versions, unrelated products, closed services, provenance, confirmation guardrails, and persistence. CI run #244 passed on Python 3.10, 3.12, and 3.14 (87 tests; 2 subtests; Ruff passed).


### TLS-only service inspection
- Added a dedicated TLS handshake probe for TLS-wrapped non-HTTP services; it records negotiated protocol, cipher and strength, certificate fingerprint and size, ALPN selection, compression, and session reuse.
- TLS inspection sends no application-layer request and does not treat an untrusted certificate as a failed handshake; trust validation is not part of this metadata-only probe.
- Corrected service classification so TLS-wrapped services such as LDAPS are not automatically sent through the HTTP adapter.
- Added a local TLS server fixture and tests for certificate capture and protocol dispatch. CI run #231 passed on Python 3.10, 3.12, and 3.14 (79 tests; Ruff passed).


### Verification
- GitHub Actions run #217 passed on Python 3.10, 3.12, and 3.14: 77 tests passed and Ruff passed.

### SMB2 service enumeration
- Added a bounded, unauthenticated SMB2 NEGOTIATE probe for discovered open TCP/445 or explicitly fingerprinted SMB services.
- Captures the negotiated dialect, security mode, server GUID, capabilities, and negotiated message-size limits without attempting authentication or file operations.
- Added a local fake SMB2 server test. Verified in CI run #217.

### FTP service enumeration
- Added a bounded FTP adapter that records the server greeting and supported FEAT capabilities as structured service observations.
- FTP enumeration is limited to discovered open TCP services fingerprinted as FTP or using conventional FTP ports, and inherits saved scope, timeout, and worker limits.
- Added a local fake FTP server test for greeting and feature parsing. Verified in CI run #217.


### Service fingerprinting foundation
- Enabled Nmap service/version detection with -sV --version-light for discovered in-scope ports.
- Expanded normalized service records with probe method, confidence, extra information, tunnel metadata, CPE identifiers, source, and observation timestamp.
- Added backward-compatible SQLite column migrations for existing service records.
- Added parser, confidence validation, persistence round-trip, legacy-schema migration, and scanner-command tests.


### Product direction correction
- Reframed MSFAuto around its core purpose: reconnaissance, service enumeration, vulnerability assessment, authorized exploitation, post-exploitation assessment, validation, and analysis.
- Promoted exploitation to a first-class assessment capability with its own catalog, matching, authorization, dispatch, and outcome lifecycle; it is not treated as a generic safe check.
- Clarified that Metasploit is one integration/engine within the platform, not the platform's entire identity.
- Corrected the intended primary interface to a graphical application. The current Textual screen is documented as a prototype, not the final UI direction.
- Updated the roadmap, README, architecture, assessment workflow, and migration plan to align future work with assessment capability rather than expanding safety/reporting scaffolding or the TUI.

### Assessment run provenance
- Added immutable, run-specific SQLite snapshots of generated assessment plans while preserving the existing workspace-level latest-plan API.
- Validated that a snapshot belongs to an existing assessment run in the same workspace.
- Added workflow tests for run-plan retrieval and rejection of missing or cross-workspace run references.

### Assessment workflow audit
- Audited the current application-service, orchestrator, CLI, storage, and reporting boundaries.
- Documented that approval, safe-check execution, evidence, findings, and reporting remain separate from the discovery-and-planning run.
- Recorded missing run-level provenance and interruption-recovery safeguards as prerequisites to end-to-end orchestration.

### Verification and handoff
- Recorded the clean-clone recovery state and the previously user-reported result of 66 passing tests.
- GitHub Actions run #180 passed tests and Ruff on Python 3.10, 3.12, and 3.14 for commit `54ec73b48653d81957c79ea068fe7be315e9df50`.
- The user should pull the latest documentation changes and run local tests; this documentation-only update has not been locally verified in the user's environment.
