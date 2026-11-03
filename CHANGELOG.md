# Changelog

All notable changes to MSFAuto are documented here.

## Unreleased

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
