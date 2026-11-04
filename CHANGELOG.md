## Unreleased

### Added
- Added authenticated Metasploit RPC support for creating/destroying temporary consoles, running bounded single-line console commands, invoking scoped `db_nmap`, selecting an isolated Metasploit database workspace, and reading host/service inventory.
- Wired the interactive `run` assessment path to execute `db_nmap` through Metasploit RPC and normalize in-scope host/open-service records from the selected Metasploit database workspace. The legacy standalone Nmap path remains for non-interactive/one-shot use and XML import remains available.
- Validated `db_nmap` inputs as IP/CIDR targets and bounded port specifications; console output is capped and timed, and temporary consoles are destroyed after use.

### Product direction
- Defined the primary objective as target-to-finding-to-prepared-exploit: the operator supplies an authorized IP/network or URL, and MSFAuto autonomously chooses the relevant discovery, investigation, vulnerability-assessment, and Metasploit-correlation steps.
- The new RPC primitives are groundwork. The current assessment orchestrator has not yet switched from its standalone Nmap/XML path to Metasploit database discovery, and URL targets plus the full vulnerability pipeline remain unimplemented.


### Added
- Added root-level `run [--profile quick|standard|full]` as the primary saved-scope assessment entry point, backed by the existing end-to-end assessment orchestrator.
- Added a consolidated assessment results view showing discovered hosts/services, vulnerability candidates, Metasploit exploit opportunities, and persisted findings after a successful run.
- Added root-level `findings` and `findings list|show <id-prefix>` commands so operators can review persisted findings and vulnerability candidates without entering analysis mode.

### Product direction
- Reframed the operator workflow around one automated assessment followed by finding review and operator-selected exploitation. Web crawling, passive/active vulnerability checks, unified finding provenance, and finding-to-module selection remain planned stages; they are not represented as implemented by the current command.


### Added
- Added a bounded, read-only Metasploit auxiliary-module intelligence component for observed web technologies. It filters out exploit modules, retrieves exact module descriptions/options/check support, and never dispatches modules; interactive investigation integration remains in progress.
- Added a deterministic, evidence-driven service investigation planner. It emits one prioritized next step per open service, records expected evidence and rationale in the assessment event stream, and explicitly avoids automatic retries or module dispatch. The interactive `investigate` view now uses the same planner.

### Improved
- Rebalanced the default discovery profiles around a web-first workflow: `quick` now checks a compact set of common web entry points and high-value supporting services; `standard` adds important alternate web, mail, remote-access, directory, and database ports. The `full` profile remains the explicit all-TCP-port option.

### Product direction
- Established MSFAuto as a web-first, Metasploit-powered assessment platform. Metasploit is the primary testing/exploitation engine; MSFAuto provides target-aware orchestration, evidence-driven next-action selection, correlation, and a guided operator experience.
- Prioritized web reconnaissance and application investigation. The default discovery profile is intended to focus on important web and supporting-service ports; full TCP scanning remains opt-in.
- Added a staged roadmap for scoped URL/origin targets, evidence-driven web investigation, Metasploit auxiliary/check module recommendations, and a unified target-centric assessment workflow. These are roadmap items, not claims of implemented functionality.

### Added
- Added read-only POP3 and IMAP service adapters. They collect protocol greetings and CAPA/CAPABILITY data without authentication; implicit TLS services on ports 993 and 995 are negotiated as protocol-aware mail endpoints, with certificate metadata retained. SMTP on implicit-TLS port 465 now receives SMTP greeting/EHLO enumeration after TLS negotiation.
- Added `investigate [target-ip]` to summarize each discovered service's evidence state and evidence-driven next action, including manual-review and missing-intelligence gaps.

### Improved
- Observation details now show POP3/IMAP greeting, capabilities, and TLS metadata; FTP FEAT status is derived from its stored capability list when no explicit status field exists.
- Failure details label the configured timeout accurately as a per-socket-operation timeout, not a whole-probe deadline.

### Added
- Added prioritized TCP discovery profiles: `quick`, `standard` (default), and `full`. The standard profile scans a curated set of commonly exposed remote-access, web, mail, file-sharing, directory, database, and infrastructure ports; full uses Nmap's all-TCP-port selection.
- Added `discover run` as an alias for the end-to-end assessment command, with `--profile quick|standard|full` and `--full` options. The one-shot CLI accepts `--scan-profile`.
- Kept saved workspace port allowlists authoritative: an explicit list is scanned exactly as configured and is never expanded by a profile.

### Improved
- The default assessment now runs service enumeration with one worker so discovered services are investigated sequentially rather than concurrently.
- Every discovered open service without a matching enumeration observation now receives a persisted `unsupported` service-fingerprint record with its Nmap fingerprint and a manual-review next action.
- Assessment discovery uses the standard prioritized TCP profile by default; broad all-port discovery is opt-in.

### Added
- Grouped persisted service observations by their originating discovery run. The default `observations` view shows only the latest run; `observations history` summarizes run groups, `observations run <id>` opens one run, and `observations all` retains access to the complete archive, including legacy unassigned records.
- Persist the Nmap scan ID on every observation generated by an assessment so repeated scans remain distinguishable without deleting prior evidence.

### Improved
- Observation history is newest-first, and host-filtered views default to the latest run; append `all` to inspect that host across the archive.

### Improved
- Observation detail now renders concise protocol-specific summaries for TLS/X.509, HTTP(S), HTTP application fingerprints, SMTP, FTP, SSH, SMB2, and failed probes while preserving the complete raw attribute payload for deeper inspection.
- Added an explicit evidence-correlation note in observation details. Exploit opportunity rationales now show linked vulnerability-candidate IDs and clarify that those candidate records retain service-observation references as supporting evidence, not proof of vulnerability or permission to execute.

### Tests
- Added coverage for TLS certificate summaries and limitations, HTTP application fingerprint fields, and protocol failure-stage diagnostics.


### Improved
- TLS observations now decode X.509 subject, issuer, common name, subject alternative names, validity window, current date validity, serial number, signature algorithm, and signature hash from the presented DER certificate. This is certificate metadata only; trust-chain and hostname validation are not implied.
- HTTP observations now expose redirect status and destination while deliberately not following redirects. HTTP failures record the stage that failed (request, response, or bounded application-body collection); TLS failures distinguish TCP connect, handshake, and metadata stages.
- Existing bounded HTTP header/status and application-technology fingerprints, SMTP greeting/EHLO/STARTTLS/auth capability details, and FTP greeting/FEAT details remain the source for those protocol observations.

### Tests
- Added TLS certificate-decoding assertions, HTTP redirect capture coverage, and a delayed-response fixture verifying HTTP failure-stage diagnostics.

### Added
- Discovery-mode `observations` now presents numbered saved-observation lists, prompts for a row selection, and opens the selected observation's full attributes and metadata. Host-filtered lists support the same flow; `observations show <number|id-prefix>` supports direct lookup. Inspection is read-only, workspace-scoped, and does not initiate probes or modify assessment records.


### Improved
- Split FTP and SMTP TCP connection setup from protocol greeting reads and record explicit failure stages (`tcp_connect`, `ftp_greeting`, `ftp_feat`, `smtp_greeting`, `smtp_ehlo`) for actionable diagnostics. Existing timeout budgets and no-retry behavior are unchanged.

### Tests
- Added delayed-greeting fixtures verifying FTP and SMTP report greeting-stage timeouts.


### Fixed
- Import only Nmap ports explicitly reported as open into the current host/service inventory; closed and filtered ports are excluded from service enumeration while remaining in the raw scan artifact and historical snapshot.
- Use the discovered hostname for TLS SNI in direct TLS and HTTPS probes while pinning the TCP connection to the discovered IP address.
- Preserve bounded exception messages across protocol adapters and unexpected adapter failures to make enumeration diagnostics actionable.

### Tests
- Added regression coverage for closed/filtered port exclusion, TLS SNI selection, and forwarding discovered hostnames into TLS probes.

### Fixed
- Run scoped Nmap discovery with `-Pn` so targets are scanned even when host-discovery probes receive no response.
- Replace the current workspace host/service inventory after a completed scan, removing stale records that were absent from the latest result while retaining historical snapshots.

### Tests
- Added regression coverage for Nmap's `-Pn` option and current-inventory replacement, including empty scan results.


### Added
- Bounded service-enumeration failure diagnostics, including per-endpoint assessment warnings and completed/partial/failed counts.

### Fixed
- Preserve concise exception detail in failed service observations so operators can distinguish network and protocol failure causes.

### Added
- Root-console `workspace create` onboarding with IP/CIDR validation, a single bounded ping check for individual IPs, optional port allowlists, duplicate-name protection, and automatic activation of the newly created workspace.
- SMTP service enumeration for greeting and EHLO/ESMTP capability intelligence, including STARTTLS and advertised authentication mechanisms. No authentication or mail delivery is attempted.
- Service-observation correlation in OSV vulnerability candidates, preserving observation IDs and protocol context as supporting evidence without changing vulnerability status or confidence.

### Fixed
- Corrected SMTP test-server CRLF framing and made the SMTP adapter send QUIT when a connection was established, with a close fallback.
- Applied Ruff's required import ordering for the SMTP adapter.

### Tests
- Added workspace onboarding and reachability coverage.
- Added a local SMTP protocol fixture and coverage for protocol observation propagation into vulnerability candidates.

