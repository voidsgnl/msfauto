## Unreleased

### Added
- Discovery-mode `observations` inspection commands: list stored service observations, filter by host, and show full attributes by observation ID or unique prefix. Inspection is read-only and restricted to the active workspace; it does not initiate probes or modify assessment records.


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

