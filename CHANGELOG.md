## Unreleased

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

