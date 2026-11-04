## Unreleased

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

