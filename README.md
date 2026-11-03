# MSFAuto

**MSFAuto is an automated security assessment platform** for discovering, enumerating, assessing, exploiting, and validating security weaknesses in explicitly authorized environments.

Its primary purpose is to perform useful security assessment work and produce technically meaningful results. Safety controls, evidence integrity, orchestration, and reporting support that purpose; they do not define the product.

MSFAuto is not intended to be merely a graphical wrapper around Metasploit. Metasploit is one integration and execution engine within a broader platform.

## Product capabilities

The intended platform is organized around these core capabilities:

- **Reconnaissance and discovery:** identify in-scope hosts, ports, and exposed services.
- **Service enumeration and intelligence:** fingerprint services, identify versions and technologies, and gather configuration and service-specific context.
- **Vulnerability assessment:** identify candidate weaknesses, assess prerequisites, and prioritize checks using evidence and confidence.
- **Exploitation:** match applicable exploit techniques to target observations, review prerequisites and options, and execute explicitly authorized attempts through supported integrations.
- **Post-exploitation assessment:** perform separately authorized, bounded assessment of achieved access, privilege context, and security impact.
- **Validation:** verify suspected weaknesses and exploit outcomes using evidence.
- **Analysis and correlation:** connect observations and results across assessment stages and produce meaningful findings.

Supporting capabilities include assessment orchestration, authorization and approvals, session/job lifecycle management, evidence integrity, reporting, and a graphical user interface.

## Current implementation status

The repository currently provides foundations for:

- Interactive workspace creation and startup.
- SQLite-backed workspaces, discovery observations, append-only service enumeration observations, workspace-level plans, immutable run-specific plan snapshots, workflow runs, and events.
- Explicit IP/CIDR scope and optional port allowlists.
- Nmap discovery with bounded execution, XML output, and lightweight service/version detection (-sV --version-light).
- Protocol-aware HTTP/HTTPS, SSH, FTP, and SMB2 enumeration with bounded probes and structured observations; HTTPS records negotiated TLS handshake metadata.
- Scope-enforced Nmap XML import and normalized host/service storage, including product/version, probe method/confidence, extra information, tunnel metadata, CPEs, source, and observation time.
- Read-only Metasploit RPC module metadata, search, and option inspection.
- Workspace-persisted module metadata and options.
- Explainable dry-run plans with deterministic service matching.
- A bounded job manager with scope checks, cancellation, concurrency limits, and structured events.
- A limited Metasploit RPC execution path for a fixed allowlist of passive service-version checks.
- Per-action approval records and execution-layer authorization checks.
- Bounded local evidence collection with SHA-256 integrity verification.
- Persisted evidence-linked findings.
- Workspace-scoped JSON and Markdown reports.
- Assessment-run records, workflow events, and immutable run-specific plan snapshots.

**Important limitation:** the current execution adapter only supports its fixed passive-check allowlist. It does not yet provide a general exploit execution workflow, a complete vulnerability assessment engine, or post-exploitation/session management. These are planned core capabilities, not features that should be assumed to exist today.

## Interface direction

The intended primary experience is a **graphical application**, not a terminal UI (TUI). The user-supplied interface reference informs the visual language and interaction feel; it is not a specification to reproduce a terminal application or copy its terminology and workflow.

The current Textual screen is an early prototype and should not be expanded into the final product interface. The graphical application should expose assets, services, vulnerability assessment, exploit opportunities, execution and session activity, evidence, and findings through a coherent operator workflow.

The CLI remains useful for scripting, automation, imports, and diagnostics.

## Intended assessment lifecycle

1. Select a workspace and define the authorized scope.
2. Discover hosts, ports, and exposed services.
3. Enumerate services and build target intelligence.
4. Assess potential vulnerabilities and identify evidence gaps.
5. Review candidate exploit paths, prerequisites, and expected outcomes.
6. Explicitly authorize and execute supported exploit attempts.
7. Where separately authorized, assess resulting access and security impact.
8. Validate outcomes, correlate evidence, and review findings.
9. Generate a report from the assessment run.

The workflow must distinguish observations, hypotheses, candidate vulnerabilities, validated findings, and execution outcomes.

## Run from source

Install the project and its dependencies in a virtual environment, then run:

```bash
python -m msfauto
```

The current command opens the existing Textual prototype. It is not the intended final graphical interface.

The equivalent module entry point is:

```bash
python -m msfauto.cli
```

Existing command-line operations remain available:

```bash
python -m msfauto.cli --workspace lab --discover
python -m msfauto.cli --workspace lab --import-nmap scan.xml
python -m msfauto.cli --workspace lab --show-plan
python -m msfauto.cli --workspace lab --run-safe-checks --max-checks 10 --check-workers 2
python -m msfauto.cli --workspace lab --run-safe-checks --metasploit --max-checks 10 --check-workers 2
python -m msfauto.cli --workspace lab --show-scope
python -m msfauto.cli --workspace lab --report json
python -m msfauto.cli --workspace lab --report markdown --report-output ./assessment-report.md
```

The default workspace database is stored at `~/.msfauto/workspaces.sqlite3`. Set `MSFAUTO_HOME` to use another local directory.

### Current Metasploit integration

The `--metasploit` flag opts into real Metasploit RPC execution. Configure the connection before running it:

```bash
export MSFAUTO_METASPLOIT_URL="http://127.0.0.1:55553/api/1.0"
export MSFAUTO_METASPLOIT_USERNAME="your-rpc-user"
export MSFAUTO_METASPLOIT_PASSWORD="your-rpc-password"
python -m msfauto.cli --workspace lab --run-safe-checks --metasploit
```

The current adapter permits only a fixed set of passive FTP, HTTP, MySQL, PostgreSQL, SMB, SSH, SSL, and Telnet version-identification modules. Other modules are unsupported by this execution path. A future exploit engine must have its own explicit metadata, matching, authorization, dispatch, and outcome lifecycle; it must not be implemented by simply removing this allowlist.

The MVP accepts IP addresses and CIDR networks. It does not resolve or scan arbitrary hostnames.

## Authorization and evidence

MSFAuto is intended for owned systems, isolated labs, and explicitly authorized assessments. Scope is enforced independently of the interface. Discovery does not authorize exploitation, and an obtained session does not authorize arbitrary post-exploitation actions. Exploit and post-exploitation operations require explicit action-specific authorization.

Evidence is retained separately from interpreted findings. Tool errors, service banners, and successful tool invocations are not by themselves proof of a vulnerability.

## Code layout

The active code is organized by responsibility: `core/` owns orchestration, `interface/` contains the current Textual prototype, `discovery/` owns Nmap discovery and parsing, `scope/` owns authorization boundaries, `assessment/` owns read-only planning and approval decisions, `execution/` owns approval-gated bounded checks, `evidence/` owns artifact collection and integrity verification, `findings/` owns evidence-linked assessment conclusions, `reporting/` exports reports, `integrations/` owns external tool clients, and `storage/` owns SQLite persistence and domain models.

The `enumeration/` package contains HTTP/HTTPS, SSH, FTP, and unauthenticated SMB2 negotiation adapters. Deeper TLS certificate inspection is the next protocol-intelligence step, followed by vulnerability intelligence, a first-class exploit catalog/execution engine, sessions, and validation.

## Development

Use the project setup script to create an isolated virtual environment and install development dependencies:

```bash
./scripts/setup_dev.sh
source .venv/bin/activate
```

Run checks from the activated environment:

```bash
python -m pytest
python -m ruff check .
```

GitHub Actions runs tests and Ruff on Python 3.10, 3.12, and 3.14. Update `ROADMAP.md` and `CHANGELOG.md` for meaningful changes.
