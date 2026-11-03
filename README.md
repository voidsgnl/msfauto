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
- Protocol-aware HTTP/HTTPS, SSH, FTP, SMB2, and TLS-only enumeration with bounded probes and structured observations; TLS captures handshake metadata and certificate fingerprints.
- Initial vulnerability advisory/candidate models and evidence-aware matching, plus OSV.dev package-version queries integrated into the assessment workflow through explicit service-product-to-package mappings. OSV advisories and candidates are persisted; provider failures are isolated and reported. Package name and ecosystem are never inferred from banners.
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

### Exploit intelligence catalog

A curated catalog can be supplied through `MSFAUTO_EXPLOIT_CATALOG` as a JSON array. Each entry requires `exploit_id`, `source`, `module_type` (must be `exploit`), `module_name`, `name`, `product_aliases`, and `affected_versions`. Optional metadata includes advisory IDs, rank, platforms, architectures, target names, prerequisites, required options, references, check support, and risk.

Example entry:

```json
[
  {
    "exploit_id": "vendor-or-catalog:unique-id",
    "source": "maintained-catalog-name",
    "module_type": "exploit",
    "module_name": "platform/service/example",
    "name": "Example exploit metadata",
    "product_aliases": ["Example Server"],
    "affected_versions": ["1.2.3"],
    "advisory_ids": ["CVE-2099-1234"],
    "rank": "excellent",
    "prerequisites": ["Required target condition"],
    "required_options": ["RHOSTS", "RPORT"],
    "references": ["https://example.invalid/advisory"],
    "check_supported": false,
    "risk": "high"
  }
]
```

Matching requires an open service, an exact product alias, and either an exact affected version or a linked vulnerability candidate with an explicitly listed advisory ID. Results are persisted as identified exploit opportunities. The catalog is metadata only: it does not authorize, configure, or execute a module. Version ranges and fuzzy product matching are deliberately not inferred.


### Importing exploit metadata from Metasploit

MSFAuto can enumerate the connected framework's exploit modules through the dedicated Metasploit RPC `module.exploits` method and normalize module metadata (rank, description, platforms, architectures, targets, required options, references, and check support). Import is deliberately opt-in and restricted to modules listed in `MSFAUTO_EXPLOIT_PRODUCT_MAPPINGS`; the importer fetches detailed metadata only for those mapped modules.

The mapping must explicitly identify products and at least one exact affected version or advisory ID. Module names, descriptions, platform labels, and references are not used to guess product identity or affected versions. Example:

```json
{
  "windows/smb/example_module": {
    "product_aliases": ["Example Server"],
    "affected_versions": ["1.2.3"],
    "advisory_ids": ["CVE-2026-12345"]
  }
}
```

Set that JSON as `MSFAUTO_EXPLOIT_PRODUCT_MAPPINGS` and call `import_metasploit_exploits(client)` from `msfauto.exploitation` using an authenticated `MetasploitClient`. The importer returns normalized catalog definitions; it does not execute modules, persist a refreshed catalog, or automatically change the assessment workflow's curated `MSFAUTO_EXPLOIT_CATALOG`. Catalog synchronization/persistence and workflow integration remain future work.

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

The `enumeration/` package contains HTTP/HTTPS, SSH, FTP, unauthenticated SMB2 negotiation, and TLS-only handshake/certificate fingerprint adapters. The `vulnerability/` package contains evidence-aware matching, the OSV.dev client, and assessment-workflow integration. The `exploitation/` package contains a curated exploit catalog, exact applicability matching, and persisted opportunity records; it does not dispatch modules. Configure mappings with `MSFAUTO_OSV_PACKAGE_MAPPINGS` as a JSON array; each entry requires `product`, `package_name`, and `ecosystem`, with optional `product_aliases`. Example: `[{"product":"OpenSSH","package_name":"openssh-server","ecosystem":"Ubuntu:22.04"}]`. The workflow queries each distinct package/ecosystem/version once, persists advisories and candidates, and continues when an individual OSV query fails. No package identity is inferred from a service banner. Bulk feed synchronization, ecosystem-specific local range evaluation, and broader CPE/package identity coverage remain future work; the exploit catalog/execution engine remains a separate first-class subsystem.

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
