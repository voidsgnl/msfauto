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

Supporting capabilities include assessment orchestration, authorization and approvals, session/job lifecycle management, evidence integrity, reporting, and a persistent Metasploit-style command console.

## Current implementation status

The repository currently provides foundations for:

- Interactive workspace creation and startup.
- SQLite-backed workspaces, discovery observations, append-only service enumeration observations, workspace-level plans, immutable run-specific plan snapshots, workflow runs, and events.
- Explicit IP/CIDR scope and optional port allowlists.
- Nmap discovery with bounded execution, XML output, and lightweight service/version detection (-sV --version-light).
- Protocol-aware HTTP/HTTPS, SSH, FTP, SMB2, and TLS-only enumeration with bounded probes and structured observations; TLS captures handshake metadata and certificate fingerprints.
- Initial vulnerability advisory/candidate models and evidence-aware matching, plus OSV.dev package-version queries integrated into the assessment workflow through explicit service-product-to-package mappings. OSV advisories and candidates are persisted; provider failures are isolated and reported. Package name and ecosystem are never inferred from banners.
- Scope-enforced Nmap XML import and normalized host/service storage, including product/version, probe method/confidence, extra information, tunnel metadata, CPEs, source, and observation time.
- Persistent Nmap scan history with unique XML artifacts, stable scan IDs, command/status/timing provenance, immutable normalized snapshots, and console history/diff commands.
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


### Metasploit RPC connection

For the default local endpoint, the interactive MSFAuto console automatically starts and supervises `msfrpcd` when no service is already listening. It binds the daemon to loopback, waits for the RPC port, and stops only the child process it started when the console exits. If an RPC service is already running, MSFAuto reuses it and requires its configured credentials.

When starting a local daemon, MSFAuto generates an ephemeral RPC password if credentials were not supplied. The password is passed to supported Metasploit versions through the child process environment rather than command-line arguments. The daemon is not started for remote RPC endpoints.

You can override the endpoint and/or provide credentials for an existing service using `MSFAUTO_METASPLOIT_URL`, `MSFAUTO_METASPLOIT_USERNAME`, and `MSFAUTO_METASPLOIT_PASSWORD`. The default endpoint is `http://127.0.0.1:55553/api/1.0`. RPC authentication is required even for read-only catalogue queries such as `exploits list`.

### Importing exploit metadata from Metasploit

Use `exploits list [filter]` in the interactive console to display the live module-name inventory returned by Metasploit's `module.exploits` RPC method; the optional case-insensitive filter narrows that inventory. Use `exploits opportunities` for target-matched, workspace-persisted leads. These are intentionally separate: a module being present in Metasploit does not mean it applies to a discovered target. MSFAuto can also normalize module metadata (rank, description, platforms, architectures, targets, required options, references, and check support). Import is deliberately opt-in and restricted to modules listed in `MSFAUTO_EXPLOIT_PRODUCT_MAPPINGS`; the importer fetches detailed metadata only for those mapped modules.

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

Pass that JSON as `mappings` to `sync_metasploit_exploits(client, store, workspace, mappings)` from `msfauto.exploitation`, using an authenticated `MetasploitClient` and the workspace's `WorkspaceStore`. The helper imports the mapped modules and persists them in the workspace-scoped `exploit_catalog` table. The assessment workflow merges active synchronized entries with `MSFAUTO_EXPLOIT_CATALOG` by `exploit_id`. Refreshes update framework metadata but preserve existing operator-controlled product/version/advisory mappings; change those explicitly with `WorkspaceStore.update_exploit_catalog_mapping(...)`. A successful non-empty refresh deactivates entries no longer present in that source. An empty result does not deactivate the existing catalog. No module is approved or executed by synchronization.

### Reviewing and authorizing an exploit opportunity

Exploit matching produces an applicability lead, not an approval. The review and authorization primitives are deliberately separate from execution:

- Create a human review with `review_opportunity(opportunity, reviewer, decision, rationale)`. Decisions are `accepted`, `rejected`, or `deferred`.
- Persist the review with `WorkspaceStore.save_exploit_review(...)`.
- Create an action-specific authorization with `authorize_opportunity(opportunity, current_scope_policy, approver, rationale, review=accepted_review)`.
- Persist it with `WorkspaceStore.save_exploit_authorization(...)`.
- Immediately before any future dispatch, load the authorization and call `validate_authorization(authorization, current_opportunity, current_scope_policy)`.

The review and authorization bind the workspace, opportunity, exploit ID, module name, exact target and port, protocol, product, and observed version. Authorization additionally binds a digest of the current scope and expires after 15 minutes by default (maximum eight hours). It is denied unless the workspace uses the `dangerous-actions` profile and both target and port are in scope. Authorizations can be revoked with `WorkspaceStore.revoke_exploit_authorization(...)`.

These APIs establish a gate; they do not execute a module. The execution layer must revalidate authorization immediately before dispatch and must never automatically retry an operation whose dispatch outcome is uncertain.

### Controlled Metasploit exploit dispatch

The durable lifecycle now has a narrow Metasploit dispatch adapter:

- Prepare an execution with `prepare_exploit_execution(store, opportunity, authorization, actor=...)`. This verifies the persisted opportunity, accepted review, authorization, and workspace scope.
- `MetasploitExploitDispatcher(store, client).dispatch(execution_id, actor=...)` accepts only the identifier of an existing `prepared` record. It does not accept arbitrary module names, targets, ports, or option dictionaries from the caller.
- Before dispatch, the adapter requires the exact module to exist in the active workspace-synchronized exploit catalog, confirms the live framework module type is `exploit`, and inspects its current options.
- The initial adapter supports only network modules exposing both `RHOSTS` and `RPORT`. It supplies exactly those two values from the persisted authorized opportunity. Modules with any other required option are rejected before dispatch; payload, handler, listener, and arbitrary datastore configuration are not exposed.
- The lifecycle revalidates the persisted opportunity, accepted review, authorization expiry/revocation, and current scope, then persists `dispatching` before the one external RPC request.
- A confirmed RPC acknowledgement stores the framework job ID and UUID and transitions to `running`. Any exception after dispatch intent is persisted is treated as ambiguous, transitions to `dispatch_uncertain`, and raises `ExploitDispatchUncertain`. The adapter never retries an uncertain attempt.
- A non-prepared execution, stale or missing catalog entry, changed opportunity, invalid module type, unsupported required option, or authorization/scope failure is blocked before the exploit RPC call.

The execution record and append-only transition events remain stored in SQLite. Each authorization is single-use. Process recovery and explicit operator reconciliation remain required when dispatch outcome is uncertain. The adapter does not stop jobs, create sessions, or validate security impact; those are separate follow-on capabilities. The existing passive-check allowlist and execution path remain unchanged.

### Metasploit exploit job reconciliation

The dispatcher now has a separate framework-job reconciler:

- `MetasploitClient.job_list()` reads the active Metasploit job map and validates job identifiers and descriptions.
- `MetasploitExploitReconciler(store, client).poll(execution_id, actor=...)` polls only persisted `running` or `cancelling` execution records with both a framework job ID and UUID.
- If the job is still listed, the execution remains active and the UUID results endpoint is not queried.
- When the job disappears, the reconciler asks `module.results` for the UUID-specific outcome. Only recognized `completed`, `failed`, or `cancelled` results can close the execution.
- If the results endpoint is unavailable, reports an unknown status, or contradicts the active-job list, the execution remains unchanged and the poll result is marked `unresolved`. An absent job alone is never treated as success or failure.
- A framework-reported `completed` state means only that Metasploit finished the module run. The stored outcome explicitly says exploit success and security impact are not independently verified.
- `dispatch_uncertain` records are not pollable through this path; they require explicit operator reconciliation.

Polling is an explicit one-shot operation, not an automatic retry loop. It does not stop jobs, create sessions, or perform post-exploitation validation.

**Important limitation:** exploit dispatch is now implemented for this narrow target-only option profile, but it is not a general-purpose Metasploit console. Modules requiring payload selection, handlers, local listener configuration, credentials, or additional options are deliberately unsupported. A returned job/UUID confirms framework acceptance, not exploit success or security impact. Independent target-outcome assessments can be recorded and reviewed separately. The exact-match module-verifier registry is implemented, but no built-in module verifier is registered yet; post-exploitation/session management also remains future work.

## Exploit outcome verification

Metasploit framework state and target outcome are separate records. A framework-reported `completed` state means only that the module run ended; it does not establish exploit success or security impact.

The current `ExploitOutcomeValidator` records append-only target outcome assessments with one of three verdicts: `confirmed`, `not_confirmed`, or `inconclusive`. Each assessment records the verifier, method, operator, rationale, timestamp, and evidence references. Conclusive verdicts require evidence stored for the exact execution workspace and target. Evidence attributed only to Metasploit is rejected as independent verification. `ModuleVerifierRegistry` selects a verifier only by exact Metasploit module name and passes it a bounded timeout budget. Missing registrations and verifier timeouts produce `inconclusive` assessments; an unsupported module causes no probe to be sent. No built-in verifier is currently registered because each one must be grounded in a documented, non-destructive target-side indicator.

This is an evidence-backed assessment record, not an automatic exploit-success detector. A module-specific verifier must define its expected target-side indicator and bounded verification procedure before it can produce a conclusive result. No generic target probe or live exploit validation is claimed.

The persistent command console exposes this workflow:

```text
exploits outcome record <execution-id> <confirmed|not_confirmed|inconclusive> <verifier> <method> <evidence-id[,id]|-> <actor> <rationale>
exploits outcome list <execution-id>
```

Evidence IDs must already exist and belong to the same workspace and exact target as the execution. Use `-` only for an inconclusive assessment without evidence. Quoted arguments can contain spaces. Recording an outcome never changes the Metasploit execution state.

## Interface direction

MSFAuto is a **terminal-only application** with a persistent Metasploit-style, mode-aware command prompt. The root `msfauto >` prompt exposes `use <mode>`, `show modes`, `help`, and `exit`. Enter `discovery`, `exploit`, `analysis`, or `workspace` mode to get a focused command catalogue and a matching prompt such as `[discovery] msfauto >`. Use `back` to return to the root prompt; `help` always shows only the current context's commands. Existing hierarchical command handlers and services are reused beneath the short mode commands. Discovery comparisons report host additions/removals/identity changes as well as service-level changes. Rich terminal output and live task messages provide feedback without turning the application into a menu-driven TUI. There is no web interface or native desktop GUI in the product plan.

Example:
```text
msfauto > show modes
msfauto > use discovery
[discovery] msfauto > help
[discovery] msfauto > history
[discovery] msfauto > back
msfauto > use exploit
[exploit] msfauto > list
```

The CLI remains available for scripting, automation, imports, and diagnostics.

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

The default command opens the full-screen terminal application.

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

The active code is organized by responsibility: `core/` owns orchestration, `interface/` contains the full-screen, menu-driven Textual terminal application, `discovery/` owns Nmap discovery and parsing, `scope/` owns authorization boundaries, `assessment/` owns read-only planning and approval decisions, `execution/` owns approval-gated passive checks, the durable exploit lifecycle, and the narrow Metasploit exploit dispatcher, `evidence/` owns artifact collection and integrity verification, `findings/` owns evidence-linked assessment conclusions, `reporting/` exports reports, `integrations/` owns external tool clients, and `storage/` owns SQLite persistence and domain models.

The `enumeration/` package contains HTTP/HTTPS, SSH, FTP, unauthenticated SMB2 negotiation, and TLS-only handshake/certificate fingerprint adapters. The `vulnerability/` package contains evidence-aware matching, the OSV.dev client, and assessment-workflow integration. The `exploitation/` package contains a curated exploit catalog, exact applicability matching, and persisted opportunity records. The separate `execution/exploit_dispatch.py` adapter handles the narrow, authorization-bound Metasploit dispatch path. Configure mappings with `MSFAUTO_OSV_PACKAGE_MAPPINGS` as a JSON array; each entry requires `product`, `package_name`, and `ecosystem`, with optional `product_aliases`. Example: `[{"product":"OpenSSH","package_name":"openssh-server","ecosystem":"Ubuntu:22.04"}]`. The workflow queries each distinct package/ecosystem/version once, persists advisories and candidates, and continues when an individual OSV query fails. No package identity is inferred from a service banner. Bulk feed synchronization, ecosystem-specific local range evaluation, and broader CPE/package identity coverage remain future work; the exploit catalog/execution engine remains a separate first-class subsystem.

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
