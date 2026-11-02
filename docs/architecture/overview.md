# MSFAuto Architecture

## Product direction

MSFAuto is a local, terminal-first orchestrator for authorized security assessments. Its interaction model is inspired by Wifite: start the application, define or select an authorized scope, discover targets, inspect the results, choose an assessment, approve actions, and review evidence.

The goal is not to reproduce Wifite's wireless-specific functionality. The goal is to adopt its focused, guided, operator-visible workflow for broader network security assessment.

## Architectural principles

1. **Workflow-first:** the normal path is a single guided assessment, not a collection of unrelated commands.
2. **Explicit authorization:** every target and operation must remain within the active authorization policy.
3. **Explainable automation:** recommendations include evidence, rationale, confidence, prerequisites, and risk.
4. **Separation of concerns:** interface, orchestration, discovery, analysis, planning, execution, persistence, and reporting have distinct responsibilities.
5. **Incremental migration:** preserve working code and tests; move responsibilities only when there is a concrete benefit.
6. **Local-first:** the application runs locally and persists state in SQLite by default.
7. **Observable execution:** long-running work exposes progress, status, output, cancellation, and recoverable errors.

## High-level component model

```text
Terminal Interface
       |
       v
Application / Workflow Orchestrator
       |
       +---- Workspace and Configuration
       +---- Scope and Authorization
       +---- Discovery
       +---- Intelligence and Correlation
       +---- Assessment Planning and Approval
       +---- Controlled Execution
       +---- Sessions and Evidence
       +---- Findings and Reporting
       |
       v
Storage and Audit Records

Integrations: Nmap, Metasploit RPC, and future explicitly configured tools
```

The interface calls application services. It must not build shell commands, call external tools directly, or bypass policy checks. The orchestrator coordinates services and records workflow state. Integrations encapsulate external tool protocols and process execution.

## Component responsibilities

| Component | Owns | Does not own |
|---|---|---|
| interface | Screens, navigation, prompts, progress and presentation | Assessment decisions or direct tool execution |
| core | Application lifecycle, workflow coordination, events and state | Tool-specific protocol details |
| configuration | Loading, defaults and validation of settings | Authorization decisions |
| workspace | Workspace identity and lifecycle | Target discovery |
| scope | Authorized targets, exclusions, ports and operation policy | User-interface navigation |
| discovery | Host, port and service observations; scanner imports | Vulnerability conclusions |
| intelligence | Fingerprinting, evidence correlation, confidence and recommendations | Running intrusive actions |
| assessment | Check selection, planning, prioritization and approvals | Bypassing execution controls |
| integrations | Nmap and Metasploit communication, tool detection and parsing | Workflow navigation |
| execution | Approved operation scheduling, bounds, cancellation and results | Selecting targets outside scope |
| sessions | Session metadata and lifecycle tracking | Unapproved session creation |
| evidence | Raw supporting artifacts, provenance and integrity metadata | Severity assignment |
| findings | Normalized observations and finding status/severity | Replacing underlying evidence |
| reporting | Rendering stored assessment data | Running new checks |
| storage | Durable records and migrations | Policy interpretation |

## Data flow

1. A workspace loads its configuration and active scope.
2. Scope validation checks the requested targets, ports, and operation class.
3. Discovery adapters produce normalized host and service observations.
4. Observations are persisted with timestamps and source provenance.
5. Intelligence correlates observations with known service capabilities and assessment knowledge.
6. The planner creates recommendations with rationale, confidence, risk, and prerequisites.
7. The approval service records operator decisions for operations requiring approval.
8. The execution manager revalidates scope and policy immediately before dispatch.
9. Results and evidence are persisted; findings reference their supporting evidence.
10. Reports are generated from persisted records.

## Domain model boundaries

Keep domain objects independent of Textual widgets and external RPC response shapes. External responses should be parsed into internal models at integration boundaries. Database records should be mapped through storage repositories rather than leaking SQLite rows into the interface.

A recommendation is not a finding. A service observation is not proof of a vulnerability. A successful tool invocation is not proof that a security issue exists.

## Initial code mapping

The current repository is intentionally small. The following mapping is a migration guide, not a requirement to move every file immediately.

| Current module | Target responsibility |
|---|---|
| `msfauto/cli.py` | CLI bootstrap and interface entry |
| `msfauto/tui.py` | Replace dashboard-only screen with workflow-oriented interface |
| `msfauto/discovery.py` | Split discovery orchestration, Nmap adapter, and XML parsing when needed |
| `msfauto/scope.py` | Scope policy and validation |
| `msfauto/models.py` | Gradually split domain models by bounded context |
| `msfauto/planner.py` | Assessment planning and recommendation logic |
| `msfauto/jobs.py` | Controlled execution/job lifecycle |
| `msfauto/metasploit.py` | Metasploit integration |
| `msfauto/storage.py` | Database access and repositories |

## Migration constraints

- Work on the existing `main` branch; do not create a redesign branch.
- Keep current public CLI flags working until replacements have tests and documented migration paths.
- Preserve SQLite data and introduce schema migrations before changing persisted structures.
- Do not create empty placeholder packages solely to match a diagram.
- Do not add dependencies unless a specific requirement justifies them.
- Update tests, documentation, and `CHANGELOG.md` with each meaningful migration.
- Keep the application usable after each phase.
