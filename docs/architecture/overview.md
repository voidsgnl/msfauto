# MSFAuto Architecture

## Product direction

MSFAuto is an automated security assessment platform. Its core job is to discover and enumerate assets, assess vulnerabilities, support authorized exploitation, assess authorized post-exploitation impact, validate results, and correlate evidence into useful security intelligence.

It is not merely a wrapper around Metasploit. Metasploit is one integration and execution engine among multiple assessment capabilities.

The intended primary interface is a **terminal-only, full-screen Textual application**. Its interaction model is keyboard-driven and menu-oriented, with numbered workflow selection, dedicated terminal views, and live execution feedback. There is no web interface or native desktop GUI in the product plan. Keep domain and application services independent of Textual widgets so the terminal presentation can evolve without rewriting assessment logic.

## Architectural principles

1. **Assessment capability first:** prioritize meaningful discovery, enumeration, vulnerability assessment, exploitation, validation, and analysis.
2. **Explicit authorization:** every target and operation must remain within the active authorization policy; exploitation and post-exploitation require action-specific authorization.
3. **Evidence-led conclusions:** distinguish observations, hypotheses, candidate vulnerabilities, validated findings, and execution outcomes.
4. **Explainable automation:** recommendations include evidence, rationale, confidence, prerequisites, and expected outcome.
5. **Separation of concerns:** interface, orchestration, domain engines, integrations, persistence, and reporting have distinct responsibilities.
6. **Local-first:** the application runs locally and persists state in SQLite by default.
7. **Observable execution:** long-running work exposes progress, status, output, cancellation, and recoverable errors.
8. **Safe recovery:** never automatically retry an operation whose dispatch outcome is uncertain.

## High-level component model

```text
Full-screen Textual Terminal
        |
        v
Application / Assessment Orchestrator
        |
        +---- Workspace and Configuration
        +---- Scope and Authorization
        +---- Reconnaissance / Discovery
        +---- Service Enumeration and Fingerprinting
        +---- Vulnerability Intelligence and Assessment
        +---- Exploit Catalog and Matching
        +---- Exploit Execution
        +---- Post-exploitation Assessment / Sessions
        +---- Validation and Correlation
        +---- Evidence and Findings
        +---- Reporting
        |
        v
Storage, Run Provenance, and Audit Records

Integrations: Nmap, Metasploit RPC, service-specific tools,
              vulnerability knowledge sources, and future adapters
```

The interface calls application services. It must not build shell commands, call external tools directly, or bypass policy checks. The orchestrator coordinates domain services and records workflow state. Integrations encapsulate external tool protocols and process execution.

## Core domain boundaries

| Component | Owns | Does not own |
|---|---|---|
| terminal interface | Numbered menus, terminal screens, keyboard navigation, prompts, tables, progress and presentation | Assessment decisions or direct tool execution |
| core | Application lifecycle, workflow coordination, events and state | Tool-specific protocol details |
| configuration/workspace | Settings, workspace identity and lifecycle | Authorization decisions |
| scope | Authorized targets, exclusions, ports and operation policy | User-interface navigation |
| discovery | Host, port and initial service observations | Vulnerability conclusions |
| enumeration | Service-specific probes, fingerprints, configurations and structured observations | Exploit dispatch |
| intelligence | Product/version intelligence, correlation, confidence and candidate weaknesses | Running intrusive actions |
| vulnerability assessment | Check selection, prerequisites, validation logic and assessment results | Bypassing execution controls |
| exploit catalog | Exploit metadata, affected targets, prerequisites, options and expected outcomes | Dispatching an exploit |
| exploit execution | Authorized exploit preparation, dispatch, bounded execution and outcomes | Selecting targets outside scope or granting authorization |
| post-exploitation/sessions | Authorized session metadata, lifecycle and bounded impact assessment | Treating session access as blanket permission |
| validation | Independent verification and evidence-backed outcome assessment | Converting tool success into a finding without evidence |
| evidence | Raw supporting artifacts, provenance and integrity metadata | Severity assignment |
| findings/analysis | Correlated conclusions, confidence, impact and review state | Replacing underlying evidence |
| reporting | Rendering stored assessment data | Running new checks |
| integrations | Nmap, Metasploit, service tools, protocol clients and parsers | Workflow navigation |
| storage | Durable records, migrations and run provenance | Policy interpretation |

## Assessment data flow

1. A workspace loads its configuration and active authorization scope.
2. Scope validation checks requested targets, ports, and operation class.
3. Discovery adapters produce normalized host, port, and initial service observations.
4. Enumeration adapters gather deeper service-specific information and preserve provenance.
5. Intelligence correlates observations with product, version, configuration, and vulnerability knowledge.
6. Vulnerability assessment produces candidate weaknesses, required checks, confidence, and evidence gaps.
7. The exploit catalog matches candidate techniques to target observations and evaluates prerequisites.
8. The operator reviews the proposed action and grants explicit action-specific authorization where required.
9. The execution manager revalidates scope and authorization immediately before dispatch.
10. Results, sessions, and evidence are associated with the originating assessment run.
11. Validation and correlation determine what the collected evidence supports.
12. Findings are reviewed and reports are generated from persisted run data.

## Important domain distinctions

- A discovered open port is an observation, not a vulnerability.
- A service banner or version match may justify further assessment, but is not by itself proof of a vulnerability.
- A candidate exploit match is not proof that the target is vulnerable.
- A successful tool invocation is not proof that exploitation succeeded.
- An obtained session is evidence of access, not blanket authorization for further actions.
- A recommendation is not a finding; a finding must reference supporting evidence and carry an explicit confidence/review state.

## Run provenance

Every meaningful operation should be traceable to an assessment run, target, operation definition, authorization decision, dispatch attempt, result, and evidence artifact. Run-specific records must preserve workspace isolation. If dispatch state is uncertain after interruption, mark the operation for operator reconciliation; do not automatically retry it.

## Current implementation and migration

The repository currently has working foundations for Nmap discovery, normalized host/service storage, read-only Metasploit metadata, a limited passive-check adapter, read-only planning, bounded jobs, approvals, evidence, findings, workspace reports, and run-specific plan snapshots.

The Textual interface is the intended primary operator experience. Keep its service calls reusable and keep domain behavior outside the widgets.

Introduce future domain packages only when they contain real behavior and tests. Preserve the existing SQLite data with explicit migrations. Work directly on `main`; do not create a redesign branch unless explicitly requested.
