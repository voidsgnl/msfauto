# Assessment Workflow

## Product objective

The operator supplies an authorized target (ultimately an IP address, network, or URL); MSFAuto autonomously discovers its attack surface, investigates relevant services and applications, runs bounded vulnerability checks, correlates evidence with Metasploit modules, and presents findings with a prepared exploitation path. The operator should not have to choose each scanner or enumeration command.

Metasploit is the primary framework integration. The intended discovery path is `db_nmap` through the Metasploit RPC console, followed by host/service retrieval from the Metasploit database. Nmap XML import remains useful for interoperability, but should not be the primary discovery-to-inventory path. Authenticated RPC primitives for `db_nmap`, temporary console lifecycle, and database inventory retrieval are implemented and wired into the interactive `run` assessment path. The one-shot CLI still uses the legacy standalone Nmap provider; URL target support, native record-ID provenance, and the complete vulnerability pipeline remain follow-up work.

## Default discovery coverage

The interactive entry point is `discover run` (also available as `discovery run`). It runs the end-to-end, read-only assessment pipeline using the `standard` TCP port profile by default.

- `--profile quick`: a smaller set of high-value service ports.
- `--profile standard`: the default prioritized service-port set.
- `--profile full` or `--full`: all TCP ports, unless the workspace has an explicit port allowlist.
- One-shot equivalent: `python -m msfauto.cli --discover --scan-profile full`.

An explicit saved workspace port allowlist takes precedence over profile defaults and is scanned exactly as configured. Profiles never expand that saved list. Nmap's discovery result feeds service fingerprinting and the existing protocol adapters. The assessment enumerator runs with one worker by default so service investigations occur sequentially. Unsupported or unrecognized service adapters remain an explicit coverage gap and should be surfaced for manual investigation rather than interpreted as a negative result.


## Product workflow

MSFAuto's primary workflow is an end-to-end, command-driven security assessment, not a sequence of disconnected scanner commands. The primary interface is a persistent Metasploit-style command console. The normal entry point is `discover run`: it discovers the prioritized port set, identifies services, investigates each open service sequentially, correlates vulnerability and exploit intelligence, and persists one traceable assessment run.

Broad all-TCP-port discovery remains an explicit alternative through `discover run --profile full`. Individual evidence and analysis commands remain available when an operator wants to inspect or repeat a specific stage. The `investigate` view explains what evidence exists and what should happen next for each discovered service. Manual review is an explicit workflow state, not a dead end.

## Assessment stages

### 1. Workspace and authorization scope
- Select or create a workspace.
- Display authorized targets, exclusions, port restrictions, and permitted operation classes.
- Validate scope and authorization before any assessment activity.
- Never silently widen saved scope.

### 2. Reconnaissance and discovery
- Check required tool availability and versions.
- Discover in-scope hosts, ports, and initial services.
- Normalize and persist observations with timestamps and source provenance.
- Support Nmap XML import as an alternate path.
- Handle timeouts, partial results, cancellation, and malformed imports.

### 3. Service enumeration
- Fingerprint identified services and gather useful product/version details.
- Run appropriate service-specific enumeration checks sequentially, one open service at a time.
- Collect protocol greetings, capabilities, TLS metadata, and application fingerprints where supported; never attempt authentication as part of passive enumeration.
- Inspect relevant configuration and protocol behavior.
- Preserve raw output as evidence and parse structured observations for later stages.
- Clearly identify what remains unknown; do not overstate fingerprint confidence.
- Produce a per-service next-action assessment: ready for analyst review, needs manual/additional review, or insufficient evidence/intelligence.

### 4. Vulnerability assessment
- Correlate observed products, versions, configurations, and behaviors with vulnerability knowledge.
- Generate candidate weaknesses with supporting observations, prerequisites, confidence, and evidence gaps.
- Distinguish detected facts, suspected weaknesses, and unverified hypotheses.
- Do not declare a vulnerability solely from a banner or version string.

### 5. Exploit intelligence and review
- Match candidate exploit techniques against target observations.
- Display affected products/versions, prerequisites, required options, compatibility, expected outcome, risk, and supporting references.
- Explain why a technique is considered relevant and what evidence is missing.
- Let the operator inspect, reject, defer, or authorize a specific action.
- A candidate match must never be treated as proof of vulnerability or authorization.

### 6. Exploit execution
- Require explicit action-specific authorization and revalidate target scope immediately before dispatch.
- Use supported integrations and bounded execution policies.
- Record preparation, dispatch, running state, output, completion, failure, timeout, cancellation, and uncertain dispatch state.
- Do not silently retry an operation with an uncertain dispatch outcome.
- Clearly distinguish tool errors, failed attempts, successful execution, and verified security impact.

### 7. Post-exploitation assessment and sessions
- Treat sessions as first-class records linked to the originating run, target, and operation.
- Require separate authorization for post-exploitation assessment actions.
- Limit activity to the approved assessment objective and preserve evidence of actions and results.
- A session does not grant blanket permission for persistence, stealth, pivoting, or destructive activity.

### 8. Validation, evidence, and findings
- Validate suspected weaknesses and exploit outcomes using evidence-backed checks.
- Store raw evidence separately from interpreted findings.
- Preserve source, target, collection time, provenance, and integrity metadata.
- Correlate observations across stages and identify confidence and limitations.
- Findings must reference supporting evidence and remain reviewable by an analyst.

### 9. Analysis and reporting
- Summarize assets, exposed services, assessment coverage, candidate vulnerabilities, exploit attempts, sessions, validated findings, and unresolved questions.
- Prioritize findings using technical impact, confidence, exposure, and supporting evidence.
- Generate reports from persisted assessment-run data with full provenance.

## Workflow state model

The lifecycle should represent at least:
- Created and scope validated.
- Discovering and discovery complete.
- Enumerating and enumeration complete.
- Assessing vulnerabilities and assessment results ready.
- Awaiting exploit review/authorization.
- Preparing, dispatched, running, and completed exploit attempts.
- Awaiting separately authorized post-exploitation assessment.
- Validating and correlating.
- Completed, partially completed, failed, cancelled, or interrupted.

Dispatch uncertainty must be represented explicitly and require operator reconciliation. Do not infer that a timed-out client request means the remote operation never started.

## Interface behavior

- Use the persistent Rich + prompt_toolkit command console as the primary experience.
- Keep startup minimal and expose the full command catalogue through `help`.
- Keep workspace and authorization context visible.
- Show meaningful stage progress and per-service status, not raw log floods.
- Make technical details and stored evidence accessible through `observations` and next-step guidance through `investigate`.
- Keep the interface independent of assessment decisions and execution enforcement; application services and execution adapters own those responsibilities.

## Authorization boundary

Discovery does not grant permission to exploit. Exploitation requires explicit action-specific authorization. Post-exploitation actions require separate authorization. Every execution path must enforce scope and authorization independently of the interface.
