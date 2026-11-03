# Assessment Workflow

## Product workflow

MSFAuto's primary workflow is an end-to-end security assessment, not a sequence of disconnected scanner commands. The intended primary interface is graphical. The current Textual console is a prototype and is not the target UI.

The graphical experience should let an operator move between an assessment overview, assets, services, vulnerability candidates, exploit opportunities, execution/session activity, evidence, and findings while retaining clear context about the active workspace and authorized scope.

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
- Run appropriate service-specific enumeration checks.
- Inspect relevant configuration and protocol behavior.
- Preserve raw output as evidence and parse structured observations for later stages.
- Clearly identify what remains unknown; do not overstate fingerprint confidence.

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

- Use a graphical application as the primary experience.
- Present assets, services, vulnerability candidates, exploit opportunities, execution/session activity, evidence, and findings as connected views.
- Keep workspace and authorization context visible.
- Show meaningful progress and actionable status, not raw log floods.
- Make technical details, command output, and evidence accessible on demand.
- Keep the interface independent of assessment decisions and execution enforcement; application services and execution adapters own those responsibilities.
- The existing Textual prototype is not the design target and should not be expanded as the final UI.

## Authorization boundary

Discovery does not grant permission to exploit. Exploitation requires explicit action-specific authorization. Post-exploitation actions require separate authorization. Every execution path must enforce scope and authorization independently of the interface.
