# Assessment Workflow

## Interaction model

MSFAuto uses a guided, terminal-first workflow inspired by Wifite. The operator should not need to manually coordinate Nmap, analysis, planning, and result storage for a routine assessment.

The primary entry point is:

```bash
python -m msfauto
```

The command-line interface remains available for scripting, imports, and advanced use. The interactive workflow is the primary user experience.

## Main menu

The main menu should remain small:

```text
MSFAuto — Automated Security Assessment

Workspace: lab
Scope:     192.168.1.0/24
Status:    Ready

[1] Start assessment
[2] Browse targets
[3] Assessment history
[4] Reports and evidence
[5] Settings
[0] Exit
```

Scope and workspace status remain visible as context rather than becoming separate top-level destinations. Target-specific actions appear after a target is selected.

## Guided assessment stages

### 1. Workspace and scope

- Select or create a workspace.
- Display the authorized IP/CIDR scope and port restrictions.
- Validate scope syntax and policy.
- Require the operator to confirm the scope before starting a new assessment.
- Never silently widen the saved scope.

### 2. Discovery

- Check required tool availability and version.
- Run bounded discovery using the configured discovery policy.
- Display progress and meaningful stage messages.
- Normalize and persist discovered hosts, ports, and services.
- Allow import of existing Nmap XML as an alternate path.
- Handle timeouts, partial results, cancellation, and malformed imports.

### 3. Target selection

Present discovered hosts in a compact table with address, hostname when known, open ports, service summary, and assessment status. The operator can select one target or explicitly choose a permitted multi-target workflow.

### 4. Intelligence analysis

For each selected target:

- Summarize observed services and versions.
- Correlate observations with relevant assessment capabilities.
- Identify missing information and useful enumeration steps.
- Show confidence and the evidence behind each inference.
- Separate confirmed observations from potential weaknesses and unverified hypotheses.

### 5. Assessment plan

Generate a plan automatically after analysis. Each recommendation should show:

- Target and service.
- Purpose and expected outcome.
- Supporting observation and rationale.
- Tool or check required.
- Prerequisites and required options.
- Risk and operation class.
- Confidence and limitations.
- Whether approval is required.

The operator may inspect, exclude, or defer recommendations. Plan generation must not execute them.

### 6. Approval

Before a safe check is dispatched, the CLI displays its target, port, module, risk, confidence, and rationale. The operator supplies an approver identifier and must type the exact word `APPROVE` for each recommendation. Every approval or rejection is persisted with a stable action identifier, timestamp, approver, and rationale. A decision applies only to that exact workspace/target/port/protocol/module/risk tuple; it does not authorize another recommendation. The current implementation stores the latest decision per action.

### 7. Execution

- Revalidate scope and policy immediately before execution.
- Apply timeouts and concurrency limits.
- Capture structured status, output, and errors.
- Support cancellation where the underlying operation permits it.
- Avoid automatic retries for operations that may have side effects unless idempotency is established.
- Clearly distinguish completed, failed, skipped, cancelled, unsupported, and timed-out results.

### 8. Findings and evidence

Persist raw evidence separately from interpreted findings. Findings should identify their confidence, severity rationale, status, and evidence references. A tool error or version-based match must not be reported as a confirmed vulnerability.

### 9. Completion and reporting

Show a concise summary of targets, checks, findings by status, failures, and report location. Reports should be generated from persisted assessment data and support JSON, Markdown, and HTML over time.

## Workflow states

Suggested assessment lifecycle:

```text
created
  -> scope_validated
  -> discovering
  -> discovery_complete
  -> analyzing
  -> plan_ready
  -> awaiting_approval
  -> executing
  -> collecting_evidence
  -> completed
```

Terminal or recoverable states include `failed`, `cancelled`, and `partial`. The state model must preserve enough information to resume or explain an interrupted workflow.

## Interface behavior

- Keep the normal path keyboard-driven and concise.
- Show current workspace, scope, and operation state persistently.
- Stream meaningful progress rather than flooding the screen with raw logs.
- Make detailed command output available on demand.
- Use consistent status labels and clear error messages.
- Provide a reliable way to cancel or return without losing persisted work.
- Avoid a separate informational dashboard that duplicates the workflow.

## Safety boundary

Discovery results do not grant authorization. Every active operation must be covered by the workspace authorization policy and any required per-action approval. The application must not automatically launch exploit, credential attack, persistence, pivoting, destructive, or other high-impact actions.
