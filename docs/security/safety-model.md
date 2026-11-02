# MSFAuto Safety and Authorization Model

## Purpose

MSFAuto is intended for authorized security assessments of owned systems, isolated labs, and explicitly approved environments. Safety controls are part of the application architecture, not optional interface decoration.

## Authorization model

Every assessment is associated with a workspace and an explicit scope policy. The policy should define:

- Authorized IP addresses and CIDR networks.
- Explicit exclusions.
- Allowed destination ports where applicable.
- Permitted operation classes.
- Relevant time or engagement constraints when configured.
- The identity or note associated with the authorization, where appropriate.

The current MVP accepts IP addresses and CIDR networks. Hostname resolution should not be introduced implicitly; it requires a separately designed resolution and scope-validation policy.

## Operation classes

Classify operations by behavior and potential impact, not merely by tool or module name.

| Class | Examples | Default handling |
|---|---|---|
| Local analysis | Parse existing scan data, correlate metadata | Allowed |
| Discovery | Bounded host and service discovery | Allowed only within configured scope |
| Non-invasive checks | Read-only or low-impact validation | Policy-controlled and bounded |
| Active validation | Requests that may affect target state or availability | Explicit approval |
| Intrusive operations | Exploitation or actions with meaningful side effects | Disabled by default; require explicit authorization and per-action approval |
| Prohibited-by-default actions | Credential attacks, persistence, pivoting, destructive actions | Not part of the normal automated workflow |

A Metasploit module's category or rank alone is not sufficient to determine whether it is safe. The operation must be reviewed based on its actual behavior, options, target, and expected impact.

## Mandatory enforcement points

1. Validate the workspace scope before discovery.
2. Restrict discovery targets and ports to the configured policy.
3. Validate imported scanner results before persistence.
4. Validate each recommendation against scope and operation policy.
5. Require approval when the operation class requires it.
6. Revalidate target, port, and policy immediately before execution.
7. Record the requested action, approval decision, execution result, and relevant timestamps.
8. Fail closed when policy cannot be evaluated.

The interface must not be the enforcement boundary. These checks belong in application services and execution adapters so CLI, TUI, and future automation entry points share the same controls.

## Approval records

The current approval record identifies:

- Workspace and assessment.
- Action or recommendation identifier.
- Exact target and port.
- Tool, module, or check identifier.
- Relevant options, excluding secrets.
- Operation class and risk explanation.
- Approver decision and timestamp.
- Policy version or relevant policy snapshot.

Approval of one action must not imply approval of another action, a different target, or modified options.

## Execution controls

- Use argument arrays rather than shell-string execution.
- Apply explicit timeouts and concurrency bounds.
- Validate executable paths and required options.
- Capture output without leaking credentials or tokens.
- Support cancellation and record its outcome.
- Do not retry potentially state-changing actions automatically.
- Revalidate scope immediately before dispatch.
- Treat unknown operation behavior as requiring review, not as safe.

## Evidence and sensitive data

Evidence should record source, collection time, target, assessment, and integrity metadata. Secrets, credentials, session tokens, and sensitive payload data must not be copied into ordinary logs or reports. Access to sensitive artifacts should be deliberate and clearly represented.

## Failure behavior

If scope, authorization, tool behavior, or operation classification is ambiguous, MSFAuto must stop the affected operation and explain why. It must never broaden scope or downgrade an operation's risk to make the workflow continue.
