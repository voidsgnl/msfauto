# MSFAuto Terminal Interface

## Product direction

MSFAuto is terminal-only. The primary operator experience is a full-screen Textual application with a guided, numbered-menu interaction model. There is no browser interface or native desktop GUI in the product plan.

The interaction style takes inspiration from the guided workflow and full-screen terminal presentation of tools such as Fluxion. MSFAuto retains its own identity, terminology, assessment workflow, and implementation.

## Interaction model

- Launch directly into a branded main menu.
- Use number keys to enter a workflow; do not require clicking buttons.
- Use `H` or `Esc` to return to the main menu, `R` to refresh the current view, and `Q` to quit.
- Keep workspace, profile, authorized targets, and port policy visible as persistent context.
- Give each major workflow a dedicated terminal view.
- Use prompts for configuration and explicit operator decisions when those workflows are implemented.
- Keep long-running activity visible without flooding the screen with raw logs.

## Main menu

| Key | Workflow | Current behavior |
| --- | --- | --- |
| 1 | Start assessment | Runs saved-scope discovery, service enumeration, and read-only planning |
| 2 | Targets & services | Displays stored hosts and service fingerprints |
| 3 | Vulnerability assessment | Displays persisted vulnerability candidates |
| 4 | Exploit intelligence | Displays matched exploit opportunities |
| 5 | Execution manager | Displays persisted exploit execution lifecycle records |
| 6 | Findings & evidence | Displays findings and evidence records |
| 7 | Workspace & scope | Displays workspace policy and authorized boundaries |
| 8 | Assessment history | Displays previous assessment runs |

A menu entry must reflect a real application capability. Do not present placeholder actions as operational features.

## Visual language

- Near-black terminal background with restrained teal/cyan identity accents.
- ASCII wordmark and compact product/version descriptor.
- Clear section headers, separators, aligned tables, and concise status labels.
- Distinct success, warning, failure, and active-task colors; always include text labels so color is not the only signal.
- Keep dense technical information readable and avoid decorative clutter.

## Long-running task presentation

- Display an animated spinner and a clear RUNNING state while work is active.
- Display elapsed time from the actual task start.
- Stream real workflow-stage messages into a bounded activity log.
- Use an indeterminate indicator when the engine does not expose a reliable progress fraction. Never invent percentages.
- Show terminal outcomes such as COMPLETED or FAILED and include the elapsed duration.
- Treat dispatch uncertainty as a distinct lifecycle state requiring reconciliation; do not imply that it is an ordinary failure or safe to retry.

## Architecture boundary

Textual widgets own presentation and keyboard navigation only. Application services own workflow orchestration; domain packages own assessment decisions; integrations own external tool communication; storage owns durable records. UI actions must not bypass scope or action-specific authorization enforcement.

## Current implementation and follow-up

The current interface implements the numbered main menu, dedicated inventory/intelligence/execution/evidence/scope/history views, keyboard navigation, an animated task indicator, elapsed time, and a live workflow activity log.

Next interface work:
1. Add focused detail screens and row drill-down for vulnerability and exploit records.
2. Add guided prompts for workspace configuration, exploit review, and action-specific authorization.
3. Connect execution controls to the persisted lifecycle and reconciliation services.
4. Add session and post-exploitation screens when the underlying services exist.
