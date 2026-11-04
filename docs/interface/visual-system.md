# Graphical interface visual system

## Direction

MSFAuto's intended operator experience is a graphical security-assessment console, not a terminal emulator. Use a dark, high-contrast workspace with restrained teal/cyan accents, compact technical typography, clear data density, and strong separation between navigation, target context, findings, and live activity.

The existing Textual application is a prototype only. This specification is for the future graphical frontend and must not be implemented by expanding the TUI.

## Core layout

- **Application shell:** persistent left navigation for Overview, Assets, Services, Assessments, Exploitation, Activity, Evidence, and Findings.
- **Top context bar:** active workspace, scope summary, integration connectivity, and global run status.
- **Main work area:** dense, sortable target/service tables and focused detail panels.
- **Activity drawer:** persistent, collapsible task feed showing current and recent operations.
- **Detail views:** evidence, technical metadata, confidence, provenance, and related actions without hiding the underlying target context.

## Task lifecycle visual language

Use one shared status component everywhere a task or execution appears. Status must be communicated by text and icon as well as color; never rely on color alone.

| State | Tone | Visual treatment | Motion |
| --- | --- | --- | --- |
| Queued | Neutral | Muted badge with clock/queue icon | None |
| Prepared | Informational | Blue badge with check-list icon | None |
| Dispatching | Active | Cyan badge and thin animated activity line | Subtle pulse |
| Running | Active | Teal badge, animated spinner, elapsed time, and progress bar when measurable | Continuous, low-amplitude |
| Cancelling | Warning | Amber badge with stop-progress treatment | Subtle pulse |
| Completed | Success | Green badge and check icon | Brief completion transition |
| Failed | Error | Red badge and error icon; expose concise failure reason | No looping animation |
| Timed out | Warning | Amber badge and timeout icon | None |
| Cancelled | Neutral | Grey badge and stop icon | None |
| Paused | Informational | Blue badge and pause icon | None |
| Dispatch uncertain | Critical attention | High-contrast amber/red outlined badge; explicit operator-review indicator | No decorative animation |

### Progress and activity rules

- Show percentage progress only when the underlying operation reports a meaningful measurable value. Do not fabricate percentages for Nmap, Metasploit, or other operations that expose only lifecycle state.
- When exact progress is unavailable, show an indeterminate animated bar or spinner, current phase, elapsed duration, and latest activity message.
- Distinguish task lifecycle from assessment outcome. A completed framework job is not a confirmed target-side exploit result.
- Display queued time, start time, elapsed time, and completion time where available.
- Keep recent task events in a chronological activity feed. Each event should include timestamp, severity, phase, and a concise message.
- Allow users to open task details for structured logs, target, scope, operation, and evidence references.
- Cancellation should visibly transition through Cancelling before reaching Cancelled; do not optimistically mark a task cancelled before the engine confirms it.
- Dispatch-uncertain executions must be visually distinct from ordinary failures and require reconciliation rather than retry.

## Motion and accessibility

- Use short transitions (roughly 120–200 ms) for badge, panel, and state changes.
- Keep running indicators subtle; avoid flashing, bouncing, or full-screen animation.
- Respect reduced-motion preferences and provide a static state indicator when motion is disabled.
- Maintain readable contrast and keyboard focus indicators.
- Pair every color with a text label and recognizable icon.
- Do not animate completed, failed, cancelled, or idle states continuously.

## Shared component contract

The frontend should implement reusable components rather than page-specific status styling:

- `StatusBadge`: state, label, icon, tone, and accessible text.
- `TaskProgress`: determinate or indeterminate progress, phase, elapsed time, and optional estimate only when supported by the backend.
- `ActivityFeed`: ordered task events with severity and timestamps.
- `TaskRow`: operation, target, state, phase, duration, and drill-down affordance.
- `ConnectionIndicator`: integration connectivity separate from task state.

The frontend must consume persisted job/execution states and structured events from application services. It must not infer success from a missing job, a closed connection, or a framework completion acknowledgement.

## Implementation boundary

This document establishes the visual and interaction contract only. The repository currently has a Python/Textual prototype and no graphical frontend. The next GUI implementation milestone must select and scaffold the graphical frontend, connect it to shared application services, and implement these shared status/activity components there. Do not claim these visuals are already present in the running application until that frontend exists and is exercised.
