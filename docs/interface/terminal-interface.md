# MSFAuto Terminal Interface

## Product direction

MSFAuto is a terminal-only security framework console. Its primary operator experience is a persistent command shell inspired by the interaction model of the Metasploit Framework console and the visual language of Fluxion. It is not a conventional widget-driven TUI, web application, or desktop GUI.

The startup screen is intentionally minimal: ASCII branding, workspace/profile/scope context, and the `msfauto >` prompt. The full command catalogue is displayed only when the operator enters `help`.

## Launch and interaction

- `msfauto` or `msfauto shell` opens the persistent interactive console.
- `msfauto --workspace lab` opens the console in a selected workspace.
- `help` displays the grouped command reference.
- Operators enter simple hierarchical commands such as `discovery run`, `plan show`, and `findings list`.
- Rich renders branding, tables, status messages, and operation output.
- prompt_toolkit provides the persistent input line, cursor editing, command completion, and interactive history.
- The existing one-shot CLI flags remain available for scripts and automation.

## Command catalogue

| Group | Commands |
| --- | --- |
| Workspace | `workspace create`, `workspace list`, `workspace show`, `workspace use` |
| Scope | `scope show`, `scope validate`, `scope update` |
| Discovery | `discovery run`, `discovery import <file.xml>`, `discovery show` |
| Planning | `plan build`, `plan show` |
| Checks | `checks list`, `checks review`, `checks approve`, `checks run` |
| Vulnerabilities | `vulnerabilities list`, `vulnerabilities show <id>` |
| Exploits | `exploits list`, `exploits review`, `exploits authorize` |
| Findings | `findings list`, `findings show <id>` |
| Reporting | `report generate [json|markdown]`, `report show` |
| General | `dashboard`, `help`, `exit` |

Commands that need additional values accept them after the command. For example, `workspace use lab`, `discovery import scan.xml`, and `vulnerabilities show <candidate-id>`.

## Visual language

- Fluxion-inspired terminal presentation with MSFAuto's own ASCII identity.
- Minimal startup screen; no permanent command catalogue or dashboard panels.
- Near-black terminal background with restrained cyan/teal accents.
- Clear section headers, separators, aligned tables, and concise status labels.
- Distinct success, warning, failure, and active-task colours; status is also communicated in text.
- Command output is rendered in the console and the prompt returns after each command.

## Long-running operations and authorization

- Discovery streams real workflow-stage messages and reports its actual terminal outcome.
- Do not display fabricated progress percentages when the engine exposes no measurable fraction.
- Passive checks continue to require exact, recorded approval before dispatch.
- Exploit review and action-specific authorization remain separate from exploit execution. A console command must not bypass persisted review, authorization, scope revalidation, or the controlled dispatcher.
- Dispatch uncertainty is a distinct state; uncertain operations must never be retried automatically.

## Current implementation boundaries

The command shell connects to existing workspace, scope, discovery, planning, check, vulnerability, exploit-intelligence, findings, and reporting services. Some catalogue entries are currently informational or reserved for guided workflows; the console reports this rather than pretending an unsupported action succeeded. In particular, exploit authorization is not synthesized from a generic command: it must use the existing opportunity-bound review and authorization lifecycle.

The previous Textual dashboard is no longer the primary application entry point. One-shot CLI options remain supported.
