# MSFAuto Roadmap

The roadmap prioritizes a dependable, explainable terminal workflow before
adding broader automation. Each stage must preserve explicit scope validation,
auditing, and safe defaults.

## Phase 1: Foundation — current

- [x] Interactive terminal startup
- [x] Initial Textual dashboard
- [x] SQLite workspace persistence
- [x] Explicit IP/CIDR scope
- [x] Optional port allowlists
- [x] Safe profile enforcement
- [x] Focused validation tests

## Phase 2: Discovery

- [x] Add a pluggable discovery adapter boundary
- [x] Normalize hosts, ports, services, and banners
- [x] Persist discovered hosts and services
- [x] Import scanner XML with scope enforcement
- [x] Add a bounded, no-shell scanner execution adapter
- [ ] Show live progress and recoverable failures
- [ ] Enforce scope and port policy for every operation

## Phase 3: Metasploit integration

- [x] Add a local Metasploit RPC adapter
- [x] Detect connection and dependency problems explicitly
- [x] Search and inspect module metadata
- [x] Validate module options without executing actions
- [x] Persist module metadata with workspace provenance

## Phase 4: Explainable planning

- [x] Correlate discovered services with relevant capabilities
- [x] Rank recommendations using deterministic evidence
- [x] Display prerequisites, confidence, and risk
- [x] Provide dry-run plans before execution
- [x] Preserve the underlying module and options for expert review

## Phase 5: Safe assessment checks

- [x] Add a controlled, scope-checked job manager boundary
- [x] Add cancellation and concurrency limits
- [x] Emit structured job events and explicit unsupported status
- [x] Stream persisted structured job output into the TUI view
- [x] Classify completed, failed, skipped, and unsupported checks
- [x] Store complete job audit events

## Phase 6: Approval-controlled actions

- [x] Add explicit `safe` and `dangerous-actions` profiles
- [ ] Add explicit approval queues
- [ ] Require per-action confirmation for intrusive operations
- [ ] Add policy profiles for isolated labs and controlled assessments
- [ ] Keep credential attacks, persistence, pivoting, and destructive actions
      disabled by default
- [ ] Add a reproducible action log

## Phase 7: Sessions, evidence, and reports

- [ ] Track sessions and their lifecycle
- [ ] Collect command output and assessment evidence
- [ ] Index loot and artifacts without exposing secrets unnecessarily
- [ ] Generate terminal, JSON, and Markdown reports
- [ ] Distinguish confirmed, possible, failed, and skipped findings

## Phase 8: Expert mode and extensibility

- [ ] Add searchable advanced module controls
- [ ] Support custom profiles and policy files
- [ ] Add discovery and reporting plugins
- [ ] Add plan import/export
- [ ] Provide a documented automation API

## Non-goals

MSFAuto will not silently attack arbitrary targets, bypass scope controls, or
hide the underlying operation from the operator. Automation is intended for
authorized environments such as owned systems, isolated labs, and explicitly
approved assessments.
