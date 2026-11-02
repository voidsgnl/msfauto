# MSFAuto

MSFAuto is a local, terminal-first orchestrator for authorized security
assessment workflows. It is designed to make complex tooling approachable
without hiding the scope, policy, or actions being requested.

## Current MVP

The initial slice provides:

- `msfauto` interactive startup
- Optional Textual dashboard with `--tui`
- SQLite-backed workspaces
- Explicit IP/CIDR scope
- Optional port allowlists
- A safe-only profile
- Scope-enforced discovery XML import and normalized service storage
- Read-only Metasploit RPC module metadata client
- Workspace-persisted module metadata and options
- Explainable dry-run plans with deterministic service matching
- Scope-checked bounded job manager with structured events
- Dashboard visibility for stored hosts, plans, jobs, and job events
- Bounded safe-check execution with status classification and persistence
- Explicit `safe` and `dangerous-actions` workspace profiles
- Scope validation tests

Discovery, Metasploit RPC integration, module planning, and execution are
intentionally not enabled yet.

## Run from source

```bash
cd msfauto
python -m msfauto.cli
```

On first launch, enter the authorized IP/CIDR targets and optional ports.
After saving them, the menu explains the next steps: import discovery results,
build a plan, run safe checks, or open the dashboard.

After creating a workspace, the interactive menu guides you through running
Nmap, building a plan, running safe checks, and opening the dashboard.

To open the dashboard directly:

```bash
python -m msfauto.cli --tui
```

Import an authorized Nmap XML result into an existing workspace:

```bash
python -m msfauto.cli --workspace lab --import-nmap scan.xml
```

Run Nmap automatically from the workspace's saved scope and import the XML:

```bash
python -m msfauto.cli --workspace lab --discover
```

Build and display a read-only plan from the workspace's stored services and
module metadata:

```bash
python -m msfauto.cli --workspace lab --show-plan
```

Run bounded non-invasive checks from the saved plan:

```bash
python -m msfauto.cli --workspace lab --run-safe-checks --max-checks 10 --check-workers 2
```

The default workspace database is stored at `~/.msfauto/workspaces.sqlite3`.
Set `MSFAUTO_HOME` to use another local directory.

New workspaces use the safe profile by default. To create a workspace with the
alternative profile:

```bash
python -m msfauto.cli --workspace lab --profile dangerous-actions
```

The `dangerous-actions` profile is an explicit policy selection and warning
boundary. It does not bypass scope validation or automatically execute
exploits, payloads, persistence, credential attacks, or destructive actions.

The MVP accepts only IP addresses and CIDR networks. It does not resolve or
scan arbitrary hostnames.

See [ROADMAP.md](ROADMAP.md) for the development plan.
