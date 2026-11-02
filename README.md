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
- Scope validation tests

Discovery, Metasploit RPC integration, module planning, and execution are
intentionally not enabled yet.

## Run from source

```bash
cd msfauto
python -m msfauto.cli
```

After creating a workspace, open the dashboard with:

```bash
python -m msfauto.cli --tui
```

Import an authorized Nmap XML result into an existing workspace:

```bash
python -m msfauto.cli --workspace lab --import-nmap scan.xml
```

Build and display a read-only plan from the workspace's stored services and
module metadata:

```bash
python -m msfauto.cli --workspace lab --show-plan
```

The default workspace database is stored at `~/.msfauto/workspaces.sqlite3`.
Set `MSFAUTO_HOME` to use another local directory.

The MVP accepts only IP addresses and CIDR networks. It does not resolve or
scan arbitrary hostnames.

See [ROADMAP.md](ROADMAP.md) for the development plan.
