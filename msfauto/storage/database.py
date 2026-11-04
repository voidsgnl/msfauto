from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from ipaddress import ip_address
from pathlib import Path

from ..exploitation.models import ExploitDefinition, ExploitOpportunity
from .models import (
    ActionApproval,
    AssessmentEvent,
    AssessmentPlan,
    AssessmentRun,
    CheckJob,
    DiscoveryRun,
    EvidenceRecord,
    Finding,
    Host,
    JobEvent,
    ModuleMetadata,
    Recommendation,
    Service,
    VulnerabilityCandidate,
    Workspace,
)


class WorkspaceStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workspaces (
                    name TEXT PRIMARY KEY,
                    policy_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS check_jobs (
                    job_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    error TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS job_events (
                    job_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_plans (
                    workspace TEXT PRIMARY KEY,
                    recommendations_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS module_metadata (
                    workspace TEXT NOT NULL,
                    module_type TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    PRIMARY KEY(workspace, module_type, module_name)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS discovery_runs (
                    workspace TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    command_json TEXT NOT NULL,
                    output_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    error TEXT NOT NULL
                )
                """
            )
            discovery_run_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(discovery_runs)")
            }
            if "scan_id" not in discovery_run_columns:
                connection.execute("ALTER TABLE discovery_runs ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_runs_scan_id "
                "ON discovery_runs(scan_id) WHERE scan_id <> ''"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS discovery_snapshots (
                    scan_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    hosts_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS discovery_hosts (
                    workspace TEXT NOT NULL,
                    address TEXT NOT NULL,
                    status TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    UNIQUE(workspace, address)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS discovery_services (
                    workspace TEXT NOT NULL,
                    address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    name TEXT NOT NULL,
                    product TEXT NOT NULL,
                    version TEXT NOT NULL,
                    method TEXT NOT NULL DEFAULT 'unknown',
                    confidence INTEGER NOT NULL DEFAULT 0,
                    extra_info TEXT NOT NULL DEFAULT '',
                    tunnel TEXT NOT NULL DEFAULT '',
                    cpes_json TEXT NOT NULL DEFAULT '[]',
                    source TEXT NOT NULL DEFAULT 'unknown',
                    observed_at TEXT NOT NULL DEFAULT '',
                    UNIQUE(workspace, address, port, protocol)
                )
                """
            )


            service_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(discovery_services)")
            }
            service_migrations = {
                "method": "TEXT NOT NULL DEFAULT 'unknown'",
                "confidence": "INTEGER NOT NULL DEFAULT 0",
                "extra_info": "TEXT NOT NULL DEFAULT ''",
                "tunnel": "TEXT NOT NULL DEFAULT ''",
                "cpes_json": "TEXT NOT NULL DEFAULT '[]'",
                "source": "TEXT NOT NULL DEFAULT 'unknown'",
                "observed_at": "TEXT NOT NULL DEFAULT ''",
            }
            for column, definition in service_migrations.items():
                if column not in service_columns:
                    connection.execute(
                        f"ALTER TABLE discovery_services ADD COLUMN {column} {definition}"
                    )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_approvals (
                    action_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    risk TEXT NOT NULL DEFAULT 'non-invasive',
                    decision TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    decided_at TEXT NOT NULL,
                    rationale TEXT NOT NULL
                )
                """
            )
            approval_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(action_approvals)")
            }
            if "risk" not in approval_columns:
                connection.execute(
                    "ALTER TABLE action_approvals ADD COLUMN risk TEXT NOT NULL DEFAULT 'non-invasive'"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    collected_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_runs (
                    run_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    error TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_events (
                    run_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assessment_run_plans (
                    run_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    recommendations_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS service_observations (
                    observation_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    transport TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    observed_at TEXT NOT NULL
                )
                """
            )
            observation_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(service_observations)")
            }
            if "discovery_run_id" not in observation_columns:
                connection.execute(
                    "ALTER TABLE service_observations ADD COLUMN discovery_run_id TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_service_observations_run "
                "ON service_observations(workspace, discovery_run_id, observed_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_opportunities (
                    opportunity_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    exploit_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    product TEXT NOT NULL,
                    observed_version TEXT NOT NULL,
                    matched_by_json TEXT NOT NULL,
                    vulnerability_candidate_ids_json TEXT NOT NULL,
                    rank TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    status TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    rationale TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_catalog (
                    workspace TEXT NOT NULL,
                    exploit_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    mapping_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    synced_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY(workspace, exploit_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_reviews (
                    review_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    opportunity_id TEXT NOT NULL,
                    review_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    opportunity_id TEXT NOT NULL,
                    authorization_json TEXT NOT NULL,
                    revoked_at TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_executions (
                    execution_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    state TEXT NOT NULL,
                    authorization_id TEXT NOT NULL DEFAULT '',
                    record_json TEXT NOT NULL
                )
                """
            )
            execution_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(exploit_executions)")
            }
            if "authorization_id" not in execution_columns:
                connection.execute(
                    "ALTER TABLE exploit_executions ADD COLUMN authorization_id TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_exploit_execution_authorization "
                "ON exploit_executions(authorization_id) WHERE authorization_id <> ''"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_execution_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    external_reference TEXT NOT NULL DEFAULT ''
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerability_advisories (
                    advisory_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    affected_versions_json TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    prerequisites_json TEXT NOT NULL,
                    evidence_requirements_json TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    product_aliases_json TEXT NOT NULL,
                    matched_versions_json TEXT NOT NULL,
                    affected_ranges_json TEXT NOT NULL,
                    aliases_json TEXT NOT NULL,
                    PRIMARY KEY(advisory_id, source, package_name, ecosystem)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerability_candidates (
                    candidate_id TEXT PRIMARY KEY, workspace TEXT NOT NULL,
                    target TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
                    advisory_id TEXT NOT NULL, advisory_source TEXT NOT NULL,
                    product TEXT NOT NULL, observed_version TEXT NOT NULL,
                    status TEXT NOT NULL, confidence INTEGER NOT NULL,
                    evidence_refs_json TEXT NOT NULL, rationale TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_vulnerability_candidates_workspace "
                "ON vulnerability_candidates(workspace, target, port)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_service_observations_workspace "
                "ON service_observations(workspace, target, port, observed_at)"
            )

    def save(self, workspace: Workspace) -> None:
        policy = {
            "networks": [str(item) for item in workspace.policy.networks],
            "addresses": [str(item) for item in workspace.policy.addresses],
            "allowed_ports": list(workspace.policy.allowed_ports),
            "profile": workspace.policy.profile,
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO workspaces(name, policy_json, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    policy_json = excluded.policy_json,
                    updated_at = excluded.updated_at
                """,
                (workspace.name, json.dumps(policy), workspace.created_at, workspace.updated_at),
            )

    def get(self, name: str) -> Workspace | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT name, policy_json, created_at, updated_at FROM workspaces WHERE name = ?",
                (name,),
            ).fetchone()
        if row is None:
            return None
        policy_data = json.loads(row["policy_json"])
        from ..scope import build_policy

        policy = build_policy(
            [*policy_data["networks"], *policy_data["addresses"]],
            ",".join(str(port) for port in policy_data["allowed_ports"]),
            policy_data["profile"],
        )
        return Workspace(
            name=row["name"],
            policy=policy,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def save_hosts(self, workspace: str, hosts: tuple[Host, ...]) -> None:
        """Replace the current workspace inventory with one completed discovery result.

        Historical scan contents remain available through discovery_snapshots; this
        table represents only the latest imported/current inventory.
        """
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM discovery_services WHERE workspace = ?",
                (workspace,),
            )
            connection.execute(
                "DELETE FROM discovery_hosts WHERE workspace = ?",
                (workspace,),
            )
            for host in hosts:
                connection.execute(
                    """
                    INSERT INTO discovery_hosts(workspace, address, status, hostname)
                    VALUES (?, ?, ?, ?)
                    """,
                    (workspace, str(host.address), host.status, host.hostname),
                )
                for service in host.services:
                    connection.execute(
                        """
                        INSERT INTO discovery_services(
                            workspace, address, port, protocol, state, name, product, version,
                            method, confidence, extra_info, tunnel, cpes_json, source, observed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            workspace,
                            str(host.address),
                            service.port,
                            service.protocol,
                            service.state,
                            service.name,
                            service.product,
                            service.version,
                            service.method,
                            service.confidence,
                            service.extra_info,
                            service.tunnel,
                            json.dumps(service.cpes),
                            service.source,
                            service.observed_at,
                        ),
                    )

    def get_hosts(self, workspace: str) -> tuple[Host, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT address, status, hostname FROM discovery_hosts WHERE workspace = ? ORDER BY address",
                (workspace,),
            ).fetchall()
            hosts: list[Host] = []
            for row in rows:
                service_rows = connection.execute(
                    """
                    SELECT port, protocol, state, name, product, version,
                           method, confidence, extra_info, tunnel, cpes_json,
                           source, observed_at
                    FROM discovery_services
                    WHERE workspace = ? AND address = ?
                    ORDER BY port, protocol
                    """,
                    (workspace, row["address"]),
                ).fetchall()
                services_list = []
                for service_row in service_rows:
                    service_data = dict(service_row)
                    service_data["cpes"] = tuple(json.loads(service_data.pop("cpes_json")))
                    services_list.append(Service(**service_data))
                services = tuple(services_list)
                hosts.append(Host(ip_address(row["address"]), row["status"], row["hostname"], services))
        return tuple(hosts)

    def save_service_observations(
        self, observations: tuple, discovery_run_id: str = ""
    ) -> None:
        """Append immutable protocol observations and associate them with their scan run."""
        with self._connect() as connection:
            for item in observations:
                connection.execute(
                    """
                    INSERT INTO service_observations(
                        observation_id, workspace, target, port, transport, protocol,
                        kind, status, attributes_json, source, confidence, observed_at,
                        discovery_run_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.observation_id, item.workspace, item.target, item.port,
                        item.transport, item.protocol, item.kind, item.status,
                        json.dumps(item.attributes, sort_keys=True), item.source,
                        item.confidence, item.observed_at, discovery_run_id,
                    ),
                )

    def get_service_observations(
        self, workspace: str, target: str | None = None,
        discovery_run_id: str | None = None,
    ) -> tuple:
        """Return newest-first observations, optionally filtered to a discovery run."""
        query = (
            "SELECT * FROM service_observations WHERE workspace = ?"
        )
        parameters: tuple = (workspace,)
        if target is not None:
            query += " AND target = ?"
            parameters += (target,)
        if discovery_run_id is not None:
            query += " AND discovery_run_id = ?"
            parameters += (discovery_run_id,)
        query += " ORDER BY observed_at DESC, observation_id DESC"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        from ..enumeration.models import ServiceObservation

        return tuple(
            ServiceObservation(
                observation_id=row["observation_id"],
                workspace=row["workspace"],
                target=row["target"],
                port=row["port"],
                transport=row["transport"],
                protocol=row["protocol"],
                kind=row["kind"],
                status=row["status"],
                attributes=json.loads(row["attributes_json"]),
                source=row["source"],
                confidence=row["confidence"],
                observed_at=row["observed_at"],
            )
            for row in rows
        )

    def save_vulnerability_candidates(
        self, candidates: tuple[VulnerabilityCandidate, ...]
    ) -> None:
        """Persist candidate matches without promoting them to confirmed findings."""
        with self._connect() as connection:
            for item in candidates:
                connection.execute(
                    """
                    INSERT INTO vulnerability_candidates(
                        candidate_id, workspace, target, port, protocol, advisory_id,
                        advisory_source, product, observed_version, status, confidence,
                        evidence_refs_json, rationale, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(candidate_id) DO UPDATE SET
                        advisory_source = excluded.advisory_source,
                        product = excluded.product,
                        observed_version = excluded.observed_version,
                        status = excluded.status, confidence = excluded.confidence,
                        evidence_refs_json = excluded.evidence_refs_json,
                        rationale = excluded.rationale
                    """,
                    (
                        item.candidate_id, item.workspace, item.target, item.port,
                        item.protocol, item.advisory_id, item.advisory_source,
                        item.product, item.observed_version, item.status,
                        item.confidence, json.dumps(item.evidence_refs),
                        item.rationale, item.created_at,
                    ),
                )

    def get_vulnerability_candidates(
        self, workspace: str
    ) -> tuple[VulnerabilityCandidate, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM vulnerability_candidates WHERE workspace = ? "
                "ORDER BY confidence DESC, target, port, advisory_id",
                (workspace,),
            ).fetchall()
        return tuple(VulnerabilityCandidate(
            candidate_id=row["candidate_id"], workspace=row["workspace"],
            target=row["target"], port=row["port"], protocol=row["protocol"],
            advisory_id=row["advisory_id"], advisory_source=row["advisory_source"],
            product=row["product"], observed_version=row["observed_version"],
            status=row["status"], confidence=row["confidence"],
            evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
            rationale=row["rationale"], created_at=row["created_at"],
        ) for row in rows)

    def save_vulnerability_advisories(
        self, advisories: tuple
    ) -> None:
        """Upsert normalized advisory intelligence with original source attribution."""
        with self._connect() as connection:
            for item in advisories:
                connection.execute(
                    """
                    INSERT INTO vulnerability_advisories(
                        advisory_id, source, vendor, product, affected_versions_json,
                        severity, description, references_json, prerequisites_json,
                        evidence_requirements_json, package_name, ecosystem,
                        product_aliases_json, matched_versions_json,
                        affected_ranges_json, aliases_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(advisory_id, source, package_name, ecosystem) DO UPDATE SET
                        vendor = excluded.vendor, product = excluded.product,
                        affected_versions_json = excluded.affected_versions_json,
                        severity = excluded.severity, description = excluded.description,
                        references_json = excluded.references_json,
                        prerequisites_json = excluded.prerequisites_json,
                        evidence_requirements_json = excluded.evidence_requirements_json,
                        product_aliases_json = excluded.product_aliases_json,
                        matched_versions_json = excluded.matched_versions_json,
                        affected_ranges_json = excluded.affected_ranges_json,
                        aliases_json = excluded.aliases_json
                    """,
                    (
                        item.advisory_id, item.source, item.vendor, item.product,
                        json.dumps(item.affected_versions), item.severity, item.description,
                        json.dumps(item.references), json.dumps(item.prerequisites),
                        json.dumps(item.evidence_requirements), item.package_name,
                        item.ecosystem, json.dumps(item.product_aliases),
                        json.dumps(item.matched_versions), json.dumps(item.affected_ranges),
                        json.dumps(item.aliases),
                    ),
                )

    def get_vulnerability_advisories(
        self, package_name: str | None = None, ecosystem: str | None = None
    ) -> tuple:
        query = "SELECT * FROM vulnerability_advisories WHERE 1 = 1"
        parameters: list[str] = []
        if package_name is not None:
            query += " AND package_name = ?"
            parameters.append(package_name)
        if ecosystem is not None:
            query += " AND ecosystem = ?"
            parameters.append(ecosystem)
        query += " ORDER BY advisory_id, source"
        with self._connect() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        from .models import VulnerabilityAdvisory

        json_fields = (
            "affected_versions", "references", "prerequisites",
            "evidence_requirements", "product_aliases", "matched_versions",
            "affected_ranges", "aliases",
        )
        result = []
        for row in rows:
            values = dict(row)
            for field in json_fields:
                values[field] = tuple(json.loads(values.pop(f"{field}_json")))
            result.append(VulnerabilityAdvisory(**values))
        return tuple(result)

    def save_discovery_run(
        self, run: DiscoveryRun, hosts: tuple[Host, ...] = ()
    ) -> None:
        """Persist scan metadata and an immutable normalized host/service snapshot."""
        snapshot = [
            {
                "address": str(host.address),
                "status": host.status,
                "hostname": host.hostname,
                "services": [
                    {
                        "port": service.port,
                        "protocol": service.protocol,
                        "state": service.state,
                        "name": service.name,
                        "product": service.product,
                        "version": service.version,
                        "method": service.method,
                        "confidence": service.confidence,
                        "extra_info": service.extra_info,
                        "tunnel": service.tunnel,
                        "cpes": list(service.cpes),
                        "source": service.source,
                        "observed_at": service.observed_at,
                    }
                    for service in host.services
                ],
            }
            for host in hosts
        ]
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO discovery_runs(
                    workspace, scanner, command_json, output_path, status,
                    started_at, finished_at, error, scan_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.workspace, run.scanner, json.dumps(run.command),
                    run.output_path, run.status, run.started_at,
                    run.finished_at, run.error, run.scan_id,
                ),
            )
            connection.execute(
                "INSERT INTO discovery_snapshots(scan_id, workspace, hosts_json) VALUES (?, ?, ?)",
                (run.scan_id, run.workspace, json.dumps(snapshot, sort_keys=True)),
            )

    def get_discovery_runs(self, workspace: str) -> tuple[DiscoveryRun, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scanner, command_json, output_path, status, started_at,
                       finished_at, error, scan_id
                FROM discovery_runs WHERE workspace = ?
                ORDER BY started_at DESC, rowid DESC
                """,
                (workspace,),
            ).fetchall()
        return tuple(
            DiscoveryRun(
                workspace=workspace,
                scanner=row["scanner"],
                command=tuple(json.loads(row["command_json"])),
                output_path=row["output_path"],
                status=row["status"],
                started_at=row["started_at"],
                finished_at=row["finished_at"],
                error=row["error"],
                scan_id=row["scan_id"] or f"legacy-{index}",
            )
            for index, row in enumerate(rows, 1)
        )

    def compare_discovery_runs(
        self, workspace: str, older_scan_id: str, newer_scan_id: str
    ) -> dict[str, list[tuple[str, str]]]:
        """Compare immutable normalized snapshots; services key on address/port/protocol."""
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT snapshots.scan_id, snapshots.hosts_json
                FROM discovery_snapshots AS snapshots
                JOIN discovery_runs AS runs ON runs.scan_id = snapshots.scan_id
                WHERE snapshots.workspace = ? AND snapshots.scan_id IN (?, ?)
                  AND runs.status = 'completed'
                """,
                (workspace, older_scan_id, newer_scan_id),
            ).fetchall()
        snapshots = {row["scan_id"]: json.loads(row["hosts_json"]) for row in rows}
        if older_scan_id not in snapshots or newer_scan_id not in snapshots:
            raise ValueError("Both completed scan snapshots must exist in the active workspace.")
        def host_index(snapshot: list[dict[str, object]]) -> dict[str, str]:
            return {
                str(host["address"]): (
                    f"status={host['status']} hostname={host['hostname'] or '—'}"
                )
                for host in snapshot
            }

        def service_index(snapshot: list[dict[str, object]]) -> dict[tuple[str, int, str], str]:
            result: dict[tuple[str, int, str], str] = {}
            for host in snapshot:
                address = str(host["address"])
                for service in host["services"]:
                    key = (address, int(service["port"]), str(service["protocol"]))
                    fingerprint = " ".join(
                        str(service[field]) for field in ("state", "name", "product", "version")
                    ).strip()
                    result[key] = fingerprint
            return result

        old_hosts = host_index(snapshots[older_scan_id])
        new_hosts = host_index(snapshots[newer_scan_id])
        added_hosts = [(address, new_hosts[address]) for address in sorted(new_hosts.keys() - old_hosts.keys())]
        removed_hosts = [(address, old_hosts[address]) for address in sorted(old_hosts.keys() - new_hosts.keys())]
        changed_hosts = [
            (address, f"{old_hosts[address]} -> {new_hosts[address]}")
            for address in sorted(old_hosts.keys() & new_hosts.keys())
            if old_hosts[address] != new_hosts[address]
        ]

        old = service_index(snapshots[older_scan_id])
        new = service_index(snapshots[newer_scan_id])
        added = [(f"{key[0]}:{key[1]}/{key[2]}", new[key]) for key in sorted(new.keys() - old.keys())]
        removed = [(f"{key[0]}:{key[1]}/{key[2]}", old[key]) for key in sorted(old.keys() - new.keys())]
        changed = [
            (f"{key[0]}:{key[1]}/{key[2]}", f"{old[key]} -> {new[key]}")
            for key in sorted(old.keys() & new.keys()) if old[key] != new[key]
        ]
        return {
            "added_hosts": added_hosts,
            "removed_hosts": removed_hosts,
            "changed_hosts": changed_hosts,
            "added": added,
            "removed": removed,
            "changed": changed,
        }

    def save_module_metadata(self, module: ModuleMetadata) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO module_metadata(
                    workspace, module_type, module_name, metadata_json,
                    options_json, source, fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace, module_type, module_name) DO UPDATE SET
                    metadata_json = excluded.metadata_json,
                    options_json = excluded.options_json,
                    source = excluded.source,
                    fetched_at = excluded.fetched_at
                """,
                (
                    module.workspace,
                    module.module_type,
                    module.module_name,
                    json.dumps(module.metadata, sort_keys=True),
                    json.dumps(module.options, sort_keys=True),
                    module.source,
                    module.fetched_at,
                ),
            )

    def get_module_metadata(
        self, workspace: str, module_type: str, module_name: str
    ) -> ModuleMetadata | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT workspace, module_type, module_name, metadata_json,
                       options_json, source, fetched_at
                FROM module_metadata
                WHERE workspace = ? AND module_type = ? AND module_name = ?
                """,
                (workspace, module_type, module_name),
            ).fetchone()
        if row is None:
            return None
        return ModuleMetadata(
            workspace=row["workspace"],
            module_type=row["module_type"],
            module_name=row["module_name"],
            metadata=json.loads(row["metadata_json"]),
            options=json.loads(row["options_json"]),
            source=row["source"],
            fetched_at=row["fetched_at"],
        )

    def get_all_module_metadata(self, workspace: str) -> tuple[ModuleMetadata, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT workspace, module_type, module_name, metadata_json,
                       options_json, source, fetched_at
                FROM module_metadata
                WHERE workspace = ?
                ORDER BY module_type, module_name
                """,
                (workspace,),
            ).fetchall()
        return tuple(
            ModuleMetadata(
                workspace=row["workspace"],
                module_type=row["module_type"],
                module_name=row["module_name"],
                metadata=json.loads(row["metadata_json"]),
                options=json.loads(row["options_json"]),
                source=row["source"],
                fetched_at=row["fetched_at"],
            )
            for row in rows
        )

    def save_plan(self, plan: AssessmentPlan) -> None:
        recommendations = [
            {
                "target": item.target,
                "port": item.port,
                "protocol": item.protocol,
                "module_type": item.module_type,
                "module_name": item.module_name,
                "confidence": item.confidence,
                "reason": item.reason,
                "risk": item.risk,
            }
            for item in plan.recommendations
        ]
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO assessment_plans(workspace, recommendations_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(workspace) DO UPDATE SET
                    recommendations_json = excluded.recommendations_json,
                    created_at = excluded.created_at
                """,
                (plan.workspace, json.dumps(recommendations, sort_keys=True), plan.created_at),
            )

    def get_plan(self, workspace: str) -> AssessmentPlan | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT workspace, recommendations_json, created_at FROM assessment_plans WHERE workspace = ?",
                (workspace,),
            ).fetchone()
        if row is None:
            return None
        recommendations = tuple(
            Recommendation(**item) for item in json.loads(row["recommendations_json"])
        )
        return AssessmentPlan(row["workspace"], recommendations, row["created_at"])

    def save_run_plan(self, run_id: str, plan: AssessmentPlan) -> None:
        """Persist an immutable plan snapshot belonging to one assessment run."""
        recommendations = [
            {
                "target": item.target,
                "port": item.port,
                "protocol": item.protocol,
                "module_type": item.module_type,
                "module_name": item.module_name,
                "confidence": item.confidence,
                "reason": item.reason,
                "risk": item.risk,
            }
            for item in plan.recommendations
        ]
        with self._connect() as connection:
            run = connection.execute(
                "SELECT workspace FROM assessment_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise ValueError(f"Assessment run not found: {run_id}")
            if run["workspace"] != plan.workspace:
                raise ValueError("Assessment plan workspace does not match its run.")
            connection.execute(
                """
                INSERT INTO assessment_run_plans(
                    run_id, workspace, recommendations_json, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    run_id,
                    plan.workspace,
                    json.dumps(recommendations, sort_keys=True),
                    plan.created_at,
                ),
            )

    def get_run_plan(self, run_id: str) -> AssessmentPlan | None:
        """Return the immutable plan snapshot for an assessment run."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT workspace, recommendations_json, created_at
                FROM assessment_run_plans WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        recommendations = tuple(
            Recommendation(**item) for item in json.loads(row["recommendations_json"])
        )
        return AssessmentPlan(row["workspace"], recommendations, row["created_at"])

    def save_job(self, job: CheckJob) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO check_jobs(
                    job_id, workspace, target, port, protocol, module_name,
                    status, started_at, finished_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(job.__dict__.values()),
            )

    def save_job_event(self, event: JobEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO job_events(job_id, timestamp, level, message) VALUES (?, ?, ?, ?)",
                (event.job_id, event.timestamp, event.level, event.message),
            )

    def get_jobs(self, workspace: str) -> tuple[CheckJob, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT job_id, workspace, target, port, protocol, module_name,
                       status, started_at, finished_at, error
                FROM check_jobs
                WHERE workspace = ?
                ORDER BY started_at DESC
                """,
                (workspace,),
            ).fetchall()
        return tuple(CheckJob(**dict(row)) for row in rows)

    def get_job_events(self, job_id: str) -> tuple[JobEvent, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT job_id, timestamp, level, message
                FROM job_events
                WHERE job_id = ?
                ORDER BY timestamp
                """,
                (job_id,),
            ).fetchall()
        return tuple(JobEvent(**dict(row)) for row in rows)

    def save_approval(self, approval: ActionApproval) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO action_approvals(
                    action_id, workspace, target, port, protocol, module_name,
                    risk, decision, approver, decided_at, rationale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(action_id) DO UPDATE SET
                    decision = excluded.decision,
                    approver = excluded.approver,
                    decided_at = excluded.decided_at,
                    rationale = excluded.rationale,
                    risk = excluded.risk
                """,
                (
                    approval.action_id, approval.workspace, approval.target,
                    approval.port, approval.protocol, approval.module_name,
                    approval.risk, approval.decision, approval.approver,
                    approval.decided_at, approval.rationale,
                ),
            )

    def get_approval(self, action_id: str) -> ActionApproval | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM action_approvals WHERE action_id = ?", (action_id,)
            ).fetchone()
        return ActionApproval(**dict(row)) if row is not None else None

    def get_approvals(self, workspace: str) -> tuple[ActionApproval, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM action_approvals WHERE workspace = ? ORDER BY decided_at",
                (workspace,),
            ).fetchall()
        return tuple(ActionApproval(**dict(row)) for row in rows)

    def save_evidence(self, evidence: EvidenceRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence_records(
                    evidence_id, workspace, source, target, evidence_type,
                    summary, artifact_path, sha256, size_bytes, collected_at,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(evidence_id) DO UPDATE SET
                    summary = excluded.summary,
                    artifact_path = excluded.artifact_path,
                    sha256 = excluded.sha256,
                    size_bytes = excluded.size_bytes,
                    metadata_json = excluded.metadata_json
                """,
                (
                    evidence.evidence_id, evidence.workspace, evidence.source,
                    evidence.target, evidence.evidence_type, evidence.summary,
                    evidence.artifact_path, evidence.sha256, evidence.size_bytes,
                    evidence.collected_at,
                    json.dumps(evidence.metadata, sort_keys=True),
                ),
            )

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence_records WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["metadata"] = json.loads(data.pop("metadata_json"))
        return EvidenceRecord(**data)

    def get_evidence_records(self, workspace: str) -> tuple[EvidenceRecord, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence_records WHERE workspace = ? ORDER BY collected_at",
                (workspace,),
            ).fetchall()
        records = []
        for row in rows:
            data = dict(row)
            data["metadata"] = json.loads(data.pop("metadata_json"))
            records.append(EvidenceRecord(**data))
        return tuple(records)

    def save_finding(self, finding: Finding) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO findings(
                    finding_id, workspace, title, description, severity, status,
                    confidence, evidence_ids_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    title = excluded.title,
                    description = excluded.description,
                    severity = excluded.severity,
                    status = excluded.status,
                    confidence = excluded.confidence,
                    evidence_ids_json = excluded.evidence_ids_json,
                    updated_at = excluded.updated_at
                """,
                (
                    finding.finding_id, finding.workspace, finding.title,
                    finding.description, finding.severity, finding.status,
                    finding.confidence, json.dumps(finding.evidence_ids),
                    finding.created_at, finding.updated_at,
                ),
            )

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["evidence_ids"] = tuple(json.loads(data.pop("evidence_ids_json")))
        return Finding(**data)

    def get_findings(self, workspace: str) -> tuple[Finding, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE workspace = ? ORDER BY updated_at DESC",
                (workspace,),
            ).fetchall()
        findings = []
        for row in rows:
            data = dict(row)
            data["evidence_ids"] = tuple(json.loads(data.pop("evidence_ids_json")))
            findings.append(Finding(**data))
        return tuple(findings)

    def save_assessment_run(self, run: AssessmentRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO assessment_runs(
                    run_id, workspace, status, stage, started_at, updated_at,
                    finished_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    stage = excluded.stage,
                    updated_at = excluded.updated_at,
                    finished_at = excluded.finished_at,
                    error = excluded.error
                """,
                (
                    run.run_id, run.workspace, run.status, run.stage,
                    run.started_at, run.updated_at, run.finished_at, run.error,
                ),
            )

    def get_assessment_run(self, run_id: str) -> AssessmentRun | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM assessment_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return AssessmentRun(**dict(row)) if row is not None else None

    def get_assessment_runs(self, workspace: str) -> tuple[AssessmentRun, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assessment_runs WHERE workspace = ? ORDER BY started_at DESC",
                (workspace,),
            ).fetchall()
        return tuple(AssessmentRun(**dict(row)) for row in rows)

    def save_assessment_event(self, event: AssessmentEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO assessment_events(run_id, timestamp, stage, level, message)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event.run_id, event.timestamp, event.stage, event.level, event.message),
            )

    def get_assessment_events(self, run_id: str) -> tuple[AssessmentEvent, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT run_id, timestamp, stage, level, message
                FROM assessment_events WHERE run_id = ? ORDER BY timestamp
                """,
                (run_id,),
            ).fetchall()
        return tuple(AssessmentEvent(**dict(row)) for row in rows)


    def save_exploit_opportunities(
        self, opportunities: tuple[ExploitOpportunity, ...]
    ) -> None:
        """Persist exploit applicability leads without implying approval or execution."""
        with self._connect() as connection:
            for item in opportunities:
                connection.execute(
                    """
                    INSERT INTO exploit_opportunities(
                        opportunity_id, workspace, exploit_id, source, module_name,
                        target, port, protocol, product, observed_version,
                        matched_by_json, vulnerability_candidate_ids_json, rank, risk,
                        status, confidence, rationale, references_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(opportunity_id) DO UPDATE SET
                        source = excluded.source,
                        module_name = excluded.module_name,
                        matched_by_json = excluded.matched_by_json,
                        vulnerability_candidate_ids_json = excluded.vulnerability_candidate_ids_json,
                        rank = excluded.rank, risk = excluded.risk,
                        confidence = excluded.confidence,
                        rationale = excluded.rationale,
                        references_json = excluded.references_json
                    """,
                    (
                        item.opportunity_id, item.workspace, item.exploit_id,
                        item.source, item.module_name, item.target, item.port,
                        item.protocol, item.product, item.observed_version,
                        json.dumps(item.matched_by),
                        json.dumps(item.vulnerability_candidate_ids),
                        item.rank, item.risk, item.status, item.confidence,
                        item.rationale, json.dumps(item.references), item.created_at,
                    ),
                )

    def get_exploit_opportunities(
        self, workspace: str
    ) -> tuple[ExploitOpportunity, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM exploit_opportunities
                WHERE workspace = ?
                ORDER BY confidence DESC, target, port, exploit_id
                """,
                (workspace,),
            ).fetchall()
        return tuple(
            ExploitOpportunity(
                opportunity_id=row["opportunity_id"],
                workspace=row["workspace"],
                exploit_id=row["exploit_id"],
                source=row["source"],
                module_name=row["module_name"],
                target=row["target"],
                port=row["port"],
                protocol=row["protocol"],
                product=row["product"],
                observed_version=row["observed_version"],
                matched_by=tuple(json.loads(row["matched_by_json"])),
                vulnerability_candidate_ids=tuple(
                    json.loads(row["vulnerability_candidate_ids_json"])
                ),
                rank=row["rank"],
                risk=row["risk"],
                status=row["status"],
                confidence=row["confidence"],
                rationale=row["rationale"],
                references=tuple(json.loads(row["references_json"])),
                created_at=row["created_at"],
            )
            for row in rows
        )


    def save_exploit_review(self, review) -> None:
        """Persist an explicit human decision for one exact exploit opportunity."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO exploit_reviews(review_id, workspace, opportunity_id, review_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    review.review_id, review.workspace, review.opportunity_id,
                    json.dumps(asdict(review), sort_keys=True),
                ),
            )

    def get_exploit_review(self, review_id: str):
        from ..exploitation.authorization import ExploitReview

        with self._connect() as connection:
            row = connection.execute(
                "SELECT review_json FROM exploit_reviews WHERE review_id = ?",
                (review_id,),
            ).fetchone()
        return ExploitReview(**json.loads(row["review_json"])) if row else None

    def get_exploit_reviews(self, workspace: str):
        from ..exploitation.authorization import ExploitReview

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT review_json FROM exploit_reviews WHERE workspace = ? ORDER BY rowid",
                (workspace,),
            ).fetchall()
        return tuple(ExploitReview(**json.loads(row["review_json"])) for row in rows)

    def save_exploit_authorization(self, authorization) -> None:
        """Persist a short-lived authorization bound to one exploit opportunity."""
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO exploit_authorizations(
                    authorization_id, workspace, opportunity_id, authorization_json,
                    revoked_at
                ) VALUES (?, ?, ?, ?, '')
                """,
                (
                    authorization.authorization_id,
                    authorization.workspace,
                    authorization.opportunity_id,
                    json.dumps(asdict(authorization), sort_keys=True),
                ),
            )

    def get_exploit_authorization(self, authorization_id: str):
        from ..exploitation.authorization import ExploitAuthorization

        with self._connect() as connection:
            row = connection.execute(
                "SELECT authorization_json, revoked_at FROM exploit_authorizations "
                "WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        if row is None:
            return None
        data = json.loads(row["authorization_json"])
        data["revoked"] = bool(row["revoked_at"])
        return ExploitAuthorization(**data)

    def get_exploit_authorizations(self, workspace: str):
        from ..exploitation.authorization import ExploitAuthorization

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT authorization_json, revoked_at FROM exploit_authorizations "
                "WHERE workspace = ? ORDER BY rowid",
                (workspace,),
            ).fetchall()
        records = []
        for row in rows:
            data = json.loads(row["authorization_json"])
            data["revoked"] = bool(row["revoked_at"])
            records.append(ExploitAuthorization(**data))
        return tuple(records)

    def revoke_exploit_authorization(self, authorization_id: str, revoked_at: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE exploit_authorizations SET revoked_at = ? "
                "WHERE authorization_id = ? AND revoked_at = ''",
                (revoked_at, authorization_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Active exploit authorization not found: {authorization_id}")

    def create_exploit_execution(self, record, event) -> None:
        """Create an execution record and its initial event atomically."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO exploit_executions("
                "execution_id, workspace, state, authorization_id, record_json"
                ") VALUES (?, ?, ?, ?, ?)",
                (
                    record.execution_id, record.workspace, record.state,
                    record.authorization_id,
                    json.dumps(asdict(record), sort_keys=True),
                ),
            )
            connection.execute(
                """
                INSERT INTO exploit_execution_events(
                    execution_id, timestamp, from_state, to_state, actor, detail,
                    external_reference
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.execution_id, event.timestamp, event.from_state,
                    event.to_state, event.actor, event.detail, event.external_reference,
                ),
            )

    def get_exploit_execution(self, execution_id: str):
        from ..execution.lifecycle import ExploitExecution

        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM exploit_executions WHERE execution_id = ?",
                (execution_id,),
            ).fetchone()
        return ExploitExecution(**json.loads(row["record_json"])) if row else None

    def get_exploit_executions(
        self, workspace: str = "", states: tuple[str, ...] = ()
    ):
        from ..execution.lifecycle import ExploitExecution

        query = "SELECT record_json FROM exploit_executions"
        clauses = []
        parameters: list[str] = []
        if workspace:
            clauses.append("workspace = ?")
            parameters.append(workspace)
        if states:
            placeholders = ", ".join("?" for _ in states)
            clauses.append(f"state IN ({placeholders})")
            parameters.extend(states)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY rowid"
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(ExploitExecution(**json.loads(row["record_json"])) for row in rows)

    def get_exploit_execution_events(self, execution_id: str):
        from ..execution.lifecycle import ExploitExecutionEvent

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT execution_id, timestamp, from_state, to_state, actor, detail,
                       external_reference
                FROM exploit_execution_events
                WHERE execution_id = ? ORDER BY event_id
                """,
                (execution_id,),
            ).fetchall()
        return tuple(ExploitExecutionEvent(**dict(row)) for row in rows)

    def transition_exploit_execution(self, record, expected_state: str, event) -> None:
        """Optimistically update one lifecycle state and append its event atomically."""
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE exploit_executions
                SET state = ?, record_json = ?
                WHERE execution_id = ? AND state = ?
                """,
                (
                    record.state,
                    json.dumps(asdict(record), sort_keys=True),
                    record.execution_id,
                    expected_state,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError(
                    "Execution state changed concurrently; reload it before transitioning."
                )
            connection.execute(
                """
                INSERT INTO exploit_execution_events(
                    execution_id, timestamp, from_state, to_state, actor, detail,
                    external_reference
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.execution_id, event.timestamp, event.from_state,
                    event.to_state, event.actor, event.detail, event.external_reference,
                ),
            )

    def sync_exploit_catalog(
        self,
        workspace: str,
        definitions: tuple[ExploitDefinition, ...],
        synced_at: str,
    ) -> int:
        """Refresh source metadata while preserving existing operator identity mappings.

        Mapping changes are intentionally handled by update_exploit_catalog_mapping(),
        not by a remote metadata refresh.
        """
        if not definitions:
            return 0
        mapping_fields = {"product_aliases", "affected_versions", "advisory_ids"}
        with self._connect() as connection:
            sources = {item.source for item in definitions}
            for source in sources:
                connection.execute(
                    "UPDATE exploit_catalog SET is_active = 0 WHERE workspace = ? AND source = ?",
                    (workspace, source),
                )
            for item in definitions:
                data = asdict(item)
                mapping = {
                    key: list(data.pop(key))
                    for key in mapping_fields
                }
                metadata = data
                connection.execute(
                    """
                    INSERT INTO exploit_catalog(
                        workspace, exploit_id, source, module_name,
                        mapping_json, metadata_json, synced_at, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(workspace, exploit_id) DO UPDATE SET
                        source = excluded.source,
                        module_name = excluded.module_name,
                        metadata_json = excluded.metadata_json,
                        synced_at = excluded.synced_at,
                        is_active = 1
                    """,
                    (
                        workspace,
                        item.exploit_id,
                        item.source,
                        item.module_name,
                        json.dumps(mapping),
                        json.dumps(metadata),
                        synced_at,
                    ),
                )
        return len(definitions)

    def get_exploit_catalog(
        self, workspace: str
    ) -> tuple[ExploitDefinition, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM exploit_catalog
                WHERE workspace = ? AND is_active = 1
                ORDER BY source, module_name
                """,
                (workspace,),
            ).fetchall()
        definitions = []
        for row in rows:
            mapping = json.loads(row["mapping_json"])
            metadata = json.loads(row["metadata_json"])
            for key in (
                "platforms", "architectures", "targets", "prerequisites",
                "required_options", "references",
            ):
                metadata[key] = tuple(metadata.get(key, ()))
            definitions.append(
                ExploitDefinition(
                    **metadata,
                    product_aliases=tuple(mapping["product_aliases"]),
                    affected_versions=tuple(mapping["affected_versions"]),
                    advisory_ids=tuple(mapping["advisory_ids"]),
                )
            )
        return tuple(definitions)

    def update_exploit_catalog_mapping(
        self,
        workspace: str,
        exploit_id: str,
        product_aliases: tuple[str, ...],
        affected_versions: tuple[str, ...],
        advisory_ids: tuple[str, ...] = (),
    ) -> None:
        """Explicitly update operator-controlled applicability mappings."""
        if not product_aliases:
            raise ValueError("At least one explicit product alias is required.")
        if not affected_versions and not advisory_ids:
            raise ValueError("Affected versions or advisory IDs are required.")
        mapping = {
            "product_aliases": list(product_aliases),
            "affected_versions": list(affected_versions),
            "advisory_ids": list(advisory_ids),
        }
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE exploit_catalog SET mapping_json = ?
                WHERE workspace = ? AND exploit_id = ? AND is_active = 1
                """,
                (json.dumps(mapping), workspace, exploit_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Active exploit catalog entry not found: {exploit_id}")
