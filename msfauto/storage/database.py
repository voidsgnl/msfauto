from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from ipaddress import ip_address
from pathlib import Path

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
                    UNIQUE(workspace, address, port, protocol)
                )
                """
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
        with self._connect() as connection:
            for host in hosts:
                connection.execute(
                    """
                    INSERT INTO discovery_hosts(workspace, address, status, hostname)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(workspace, address) DO UPDATE SET
                        status = excluded.status,
                        hostname = excluded.hostname
                    """,
                    (workspace, str(host.address), host.status, host.hostname),
                )
                for service in host.services:
                    connection.execute(
                        """
                        INSERT INTO discovery_services(
                            workspace, address, port, protocol, state, name, product, version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(workspace, address, port, protocol) DO UPDATE SET
                            state = excluded.state,
                            name = excluded.name,
                            product = excluded.product,
                            version = excluded.version
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
                    SELECT port, protocol, state, name, product, version
                    FROM discovery_services
                    WHERE workspace = ? AND address = ?
                    ORDER BY port, protocol
                    """,
                    (workspace, row["address"]),
                ).fetchall()
                services = tuple(Service(**dict(service_row)) for service_row in service_rows)
                hosts.append(Host(ip_address(row["address"]), row["status"], row["hostname"], services))
        return tuple(hosts)

    def save_discovery_run(self, run: DiscoveryRun) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO discovery_runs(
                    workspace, scanner, command_json, output_path, status,
                    started_at, finished_at, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.workspace,
                    run.scanner,
                    json.dumps(run.command),
                    run.output_path,
                    run.status,
                    run.started_at,
                    run.finished_at,
                    run.error,
                ),
            )

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
