from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..evidence import EvidenceCollector


_SECRET_KEY = re.compile(r"(password|passwd|secret|token|credential|authorization|api[_-]?key)", re.I)
_SECRET_TEXT = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*([:=])\s*([^\s,;]+)")


class ReportError(ValueError):
    """Raised when a report format or destination is invalid."""


def _redact(value: Any, key: str = "") -> Any:
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _SECRET_TEXT.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value)
    return value


def build_report(store, workspace: str) -> dict[str, Any]:
    saved_workspace = store.get(workspace)
    if saved_workspace is None:
        raise ReportError(f"Workspace not found: {workspace}")
    collector = EvidenceCollector(store)
    evidence = [
        {
            "evidence_id": item.evidence_id,
            "source": item.source,
            "target": item.target,
            "evidence_type": item.evidence_type,
            "summary": item.summary,
            "sha256": item.sha256,
            "size_bytes": item.size_bytes,
            "collected_at": item.collected_at,
            "metadata": item.metadata,
            "integrity": "verified" if collector.verify(item) else "failed",
        }
        for item in store.get_evidence_records(workspace)
    ]
    hosts = [
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
                }
                for service in host.services
            ],
        }
        for host in store.get_hosts(workspace)
    ]
    jobs = [
        {
            "job_id": job.job_id,
            "target": job.target,
            "port": job.port,
            "protocol": job.protocol,
            "module_name": job.module_name,
            "status": job.status,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
        }
        for job in store.get_jobs(workspace)
    ]
    findings = [
        {
            "finding_id": item.finding_id,
            "title": item.title,
            "description": item.description,
            "severity": item.severity,
            "status": item.status,
            "confidence": item.confidence,
            "evidence_ids": list(item.evidence_ids),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }
        for item in store.get_findings(workspace)
    ]
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": {
            "name": saved_workspace.name,
            "created_at": saved_workspace.created_at,
            "updated_at": saved_workspace.updated_at,
            "scope": {
                "networks": [str(item) for item in saved_workspace.policy.networks],
                "addresses": [str(item) for item in saved_workspace.policy.addresses],
                "allowed_ports": list(saved_workspace.policy.allowed_ports),
                "profile": saved_workspace.policy.profile,
            },
        },
        "summary": {
            "hosts": len(hosts),
            "services": sum(len(host["services"]) for host in hosts),
            "jobs": len(jobs),
            "findings": len(findings),
            "evidence_records": len(evidence),
            "evidence_integrity_failures": sum(item["integrity"] == "failed" for item in evidence),
        },
        "hosts": hosts,
        "jobs": jobs,
        "findings": findings,
        "evidence": evidence,
    }
    return _redact(report)


def _markdown(report: dict[str, Any]) -> str:
    workspace = report["workspace"]
    summary = report["summary"]
    lines = [
        f"# Assessment report: {workspace['name']}",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Scope profile: {workspace['scope']['profile']}",
        f"- Authorized networks: {', '.join(workspace['scope']['networks']) or 'None'}",
        f"- Authorized addresses: {', '.join(workspace['scope']['addresses']) or 'None'}",
        f"- Allowed ports: {', '.join(map(str, workspace['scope']['allowed_ports'])) or 'All ports'}",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    for key, label in (
        ("hosts", "Hosts"), ("services", "Services"), ("jobs", "Execution jobs"),
        ("findings", "Findings"), ("evidence_records", "Evidence records"),
        ("evidence_integrity_failures", "Evidence integrity failures"),
    ):
        lines.append(f"| {label} | {summary[key]} |")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings have been recorded.")
    for finding in report["findings"]:
        lines.extend([
            f"### {finding['title']}", "",
            f"- Severity: {finding['severity']}",
            f"- Status: {finding['status']}",
            f"- Confidence: {finding['confidence']}%",
            f"- Evidence: {', '.join(finding['evidence_ids']) or 'None'}", "",
            finding["description"], "",
        ])
    lines.extend(["## Discovered assets", ""])
    if not report["hosts"]:
        lines.append("No hosts have been recorded.")
    for host in report["hosts"]:
        lines.append(f"### {host['address']} ({host['status']})")
        if host["hostname"]:
            lines.append(f"Hostname: {host['hostname']}")
        if not host["services"]:
            lines.append("No services recorded.")
        for service in host["services"]:
            product = " ".join(part for part in (service["product"], service["version"]) if part)
            lines.append(
                f"- {service['port']}/{service['protocol']} {service['state']} "
                f"{service['name']} {product}".rstrip()
            )
        lines.append("")
    lines.extend(["## Execution jobs", ""])
    if not report["jobs"]:
        lines.append("No execution jobs have been recorded.")
    for job in report["jobs"]:
        lines.append(
            f"- {job['status']}: {job['target']}:{job['port']}/{job['protocol']} "
            f"({job['module_name']}) — {job['job_id']}"
        )
    lines.extend(["", "## Evidence register", ""])
    if not report["evidence"]:
        lines.append("No evidence records have been collected.")
    else:
        lines.extend([
            "| Evidence ID | Type | Target | Integrity | SHA-256 |",
            "| --- | --- | --- | --- | --- |",
        ])
        for item in report["evidence"]:
            lines.append(
                f"| {item['evidence_id']} | {item['evidence_type']} | {item['target']} "
                f"| {item['integrity']} | {item['sha256']} |"
            )
    lines.extend([
        "",
        "> Execution outcomes and service observations are not, by themselves, proof of a vulnerability. "
        "Finding status reflects analyst review.",
        "",
    ])
    return "\n".join(lines)


def write_report(store, workspace: str, output_format: str, output_path: Path | None = None) -> Path:
    if output_format not in {"json", "markdown"}:
        raise ReportError(f"Unsupported report format: {output_format}")
    report = build_report(store, workspace)
    extension = "json" if output_format == "json" else "md"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_workspace = re.sub(r"[^A-Za-z0-9_-]+", "_", workspace).strip("_") or "workspace"
    destination = output_path or (
        store.path.parent / "reports" / f"{safe_workspace}-{timestamp}.{extension}"
    )
    if destination.suffix.lower() != f".{extension}":
        raise ReportError(f"{output_format} reports must use the .{extension} extension.")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = (
            json.dumps(report, indent=2, sort_keys=True) + "\n"
            if output_format == "json"
            else _markdown(report)
        )
        temporary = destination.with_name(f".{destination.name}.tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(destination)
    except OSError as exc:
        raise ReportError(f"Unable to write report to {destination}: {exc}") from exc
    return destination.resolve()
