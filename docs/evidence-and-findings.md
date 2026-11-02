# Evidence and Findings

## Evidence artifacts

Use `EvidenceCollector` to store an artifact and its provenance separately from an analyst conclusion:

```python
from msfauto.evidence import EvidenceCollector

collector = EvidenceCollector(store)
record = collector.collect(
    workspace="lab",
    source="nmap",
    target="192.168.56.10",
    evidence_type="text/plain",
    summary="Captured service banner",
    content=b"SSH-2.0-example",
    metadata={"port": 22, "protocol": "tcp"},
)

if not collector.verify(record):
    raise RuntimeError("Evidence integrity verification failed")
```

The default maximum artifact size is 2,000,000 bytes. Artifacts are written beneath the directory containing the workspace database, in a workspace-specific directory. On POSIX systems, the collector applies mode 0700 to evidence directories and 0600 to artifact files. SQLite stores the provenance and integrity metadata, including the SHA-256 digest.

The CLI stores each safe-check outcome, structured job events, and any textual adapter output as a bounded `execution-result` evidence artifact. Adapters return output through `CheckResult.output`; the job manager enforces a 256,000-byte UTF-8 limit and redacts common password, token, secret, API-key, authorization, cookie, credential, and bearer-token values before the output can be retrieved or persisted. Oversized or non-text output is rejected and the job is marked failed with `invalid-adapter-output`. Redaction is best-effort, not a guarantee that all sensitive data is removed. No live Metasploit execution adapter is implemented by this contract; it defines the boundary for future adapters.

The collector does not redact, encrypt, or classify sensitive content. Sanitize artifacts before collection and protect the local evidence directory. Do not put credentials, tokens, or secrets in metadata or summaries.

## Findings

A finding is an interpreted assessment record, not a raw artifact. Create findings with evidence identifiers from the same workspace:

```python
from msfauto.findings import create_finding, update_finding_status

finding = create_finding(
    store,
    workspace="lab",
    title="SSH service observed",
    description="A service banner was captured; this is not a vulnerability confirmation.",
    severity="info",
    status="potential",
    confidence=95,
    evidence_ids=(record.evidence_id,),
)

finding = update_finding_status(store, finding.finding_id, "unverified")
```

Supported severities are `info`, `low`, `medium`, `high`, and `critical`. Supported finding states are `potential`, `confirmed`, `unverified`, and `false_positive`. Confidence is an integer from 0 to 100. Before a finding can reference evidence, MSFAuto verifies that every artifact still exists, belongs to the same workspace, and matches its stored SHA-256 digest. A finding cannot be marked `confirmed` unless it references at least one persisted evidence record; confirmation remains an analyst decision and requires evidence that actually supports the vulnerability claim. A service banner or execution status alone is not sufficient.

Execution outcomes such as `completed`, `failed`, `skipped`, `cancelled`, and `unsupported` remain job states; they must not be converted into confirmed findings automatically. Automatic creation of vulnerability findings from execution evidence is intentionally not enabled: analysts must supply an interpretation and supporting evidence. Adapter-output capture, automated correlation, and evidence/finding UI remain future work.

## Assessment reports

Export the current workspace as JSON or Markdown:

```bash
python -m msfauto.cli --workspace lab --report json
python -m msfauto.cli --workspace lab --report markdown --report-output ./assessment-report.md
```

Without `--report-output`, files are written under the workspace database directory in `reports/`. JSON exports use schema version 1. Both formats include the saved authorization scope, discovered hosts and services, execution job summaries, analyst findings, and an evidence register with current SHA-256 integrity state. Reports include evidence metadata and digests, not the raw artifact contents. Common secret-bearing metadata keys and inline password/token assignments are redacted during export. Treat reports as sensitive assessment records and review them before sharing; redaction is a safeguard, not a guarantee that all sensitive information is removed.
