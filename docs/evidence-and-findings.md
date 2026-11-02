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

finding = update_finding_status(store, finding.finding_id, "confirmed")
```

Supported severities are `info`, `low`, `medium`, `high`, and `critical`. Supported finding states are `potential`, `confirmed`, `unverified`, and `false_positive`. Confidence is an integer from 0 to 100.

Execution outcomes such as `completed`, `failed`, `skipped`, `cancelled`, and `unsupported` remain job states; they must not be converted into confirmed findings automatically. Adapter-output capture, automated correlation, evidence/finding UI, and report generation remain future work.
