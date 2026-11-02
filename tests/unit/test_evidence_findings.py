import stat
import tempfile
import unittest
from pathlib import Path

from msfauto.evidence import EvidenceCollector, EvidenceError
from msfauto.findings import FindingError, create_finding, update_finding_status
from msfauto.storage import WorkspaceStore


class EvidenceFindingTests(unittest.TestCase):
    def test_evidence_is_persisted_and_integrity_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            collector = EvidenceCollector(store)
            evidence = collector.collect(
                "lab",
                "unit-test",
                "192.168.56.10",
                "text/plain",
                "Captured service response.",
                b"SSH-2.0-example",
                {"port": 22},
            )
            saved = store.get_evidence(evidence.evidence_id)

            self.assertEqual(saved, evidence)
            self.assertTrue(collector.verify(saved))
            self.assertEqual(stat.S_IMODE(Path(saved.artifact_path).stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(Path(saved.artifact_path).parent.stat().st_mode), 0o700)
            Path(saved.artifact_path).write_bytes(b"modified")
            self.assertFalse(collector.verify(saved))

    def test_evidence_size_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            collector = EvidenceCollector(store, max_bytes=4)
            with self.assertRaisesRegex(EvidenceError, "exceeds"):
                collector.collect("lab", "unit-test", "", "text/plain", "too large", b"12345")

    def test_findings_require_evidence_from_the_same_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            evidence = EvidenceCollector(store).collect(
                "lab", "unit-test", "192.168.56.10", "text/plain",
                "Observed banner.", b"SSH-2.0-example",
            )
            finding = create_finding(
                store,
                "lab",
                "SSH service observed",
                "An SSH service banner was collected.",
                severity="info",
                status="potential",
                confidence=95,
                evidence_ids=(evidence.evidence_id,),
            )
            saved = store.get_finding(finding.finding_id)
            updated = update_finding_status(store, finding.finding_id, "confirmed")

            self.assertEqual(saved, finding)
            self.assertEqual(updated.status, "confirmed")
            self.assertEqual(updated.evidence_ids, (evidence.evidence_id,))

    def test_confirmed_finding_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            with self.assertRaisesRegex(ValueError, "must reference"):
                create_finding(
                    store, "lab", "Unsupported confirmation",
                    "A confirmed finding cannot be evidence-free.",
                    status="confirmed",
                )


    def test_findings_reject_tampered_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            evidence = EvidenceCollector(store).collect(
                "lab", "unit-test", "192.168.56.10", "text/plain",
                "Observed banner.", b"SSH-2.0-example",
            )
            Path(evidence.artifact_path).write_bytes(b"tampered")
            with self.assertRaisesRegex(FindingError, "integrity verification"):
                create_finding(
                    store, "lab", "Tampered evidence",
                    "This evidence must not support a finding.",
                    evidence_ids=(evidence.evidence_id,),
                )


    def test_status_change_rejects_evidence_tampered_after_finding_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            evidence = EvidenceCollector(store).collect(
                "lab", "unit-test", "192.168.56.10", "text/plain",
                "Observed service response.", b"safe-observation",
            )
            finding = create_finding(
                store, "lab", "Potential observation",
                "An analyst must review this observation.",
                evidence_ids=(evidence.evidence_id,),
            )
            Path(evidence.artifact_path).write_bytes(b"tampered")
            with self.assertRaisesRegex(FindingError, "integrity verification"):
                update_finding_status(store, finding.finding_id, "confirmed")

    def test_finding_rejects_evidence_from_another_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            evidence = EvidenceCollector(store).collect(
                "lab-a", "unit-test", "192.168.56.10", "text/plain",
                "Observed banner.", b"SSH-2.0-example",
            )
            with self.assertRaisesRegex(FindingError, "does not exist"):
                create_finding(
                    store, "lab-b", "Cross-workspace reference",
                    "This must be rejected.", evidence_ids=(evidence.evidence_id,),
                )

if __name__ == "__main__":
    unittest.main()
