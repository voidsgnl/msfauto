import sqlite3
import tempfile
import unittest
from pathlib import Path

from msfauto.assessment.approval import action_id, record_decision
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import Recommendation


class ApprovalTests(unittest.TestCase):
    def test_action_identity_changes_when_target_or_module_changes(self) -> None:
        recommendation = Recommendation(
            "192.168.56.10", 22, "tcp", "auxiliary",
            "scanner/ssh/ssh_version", 90, "Observed SSH service.",
        )
        changed_target = Recommendation(
            "192.168.56.11", 22, "tcp", "auxiliary",
            "scanner/ssh/ssh_version", 90, "Observed SSH service.",
        )
        self.assertEqual(action_id("lab", recommendation), action_id("lab", recommendation))
        self.assertNotEqual(action_id("lab", recommendation), action_id("lab", changed_target))
        changed_risk = Recommendation(
            "192.168.56.10", 22, "tcp", "auxiliary",
            "scanner/ssh/ssh_version", 90, "Observed SSH service.", "intrusive",
        )
        self.assertNotEqual(action_id("lab", recommendation), action_id("lab", changed_risk))

    def test_decision_is_persisted_with_approver_and_action_context(self) -> None:
        recommendation = Recommendation(
            "192.168.56.10", 22, "tcp", "auxiliary",
            "scanner/ssh/ssh_version", 90, "Observed SSH service.",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "state.sqlite3")
            record = record_decision(
                store, "lab", recommendation, "approved", "operator-1", "Reviewed in CLI."
            )
            saved = store.get_approval(record.action_id)

        self.assertEqual(saved, record)
        self.assertEqual(saved.decision, "approved")
        self.assertEqual(saved.approver, "operator-1")
        self.assertEqual(saved.target, "192.168.56.10")
        self.assertEqual(saved.port, 22)
        self.assertEqual(saved.risk, "non-invasive")


    def test_existing_approval_table_is_migrated_with_risk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute(
                """
                CREATE TABLE action_approvals (
                    action_id TEXT PRIMARY KEY,
                    workspace TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    decided_at TEXT NOT NULL,
                    rationale TEXT NOT NULL
                )
                """
            )
            connection.commit()
            connection.close()

            store = WorkspaceStore(path)
            recommendation = Recommendation(
                "192.168.56.10", 22, "tcp", "auxiliary",
                "scanner/ssh/ssh_version", 90, "Observed SSH service.", "intrusive",
            )
            record = record_decision(store, "lab", recommendation, "approved", "operator-1")
            saved = store.get_approval(record.action_id)

        self.assertEqual(saved.risk, "intrusive")



if __name__ == "__main__":
    unittest.main()
