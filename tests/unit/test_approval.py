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


if __name__ == "__main__":
    unittest.main()
