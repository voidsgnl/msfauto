import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msfauto.core import AssessmentApplication, WorkflowError
from msfauto.storage.models import DiscoveryRun, Workspace
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore


class AssessmentWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(Path(self.directory.name) / "workspace.sqlite3")
        self.workspace = Workspace("lab", build_policy(["192.168.56.0/24"]))
        self.store.save(self.workspace)
        self.application = AssessmentApplication(self.workspace, self.store)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_workflow_persists_completed_lifecycle_and_events(self) -> None:
        run = DiscoveryRun(
            "lab", "nmap", ("nmap",), str(Path(self.directory.name) / "scan.xml"),
            "completed", "started", "finished",
        )
        events = []
        with patch("msfauto.core.orchestrator.run_nmap", return_value=(run, ())):
            workflow, plan = self.application.run_assessment(events.append)

        stored = self.store.get_assessment_run(workflow.run_id)
        self.assertEqual(workflow.status, "completed")
        self.assertEqual(workflow.stage, "completed")
        self.assertEqual(stored, workflow)
        self.assertEqual(plan.workspace, "lab")
        self.assertEqual([event.stage for event in events], [
            "discovery", "discovery", "planning", "planning", "completed"
        ])
        self.assertEqual(self.store.get_assessment_events(workflow.run_id), tuple(events))

    def test_missing_scope_is_persisted_as_failure(self) -> None:
        workspace = Workspace("empty")
        self.store.save(workspace)
        application = AssessmentApplication(workspace, self.store)

        with self.assertRaises(WorkflowError):
            application.run_assessment()

        runs = self.store.get_assessment_runs("empty")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].status, "failed")
        self.assertIn("no authorized targets", runs[0].error)
        self.assertEqual(len(self.store.get_assessment_events(runs[0].run_id)), 1)


if __name__ == "__main__":
    unittest.main()
