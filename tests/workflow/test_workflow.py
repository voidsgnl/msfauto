import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.core import AssessmentApplication, WorkflowError
from msfauto.exploitation import ExploitDefinition
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import (
    AssessmentPlan,
    DiscoveryRun,
    Host,
    Service,
    Workspace,
)


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
        self.assertEqual(self.store.get_run_plan(workflow.run_id), plan)
        self.assertEqual([event.stage for event in events], [
            "discovery", "discovery", "enumeration",
            "vulnerability_assessment", "exploit_intelligence", "enumeration",
            "planning", "planning", "completed"
        ])
        self.assertEqual(self.store.get_assessment_events(workflow.run_id), tuple(events))

    def test_workflow_persists_catalog_matched_exploit_opportunity(self) -> None:
        run = DiscoveryRun(
            "lab", "nmap", ("nmap",), str(Path(self.directory.name) / "scan.xml"),
            "completed", "started", "finished",
        )
        host = Host(
            ip_address("192.168.56.10"),
            "up",
            services=(Service(
                port=22, protocol="tcp", state="open", product="OpenSSH", version="8.2p1"
            ),),
        )
        definition = ExploitDefinition(
            exploit_id="catalog:workflow-test",
            source="test-catalog",
            module_type="exploit",
            module_name="multi/ssh/test_module",
            name="Workflow test exploit metadata",
            product_aliases=("OpenSSH",),
            affected_versions=("8.2p1",),
        )
        with (
            patch("msfauto.core.orchestrator.run_nmap", return_value=(run, (host,))),
            patch("msfauto.core.orchestrator.enumerate_services", return_value=()),
            patch("msfauto.core.orchestrator.load_package_mappings", return_value=()),
            patch("msfauto.core.orchestrator.load_exploit_catalog", return_value=(definition,)),
        ):
            workflow, _ = self.application.run_assessment()

        opportunities = self.store.get_exploit_opportunities("lab")
        self.assertEqual(workflow.status, "completed")
        self.assertEqual(len(opportunities), 1)
        self.assertEqual(opportunities[0].status, "identified")
        self.assertEqual(opportunities[0].target, "192.168.56.10")
        self.assertTrue(any(
            event.stage == "exploit_intelligence" and "1 opportunity" in event.message
            for event in self.store.get_assessment_events(workflow.run_id)
        ))

    def test_run_plan_rejects_missing_or_mismatched_run(self) -> None:
        plan = AssessmentPlan("lab", ())

        with self.assertRaisesRegex(ValueError, "not found"):
            self.store.save_run_plan("missing-run", plan)

        run = self.application.run_assessment
        discovery = DiscoveryRun(
            "lab", "nmap", ("nmap",), str(Path(self.directory.name) / "scan.xml"),
            "completed", "started", "finished",
        )
        with patch("msfauto.core.orchestrator.run_nmap", return_value=(discovery, ())):
            workflow, _ = run()

        with self.assertRaisesRegex(ValueError, "workspace does not match"):
            self.store.save_run_plan(workflow.run_id, AssessmentPlan("another-workspace", ()))

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
