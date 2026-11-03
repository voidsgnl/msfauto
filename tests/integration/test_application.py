import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.core import AssessmentApplication
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import DiscoveryRun, Host, Service, Workspace


class AssessmentApplicationTests(unittest.TestCase):
    def test_discovery_persists_run_and_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            workspace = Workspace("lab", build_policy(["192.168.56.0/24"]))
            store.save(workspace)
            host = Host(
                ip_address("192.168.56.10"),
                "up",
                "lab-host",
                (Service(22, "tcp", "open", "ssh"),),
            )
            run = DiscoveryRun(
                "lab", "nmap", ("nmap",), str(Path(directory) / "discovery/lab.xml"),
                "completed", "start", "finish",
            )
            service = AssessmentApplication(workspace, store)
            with patch("msfauto.core.orchestrator.run_nmap", return_value=(run, (host,))):
                status, hosts = service.discover()

            self.assertEqual(status, "completed")
            self.assertEqual(hosts, (host,))
            self.assertEqual(store.get_hosts("lab"), (host,))

    def test_plan_is_persisted_by_application_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            workspace = Workspace("lab", build_policy(["192.168.56.0/24"]))
            store.save(workspace)
            service = AssessmentApplication(workspace, store)

            plan = service.build_assessment_plan()

            self.assertEqual(plan.workspace, "lab")
            self.assertEqual(store.get_plan("lab"), plan)
