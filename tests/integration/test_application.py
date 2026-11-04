import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.core import AssessmentApplication
from msfauto.enumeration.models import ServiceObservation
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
                status, hosts, scan_id = service.discover()

            self.assertEqual(status, "completed")
            self.assertEqual(hosts, (host,))
            self.assertEqual(scan_id, run.scan_id)
            self.assertEqual(store.get_hosts("lab"), (host,))
            observation = ServiceObservation(
                "observation-current", "lab", "192.168.56.10", 22, "tcp",
                "ssh", "ssh_banner", "completed", {"banner": "SSH-2.0-test"},
                observed_at="2026-11-04T12:00:00+00:00",
            )
            legacy = ServiceObservation(
                "observation-legacy", "lab", "192.168.56.10", 21, "tcp",
                "ftp", "ftp_response", "completed", {},
                observed_at="2026-11-04T11:00:00+00:00",
            )
            store.save_service_observations((observation,), scan_id)
            store.save_service_observations((legacy,))
            self.assertEqual(
                tuple(item.observation_id for item in store.get_service_observations(
                    "lab", discovery_run_id=scan_id,
                )),
                ("observation-current",),
            )
            self.assertEqual(
                tuple(item.observation_id for item in store.get_service_observations(
                    "lab", discovery_run_id="",
                )),
                ("observation-legacy",),
            )
            self.assertEqual(
                len(store.get_service_observations("lab")),
                2,
            )

    def test_plan_is_persisted_by_application_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            workspace = Workspace("lab", build_policy(["192.168.56.0/24"]))
            store.save(workspace)
            service = AssessmentApplication(workspace, store)

            plan = service.build_assessment_plan()

            self.assertEqual(plan.workspace, "lab")
            self.assertEqual(store.get_plan("lab"), plan)
