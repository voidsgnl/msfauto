import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path

from msfauto.storage.models import Host, ModuleMetadata, Service
from msfauto.assessment.planner import build_plan
from msfauto.storage import WorkspaceStore


class PlannerTests(unittest.TestCase):
    def test_plan_matches_open_service_and_explains_reason(self) -> None:
        hosts = (
            Host(
                ip_address("192.168.56.10"),
                "up",
                services=(Service(22, "tcp", "open", "ssh", "OpenSSH", "9"),),
            ),
        )
        modules = (
            ModuleMetadata(
                "lab",
                "auxiliary",
                "scanner/ssh/ssh_version",
                {"description": "SSH version scanner"},
                {},
                "local-cache",
            ),
        )

        plan = build_plan("lab", hosts, modules)

        self.assertEqual(len(plan.recommendations), 1)
        self.assertGreaterEqual(plan.recommendations[0].confidence, 75)
        self.assertIn("OpenSSH", plan.recommendations[0].reason)

    def test_plan_persistence_round_trip(self) -> None:
        plan = build_plan(
            "lab",
            (Host(ip_address("127.0.0.1"), "up", services=(Service(80, "tcp", "open", "http"),)),),
            (),
        )
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "state.sqlite3")
            store.save_plan(plan)
            self.assertEqual(store.get_plan("lab"), plan)
