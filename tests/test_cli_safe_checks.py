import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.cli import main
from msfauto.models import Host, ModuleMetadata, Service, Workspace
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore


class SafeChecksCliTests(unittest.TestCase):
    def test_run_safe_checks_persists_completed_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            store.save(Workspace("lab", build_policy(["192.168.56.0/24"])))
            store.save_hosts(
                "lab",
                (Host(ip_address("192.168.56.10"), "up", services=(Service(22, "tcp", "open", "ssh"),)),),
            )
            store.save_module_metadata(
                ModuleMetadata(
                    workspace="lab",
                    module_type="auxiliary",
                    module_name="scanner/ssh/ssh_version",
                    metadata={"description": "SSH scanner"},
                    options={},
                    source="test",
                )
            )
            result = run_main_with_env(directory, ["--workspace", "lab", "--run-safe-checks", "--max-checks", "1"])
            jobs = store.get_jobs("lab")

        self.assertEqual(result, 0)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].status, "completed")


def run_main_with_env(home: str, argv: list[str]) -> int:
    import sys

    with patch.dict("os.environ", {"MSFAUTO_HOME": home}):
        with patch.object(sys, "argv", ["msfauto", *argv]):
            return main()
