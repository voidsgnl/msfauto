import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msfauto.cli import run_discovery
from msfauto.models import DiscoveryRun, Workspace
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore


class DiscoveryCliTests(unittest.TestCase):
    def test_run_discovery_persists_run_and_imports_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            workspace = Workspace("lab", build_policy(["192.168.56.0/24"]))
            store.save(workspace)
            run = DiscoveryRun(
                "lab", "nmap", ("nmap",), str(Path(directory) / "discovery" / "lab.xml"),
                "completed", "start", "finish",
            )
            with patch("msfauto.cli.run_nmap", return_value=(run, ())):
                result = run_discovery(store, workspace)

            self.assertEqual(result, 0)
            self.assertEqual(store.get_hosts("lab"), ())
