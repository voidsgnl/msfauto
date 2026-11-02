import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.cli import main
from msfauto.models import Host, ModuleMetadata, Service, Workspace
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore


class PlanCliTests(unittest.TestCase):
    def test_show_plan_prints_persisted_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            workspace = Workspace("lab", build_policy(["192.168.56.0/24"]))
            store.save(workspace)
            store.save_hosts(
                "lab",
                (Host(ip_address("192.168.56.10"), "up", services=(Service(22, "tcp", "open", "ssh"),)),),
            )
            store.save_module_metadata(
                ModuleMetadata("lab", "auxiliary", "scanner/ssh/version", {"description": "ssh"}, {}, "test")
            )
            with patch.dict("os.environ", {"MSFAUTO_HOME": directory}):
                with patch("builtins.print") as printer:
                    result = main_with_args(["--workspace", "lab", "--show-plan"])

        self.assertEqual(result, 0)
        self.assertTrue(any("scanner/ssh/version" in str(call) for call in printer.call_args_list))


def main_with_args(arguments: list[str]) -> int:
    import sys

    with patch.object(sys, "argv", ["msfauto", *arguments]):
        return main()
