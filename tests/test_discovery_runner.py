import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msfauto.discovery import DiscoveryError, run_nmap
from msfauto.scope import build_policy


class DiscoveryRunnerTests(unittest.TestCase):
    def test_runner_builds_scope_limited_command(self) -> None:
        xml = "<nmaprun></nmaprun>"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.xml"
            output.write_text(xml, encoding="utf-8")
            completed = unittest.mock.Mock(returncode=0, stderr="", stdout="")
            with patch("msfauto.discovery.shutil.which", return_value="/usr/bin/nmap"), patch(
                "msfauto.discovery.subprocess.run", return_value=completed
            ) as run:
                result, hosts = run_nmap(
                    "lab",
                    build_policy(["192.168.56.0/24"], "22,445"),
                    output,
                    executable="nmap",
                )

        self.assertEqual(result.status, "completed")
        self.assertEqual(hosts, ())
        command = run.call_args.args[0]
        self.assertEqual(command[-1], "192.168.56.0/24")
        self.assertIn("22,445", command)
        run.assert_called_once()

    def test_runner_rejects_missing_scanner(self) -> None:
        with patch("msfauto.discovery.shutil.which", return_value=None):
            with self.assertRaisesRegex(DiscoveryError, "not found"):
                run_nmap("lab", build_policy(["127.0.0.1"]), Path("/tmp/scan.xml"))
