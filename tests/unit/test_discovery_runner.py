import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from msfauto.discovery import DiscoveryError, run_metasploit_db_nmap, run_nmap
from msfauto.scope import build_policy


class DiscoveryRunnerTests(unittest.TestCase):
    def test_runner_builds_scope_limited_command(self) -> None:
        xml = "<nmaprun></nmaprun>"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.xml"
            output.write_text(xml, encoding="utf-8")
            completed = unittest.mock.Mock(returncode=0, stderr="")
            completed.poll.return_value = 0
            with patch("msfauto.discovery.pipeline.shutil.which", return_value="/usr/bin/nmap"), patch(
                "msfauto.discovery.pipeline.subprocess.Popen", return_value=completed
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
        self.assertIn("-sV", command)
        self.assertIn("--version-light", command)
        self.assertIn("-Pn", command)
        run.assert_called_once()


    def test_default_standard_profile_is_focused_and_web_first(self) -> None:
        from msfauto.discovery.pipeline import QUICK_TCP_PORTS, STANDARD_TCP_PORTS

        self.assertLessEqual(len(QUICK_TCP_PORTS), 16)
        self.assertLessEqual(len(STANDARD_TCP_PORTS), 55)
        self.assertTrue({80, 443, 3000, 5000, 8000, 8080, 8443}.issubset(STANDARD_TCP_PORTS))
        self.assertTrue({22, 25, 53, 445, 3306, 5432}.issubset(STANDARD_TCP_PORTS))
        self.assertNotIn(69, STANDARD_TCP_PORTS)
        self.assertNotIn(514, STANDARD_TCP_PORTS)
        self.assertGreater(len(STANDARD_TCP_PORTS), len(QUICK_TCP_PORTS))

    def test_runner_terminates_process_when_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.xml"
            output.write_text("<nmaprun>", encoding="utf-8")
            process = unittest.mock.Mock(returncode=-15)
            process.poll.return_value = None
            cancel = Event()
            cancel.set()
            with patch("msfauto.discovery.pipeline.shutil.which", return_value="/usr/bin/nmap"), patch(
                "msfauto.discovery.pipeline.subprocess.Popen", return_value=process
            ):
                result, hosts = run_nmap(
                    "lab",
                    build_policy(["192.0.2.25"], "22"),
                    output,
                    cancel_event=cancel,
                )

        self.assertEqual(result.status, "cancelled")
        self.assertEqual(hosts, ())
        self.assertFalse(output.exists())
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)

    def test_runner_rejects_missing_scanner(self) -> None:
        with (
            patch("msfauto.discovery.pipeline.shutil.which", return_value=None),
            self.assertRaisesRegex(DiscoveryError, "not found"),
        ):
            run_nmap("lab", build_policy(["127.0.0.1"]), Path("/tmp/scan.xml"))


    def test_metasploit_db_nmap_normalizes_only_in_scope_open_services(self) -> None:
        class FakeMetasploitClient:
            def __init__(self) -> None:
                self.scan = None

            def run_db_nmap(self, workspace, targets, port_spec, timeout=300.0):
                self.scan = (workspace, targets, port_spec)
                return "Nmap completed"

            def database_hosts(self, workspace, addresses=(), limit=1000):
                return [
                    {"address": "192.0.2.10", "state": "alive", "name": "lab-host"},
                    {"address": "192.0.2.99", "state": "alive", "name": "out-of-scope"},
                ]

            def database_services(self, workspace, addresses=(), limit=1000):
                return [
                    {"host": "192.0.2.10", "port": 80, "proto": "tcp", "state": "open", "name": "http", "info": "nginx"},
                    {"host": "192.0.2.10", "port": 22, "proto": "tcp", "state": "closed", "name": "ssh"},
                    {"host": "192.0.2.99", "port": 443, "proto": "tcp", "state": "open", "name": "https"},
                ]

        client = FakeMetasploitClient()
        policy = build_policy(["192.0.2.10"], "80")
        run, hosts = run_metasploit_db_nmap("lab", policy, client)

        self.assertEqual(run.scanner, "metasploit:db_nmap")
        self.assertEqual(client.scan, ("lab", ("192.0.2.10",), "80"))
        self.assertEqual(len(hosts), 1)
        self.assertEqual(str(hosts[0].address), "192.0.2.10")
        self.assertEqual(hosts[0].hostname, "lab-host")
        self.assertEqual(len(hosts[0].services), 1)
        self.assertEqual(hosts[0].services[0].port, 80)
        self.assertEqual(hosts[0].services[0].source, "metasploit-db")
