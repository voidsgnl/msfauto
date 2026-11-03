import json
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.cli import main
from msfauto.evidence import EvidenceCollector
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import Host, ModuleMetadata, Service, Workspace


class SafeChecksCliTests(unittest.TestCase):
    def test_metasploit_mode_uses_real_adapter_and_persists_rpc_output(self) -> None:
        class StubMetasploitClient:
            def module_info(self, module_type: str, module_name: str) -> dict[str, str]:
                return {"stance": "passive"}

            def execute_auxiliary(self, module_name: str, options: dict) -> tuple[int, str]:
                self.options = options
                return 3, "run-uuid"

            def module_results(self, run_uuid: str) -> dict:
                return {"status": "completed", "result": {"service": "ssh", "version": "OpenSSH"}}

            def stop_job(self, job_id: int) -> None:
                raise AssertionError("A completed job must not be stopped.")

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
                    metadata={"description": "SSH version scanner"},
                    options={},
                    source="test",
                )
            )
            stub_client = StubMetasploitClient()
            with (
                patch("builtins.input", side_effect=["operator-1", "APPROVE"]),
                patch.dict(
                    "os.environ",
                    {
                        "MSFAUTO_METASPLOIT_USERNAME": "rpc-user",
                        "MSFAUTO_METASPLOIT_PASSWORD": "rpc-password",
                    },
                ),
                patch("msfauto.cli.MetasploitClient", return_value=stub_client),
            ):
                result = run_main_with_env(
                    directory,
                    ["--workspace", "lab", "--run-safe-checks", "--metasploit", "--max-checks", "1"],
                )

            jobs = store.get_jobs("lab")
            evidence_records = store.get_evidence_records("lab")
            payload = json.loads(Path(evidence_records[0].artifact_path).read_text())

        self.assertEqual(result, 0)
        self.assertEqual(jobs[0].status, "completed")
        self.assertEqual(stub_client.options, {"RHOSTS": "192.168.56.10", "RPORT": 22})
        self.assertIn("OpenSSH", payload["adapter_output"])

    def test_metasploit_mode_requires_credentials_before_asking_for_approval(self) -> None:
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
                    metadata={"description": "SSH version scanner"},
                    options={},
                    source="test",
                )
            )
            with (
                patch("builtins.input") as prompt,
                patch.dict(
                    "os.environ",
                    {
                        "MSFAUTO_METASPLOIT_USERNAME": "",
                        "MSFAUTO_METASPLOIT_PASSWORD": "",
                    },
                ),
            ):
                result = run_main_with_env(
                    directory,
                    ["--workspace", "lab", "--run-safe-checks", "--metasploit", "--max-checks", "1"],
                )
                prompt.assert_not_called()

        self.assertEqual(result, 2)

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
            with patch("builtins.input", side_effect=["operator-1", "APPROVE"]):
                result = run_main_with_env(directory, ["--workspace", "lab", "--run-safe-checks", "--max-checks", "1"])
            approvals = store.get_approvals("lab")
            jobs = store.get_jobs("lab")
            evidence_records = store.get_evidence_records("lab")
            self.assertEqual(len(evidence_records), 1)
            self.assertEqual(evidence_records[0].evidence_type, "execution-result")
            self.assertEqual(evidence_records[0].metadata["status"], "completed")
            payload = json.loads(Path(evidence_records[0].artifact_path).read_text())
            self.assertEqual(payload["adapter_output"], "")
            self.assertTrue(EvidenceCollector(store).verify(evidence_records[0]))
            self.assertEqual(store.get_findings("lab"), ())

        self.assertEqual(result, 0)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].status, "completed")
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0].decision, "approved")
        self.assertEqual(approvals[0].approver, "operator-1")


def run_main_with_env(home: str, argv: list[str]) -> int:
    import sys

    with (
        patch.dict("os.environ", {"MSFAUTO_HOME": home}),
        patch.object(sys, "argv", ["msfauto", *argv]),
    ):
        return main()
