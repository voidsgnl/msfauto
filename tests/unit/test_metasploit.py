import unittest
from typing import Any

from msfauto.integrations.metasploit import MetasploitClient, MetasploitError
from msfauto.storage.models import ModuleMetadata
from msfauto.storage import WorkspaceStore
from pathlib import Path
import tempfile


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def request(self, method: str, arguments: tuple[str, ...]) -> dict[str, Any]:
        self.calls.append((method, arguments))
        if method == "auth.login":
            return {"token": "token-1"}
        if method == "module.search":
            return {"modules": [{"type": "auxiliary", "name": "scanner/example"}]}
        if method == "module.options":
            return {"options": {"RHOSTS": {"required": True}}}
        return {"name": "example", "description": "safe metadata"}


class MetasploitClientTests(unittest.TestCase):
    def test_authentication_and_metadata_calls_use_token(self) -> None:
        transport = FakeTransport()
        client = MetasploitClient(transport, "user", "password")

        modules = client.search_modules("ssh")
        options = client.module_options("auxiliary", "scanner/example")

        self.assertEqual(modules[0]["name"], "scanner/example")
        self.assertIn("RHOSTS", options)
        self.assertEqual(transport.calls[1], ("module.search", ("token-1", "ssh")))
        self.assertEqual(transport.calls[2], ("module.options", ("token-1", "auxiliary", "scanner/example")))

    def test_empty_search_is_rejected(self) -> None:
        client = MetasploitClient(FakeTransport())
        with self.assertRaisesRegex(MetasploitError, "cannot be empty"):
            client.search_modules(" ")

    def test_missing_authentication_token_is_rejected(self) -> None:
        class NoTokenTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[str, ...]) -> dict[str, Any]:
                return {}

        with self.assertRaisesRegex(MetasploitError, "no token"):
            MetasploitClient(NoTokenTransport(), "user", "password")

    def test_auxiliary_execution_uses_flat_options_and_returns_run_identifiers(self) -> None:
        class ExecutionTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[str, ...]) -> dict[str, Any]:
                self.calls.append((method, arguments))
                if method == "module.execute":
                    return {"job_id": 4, "uuid": "run-uuid"}
                return super().request(method, arguments)

        transport = ExecutionTransport()
        client = MetasploitClient(transport, "user", "password")

        job_id, run_uuid = client.execute_auxiliary(
            "scanner/ssh/ssh_version",
            {"RHOSTS": "192.0.2.10", "RPORT": 2222},
        )

        self.assertEqual((job_id, run_uuid), (4, "run-uuid"))
        self.assertEqual(
            transport.calls[-1],
            (
                "module.execute",
                (
                    "token-1",
                    "auxiliary",
                    "scanner/ssh/ssh_version",
                    {"RHOSTS": "192.0.2.10", "RPORT": 2222},
                ),
            ),
        )

    def test_execution_requires_valid_identifiers(self) -> None:
        class InvalidExecutionTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[str, ...]) -> dict[str, Any]:
                if method == "auth.login":
                    return {"token": "token-1"}
                if method == "module.execute":
                    return {"job_id": "not-an-integer"}
                return {}

        client = MetasploitClient(InvalidExecutionTransport(), "user", "password")
        with self.assertRaisesRegex(MetasploitError, "valid job identifier"):
            client.execute_auxiliary("scanner/ssh/ssh_version", {"RPORT": 22})

    def test_module_results_and_stop_job_use_authenticated_rpc(self) -> None:
        transport = FakeTransport()
        client = MetasploitClient(transport, "user", "password")

        result = client.module_results("run-uuid")
        client.stop_job(4)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(transport.calls[-1], ("job.stop", ("token-1", "4")))

    def test_module_metadata_round_trip(self) -> None:
        module = ModuleMetadata(
            workspace="lab",
            module_type="auxiliary",
            module_name="scanner/example",
            metadata={"description": "safe metadata"},
            options={"RHOSTS": {"required": True}},
            source="http://127.0.0.1:55553/api/1.0",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "state.sqlite3")
            store.save_module_metadata(module)
            restored = store.get_module_metadata("lab", "auxiliary", "scanner/example")

        self.assertEqual(restored, module)
