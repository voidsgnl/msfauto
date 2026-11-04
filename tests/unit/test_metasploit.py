import io
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from msfauto.integrations.metasploit import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MsgpackHttpTransport,
)
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import ModuleMetadata


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
        self.calls.append((method, arguments))
        if method == "auth.login":
            return {"token": "token-1"}
        if method == "module.search":
            return {"modules": [{"type": "auxiliary", "name": "scanner/example"}]}
        if method == "module.options":
            return {"options": {"RHOSTS": {"required": True}}}
        if method == "module.execute":
            return {"job_id": 4, "uuid": "run-uuid"}
        if method == "module.results":
            return {"status": "completed", "result": None}
        if method == "job.stop":
            return {"result": "success"}
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

    def test_msgpack_transport_normalizes_binary_encoded_rpc_strings(self) -> None:
        import msgpack

        login_response = msgpack.packb(
            {b"result": b"success", b"token": b"token-1"},
            use_bin_type=True,
        )
        result_response = msgpack.packb(
            {b"status": b"completed", b"details": {b"message": b"finished"}},
            use_bin_type=True,
        )
        transport = MsgpackHttpTransport(MetasploitConfig())

        with patch(
            "msfauto.integrations.metasploit.client.urlopen",
            side_effect=[io.BytesIO(login_response), io.BytesIO(result_response)],
        ):
            client = MetasploitClient(transport, "user", "password")
            result = client.module_results("run-uuid")

        self.assertEqual(client.token, "token-1")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["details"]["message"], "finished")

    def test_msgpack_transport_normalizes_binary_encoded_error_response(self) -> None:
        import msgpack

        error_response = msgpack.packb(
            {b"error": True, b"error_message": b"Login Failed"},
            use_bin_type=True,
        )
        transport = MsgpackHttpTransport(MetasploitConfig())

        with (
            patch(
                "msfauto.integrations.metasploit.client.urlopen",
                return_value=io.BytesIO(error_response),
            ),
            self.assertRaisesRegex(MetasploitError, "Login Failed"),
        ):
            transport.request("auth.login", ("user", "password"))

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

    def test_job_list_normalizes_numeric_ids(self) -> None:
        class JobsTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
                if method == "job.list":
                    self.calls.append((method, arguments))
                    return {"jobs": {"4": "Exploit: example", "9": "Auxiliary: scanner"}}
                return super().request(method, arguments)

        transport = JobsTransport()
        client = MetasploitClient(transport, "user", "password")

        self.assertEqual(
            client.job_list(),
            {4: "Exploit: example", 9: "Auxiliary: scanner"},
        )
        self.assertEqual(transport.calls[-1], ("job.list", ("token-1",)))

    def test_job_list_rejects_invalid_framework_response(self) -> None:
        class InvalidJobsTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
                if method == "job.list":
                    return {"jobs": ["not", "a", "mapping"]}
                return super().request(method, arguments)

        with self.assertRaisesRegex(MetasploitError, "invalid job list"):
            MetasploitClient(InvalidJobsTransport()).job_list()

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


    def test_db_nmap_runs_through_metasploit_console_and_selects_workspace(self) -> None:
        class DbNmapTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
                self.calls.append((method, arguments))
                if method == "db.add_workspace":
                    return {"result": "success"}
                if method == "db.set_workspace":
                    return {"result": "success"}
                if method == "console.create":
                    return {"id": "console-7", "busy": False}
                if method == "console.read":
                    if not hasattr(self, "reads"):
                        self.reads = 0
                    self.reads += 1
                    if self.reads == 1:
                        return {"data": "banner", "busy": False}
                    if self.reads == 2:
                        # The RPC console can report idle immediately after
                        # console.write while its worker is still dispatching.
                        return {"data": "", "busy": False}
                    if self.reads == 3:
                        return {"data": "Nmap scan started", "busy": True}
                    return {"data": "Nmap done", "busy": False}
                if method == "console.write":
                    return {"wrote": len(arguments[-1])}
                if method == "console.destroy":
                    return {"result": "success"}
                return super().request(method, arguments)

        transport = DbNmapTransport()
        client = MetasploitClient(transport, "user", "password")
        output = client.run_db_nmap(
            "lab", ("192.0.2.10", "192.0.2.0/24"), "22,80,443",
        )

        self.assertIn("Nmap done", output)
        methods = [method for method, _ in transport.calls]
        self.assertIn("db.add_workspace", methods)
        self.assertIn("db.set_workspace", methods)
        write_calls = [args for method, args in transport.calls if method == "console.write"]
        self.assertEqual(
            write_calls[-1],
            ("token-1", "console-7", "db_nmap -n -Pn -sV --version-light -p 22,80,443 192.0.2.10/32 192.0.2.0/24\n"),
        )
        self.assertGreaterEqual(
            sum(method == "console.destroy" for method, _ in transport.calls), 2,
        )

    def test_db_nmap_rejects_shell_injection_and_invalid_ports(self) -> None:
        client = MetasploitClient(FakeTransport(), "user", "password")
        with self.assertRaisesRegex(MetasploitError, "validated IP/CIDR"):
            client.run_db_nmap("lab", ("192.0.2.1; whoami",), "80")
        with self.assertRaisesRegex(MetasploitError, "between 1 and 65535"):
            client.run_db_nmap("lab", ("192.0.2.1",), "0,80")

    def test_database_inventory_methods_validate_rpc_shapes(self) -> None:
        class InventoryTransport(FakeTransport):
            def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
                self.calls.append((method, arguments))
                if method == "db.hosts":
                    return {"hosts": [{"address": "192.0.2.10", "state": "alive"}]}
                if method == "db.services":
                    return {"services": [{"host": "192.0.2.10", "port": 443, "name": "https"}]}
                return super().request(method, arguments)

        transport = InventoryTransport()
        client = MetasploitClient(transport, "user", "password")
        hosts = client.database_hosts("lab", ("192.0.2.10",))
        services = client.database_services("lab", ("192.0.2.10",))

        self.assertEqual(hosts[0]["address"], "192.0.2.10")
        self.assertEqual(services[0]["port"], 443)
        self.assertEqual(transport.calls[-1][0], "db.services")
