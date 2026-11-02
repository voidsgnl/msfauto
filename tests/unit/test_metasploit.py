import unittest
from typing import Any

from msfauto.metasploit import MetasploitClient, MetasploitError
from msfauto.models import ModuleMetadata
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
