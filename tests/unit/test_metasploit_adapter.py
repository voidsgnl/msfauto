import unittest
from threading import Event
from typing import Any

from msfauto.execution import CheckRequest, MetasploitSafeAdapter
from msfauto.integrations.metasploit import MetasploitClient


class FakeTransport:
    def __init__(
        self,
        result_states: list[dict[str, Any]] | None = None,
        stance: str = "passive",
    ) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.result_states = list(result_states or [{"status": "completed", "result": {"service": "ssh"}}])
        self.stance = stance

    def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
        self.calls.append((method, arguments))
        if method == "auth.login":
            return {"token": "token-1"}
        if method == "module.info":
            return {"name": "SSH version scanner", "stance": self.stance}
        if method == "module.execute":
            return {"job_id": 7, "uuid": "run-uuid"}
        if method == "module.results":
            if self.result_states:
                return self.result_states.pop(0)
            return {"status": "running"}
        if method == "job.stop":
            return {"result": "success"}
        return {}


class MetasploitSafeAdapterTests(unittest.TestCase):
    def make_adapter(
        self,
        result_states: list[dict[str, Any]] | None = None,
        stance: str = "passive",
        timeout: float = 0.05,
    ) -> tuple[MetasploitSafeAdapter, FakeTransport]:
        transport = FakeTransport(result_states, stance)
        client = MetasploitClient(transport, "operator", "secret")
        return MetasploitSafeAdapter(client, timeout=timeout, poll_interval=0.001), transport

    def request(self, module_name: str = "auxiliary/scanner/ssh/ssh_version") -> CheckRequest:
        return CheckRequest(
            "lab",
            "192.168.56.10",
            2222,
            "tcp",
            module_name,
            "approval-1",
            "non-invasive",
        )

    def test_allowlisted_passive_module_executes_with_only_scoped_target_options(self) -> None:
        adapter, transport = self.make_adapter()

        result = adapter.run(self.request(), Event())

        self.assertEqual(result.status, "completed")
        self.assertIn('"service": "ssh"', result.output)
        execute_call = next(call for call in transport.calls if call[0] == "module.execute")
        self.assertEqual(
            execute_call[1],
            (
                "token-1",
                "auxiliary",
                "scanner/ssh/ssh_version",
                {"RHOSTS": "192.168.56.10", "RPORT": 2222},
            ),
        )

    def test_non_allowlisted_scanner_is_not_dispatched(self) -> None:
        adapter, transport = self.make_adapter()

        result = adapter.run(self.request("auxiliary/scanner/ssh/ssh_login"), Event())

        self.assertEqual(result.status, "unsupported")
        self.assertNotIn("module.execute", [method for method, _ in transport.calls])

    def test_module_not_reported_as_passive_is_not_dispatched(self) -> None:
        adapter, transport = self.make_adapter(stance="aggressive")

        result = adapter.run(self.request(), Event())

        self.assertEqual(result.status, "unsupported")
        self.assertNotIn("module.execute", [method for method, _ in transport.calls])

    def test_non_invasive_risk_is_required(self) -> None:
        adapter, transport = self.make_adapter()
        request = self.request()
        request = CheckRequest(
            request.workspace,
            request.target,
            request.port,
            request.protocol,
            request.module_name,
            request.approval_id,
            "intrusive",
        )

        result = adapter.run(request, Event())

        self.assertEqual(result.status, "unsupported")
        self.assertEqual([method for method, _ in transport.calls], ["auth.login"])

    def test_execution_timeout_stops_the_metasploit_job(self) -> None:
        adapter, transport = self.make_adapter(
            result_states=[{"status": "running"}],
            timeout=0.005,
        )

        result = adapter.run(self.request(), Event())

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.error, "metasploit-timeout")
        self.assertIn("job.stop", [method for method, _ in transport.calls])

    def test_cancel_before_dispatch_does_not_contact_metasploit(self) -> None:
        adapter, transport = self.make_adapter()
        cancel = Event()
        cancel.set()

        result = adapter.run(self.request(), cancel)

        self.assertEqual(result.status, "cancelled")
        self.assertEqual([method for method, _ in transport.calls], ["auth.login"])


if __name__ == "__main__":
    unittest.main()
