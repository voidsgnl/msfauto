from __future__ import annotations

from typing import Any

from msfauto.assessment.metasploit_intelligence import discover_web_auxiliary_modules
from msfauto.integrations.metasploit import MetasploitClient


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def request(self, method: str, arguments: tuple[Any, ...]) -> dict[str, Any]:
        self.calls.append((method, arguments))
        if method == "module.search":
            return {"modules": [
                {"type": "exploit", "fullname": "exploit/multi/http/unsafe"},
                {"type": "auxiliary", "fullname": "auxiliary/scanner/http/title"},
                {"type": "auxiliary", "fullname": "auxiliary/scanner/http/title"},
            ]}
        if method == "module.info":
            return {
                "type": "auxiliary",
                "rank": "normal",
                "description": "Read-only HTTP title scanner metadata.",
                "check": True,
            }
        if method == "module.options":
            return {"options": {
                "RHOSTS": {"required": True},
                "RPORT": {"required": False},
            }}
        raise AssertionError(f"Unexpected RPC method: {method}")


def test_discovers_only_bounded_auxiliary_modules_and_fetches_requirements() -> None:
    transport = FakeTransport()
    client = MetasploitClient(transport)

    candidates = discover_web_auxiliary_modules(
        client,
        ("WordPress", "nginx", "WordPress", "Apache"),
        max_technologies=2,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.module_name == "scanner/http/title"
    assert candidate.technology == "WordPress"
    assert candidate.rank == "normal"
    assert candidate.check_supported is True
    assert candidate.required_options == ("RHOSTS",)
    assert [call[0] for call in transport.calls].count("module.search") == 1
    assert [call[0] for call in transport.calls].count("module.info") == 1
    assert [call[0] for call in transport.calls].count("module.options") == 1


def test_rejects_unbounded_discovery_limits() -> None:
    client = MetasploitClient(FakeTransport())

    try:
        discover_web_auxiliary_modules(client, ("WordPress",), max_modules=100)
    except ValueError as exc:
        assert "limits" in str(exc)
    else:
        raise AssertionError("Expected invalid module discovery limit to fail")
