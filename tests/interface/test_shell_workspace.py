from ipaddress import ip_address
from types import SimpleNamespace
from unittest.mock import Mock, patch

from msfauto.interface.shell import CommandShell, _ping_target
from msfauto.scope import build_policy
from msfauto.storage.models import Workspace


def make_shell(prompts: list[str]) -> CommandShell:
    shell = CommandShell.__new__(CommandShell)
    shell.mode = None
    shell.console = Mock()
    shell.session = Mock()
    shell.session.prompt.side_effect = prompts
    shell.store = Mock()
    shell.store.get.return_value = None
    shell.workspace = Workspace("default", build_policy(["127.0.0.1"]))
    shell._show_context = Mock()
    return shell


def test_root_workspace_create_validates_pings_and_activates_workspace() -> None:
    shell = make_shell(["lab", "192.0.2.15", "80,443"])

    with patch("msfauto.interface.shell._ping_target", return_value="reachable") as ping:
        shell.execute("workspace create")

    ping.assert_called_once_with("192.0.2.15")
    shell.store.save.assert_called_once()
    created = shell.store.save.call_args.args[0]
    assert created.name == "lab"
    assert created.policy.permits_address(ip_address("192.0.2.15"))
    assert created.policy.allowed_ports == (80, 443)
    assert shell.workspace is created
    shell._show_context.assert_called_once()


def test_workspace_creation_continues_when_ping_has_no_reply() -> None:
    shell = make_shell(["lab", "192.0.2.15", ""])

    with patch("msfauto.interface.shell._ping_target", return_value="no reply"):
        shell.execute("workspace create")

    shell.store.save.assert_called_once()
    assert shell.workspace.name == "lab"


def test_workspace_creation_rejects_invalid_target_before_ping_or_save() -> None:
    shell = make_shell(["lab", "not-an-ip", ""])

    with patch("msfauto.interface.shell._ping_target") as ping:
        shell.execute("workspace create")

    ping.assert_not_called()
    shell.store.save.assert_not_called()


def test_workspace_creation_does_not_overwrite_existing_name() -> None:
    shell = make_shell(["lab"])
    shell.store.get.return_value = Workspace("lab", build_policy(["192.0.2.1"]))

    shell.execute("workspace create")

    shell.session.prompt.assert_called_once_with("New workspace name: ")
    shell.store.save.assert_not_called()


def test_ping_skips_network_ranges() -> None:
    with patch("msfauto.interface.shell.subprocess.run") as run:
        assert _ping_target("192.0.2.0/24") == "not attempted (network range)"
    run.assert_not_called()


def test_ping_uses_one_bounded_echo_request() -> None:
    with patch("msfauto.interface.shell.subprocess.run") as run:
        run.return_value = SimpleNamespace(returncode=0)
        assert _ping_target("192.0.2.15") == "reachable"
    args, kwargs = run.call_args
    assert args[0] == ["ping", "-c", "1", "-W", "1", "192.0.2.15"]
    assert kwargs["timeout"] == 2.0
