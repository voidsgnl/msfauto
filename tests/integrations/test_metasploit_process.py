from __future__ import annotations

from unittest.mock import Mock

import pytest

from msfauto.integrations.metasploit.client import MetasploitError
from msfauto.integrations.metasploit.process import MetasploitProcessManager


def test_starts_local_rpc_with_secret_in_environment_not_process_arguments(monkeypatch) -> None:
    process = Mock()
    process.poll.return_value = None
    monkeypatch.setattr("msfauto.integrations.metasploit.process.shutil.which", lambda _: "/usr/bin/msfrpcd")
    popen = Mock(return_value=process)
    monkeypatch.setattr("msfauto.integrations.metasploit.process.subprocess.Popen", popen)
    monkeypatch.setattr(MetasploitProcessManager, "_is_listening", lambda self, host, port: False)
    manager = MetasploitProcessManager("http://127.0.0.1:55553/api/1.0")
    monkeypatch.setattr(manager, "_wait_until_ready", lambda host, port: None)

    username, password = manager.start()

    args, kwargs = popen.call_args
    assert args[0] == [
        "/usr/bin/msfrpcd", "-f", "-a", "127.0.0.1", "-p", "55553", "-S"
    ]
    assert kwargs["env"]["MSF_RPC_USER"] == username == "msf"
    assert kwargs["env"]["MSF_RPC_PASS"] == password
    assert password not in args[0]
    assert manager.started is True

    manager.stop()
    process.terminate.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=5)


def test_existing_service_is_reused_without_spawning_another(monkeypatch) -> None:
    monkeypatch.setattr(MetasploitProcessManager, "_is_listening", lambda self, host, port: True)
    popen = Mock()
    monkeypatch.setattr("msfauto.integrations.metasploit.process.subprocess.Popen", popen)
    manager = MetasploitProcessManager("http://127.0.0.1:55553/api/1.0")

    with pytest.raises(MetasploitError, match="already listening"):
        manager.start()

    popen.assert_not_called()
    assert manager.started is False


def test_remote_rpc_endpoint_is_never_started_locally() -> None:
    manager = MetasploitProcessManager("https://192.0.2.10:55553/api/1.0")

    with pytest.raises(MetasploitError, match="cannot be started"):
        manager.start()


def test_remote_rpc_endpoint_uses_supplied_credentials() -> None:
    manager = MetasploitProcessManager("https://192.0.2.10:55553/api/1.0")

    assert manager.start("operator", "secret") == ("operator", "secret")
    assert manager.process is None
