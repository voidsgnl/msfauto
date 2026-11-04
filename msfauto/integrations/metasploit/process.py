from __future__ import annotations

import ipaddress
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse

from .client import MetasploitError


class MetasploitProcessManager:
    """Start and supervise a local msfrpcd child for one MSFAuto session."""

    def __init__(self, url: str, startup_timeout: float = 30.0) -> None:
        self.url = url
        self.startup_timeout = startup_timeout
        self.process: subprocess.Popen[bytes] | None = None
        self._log = None
        self.started = False

    def _endpoint(self) -> tuple[str, int, str]:
        parsed = urlparse(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise MetasploitError("Metasploit RPC URL must be an HTTP(S) URL with a hostname.")
        return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), parsed.scheme

    @staticmethod
    def _is_loopback(host: str) -> bool:
        if host.casefold() == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _is_listening(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            return False

    def _wait_until_ready(self, host: str, port: int) -> None:
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                detail = self._read_startup_log()
                raise MetasploitError(
                    "msfrpcd exited before its RPC socket became ready."
                    + (f" Details: {detail}" if detail else "")
                )
            if self._is_listening(host, port):
                return
            time.sleep(0.2)
        self.stop()
        detail = self._read_startup_log()
        raise MetasploitError(
            f"Timed out waiting {self.startup_timeout:g}s for msfrpcd on {host}:{port}."
            + (f" Details: {detail}" if detail else "")
        )

    def _read_startup_log(self) -> str:
        if self._log is None:
            return ""
        try:
            self._log.flush()
            self._log.seek(0)
            return self._log.read(8192).strip()
        except (OSError, ValueError):
            return ""

    def start(self, username: str = "", password: str = "") -> tuple[str, str]:
        host, port, scheme = self._endpoint()
        if not self._is_loopback(host):
            if not username or not password:
                raise MetasploitError(
                    "A remote Metasploit RPC server cannot be started by MSFAuto; "
                    "configure its existing RPC username and password."
                )
            return username, password

        if self._is_listening(host, port):
            if not username or not password:
                raise MetasploitError(
                    "A Metasploit RPC service is already listening, but its credentials "
                    "are not configured. Set MSFAUTO_METASPLOIT_USERNAME and "
                    "MSFAUTO_METASPLOIT_PASSWORD to connect to that existing service."
                )
            return username, password

        executable = shutil.which("msfrpcd")
        if executable is None:
            raise MetasploitError(
                "Metasploit RPC is not running and 'msfrpcd' was not found in PATH. "
                "Install Metasploit Framework or configure an existing RPC endpoint."
            )

        if not username and not password:
            username = "msf"
            password = secrets.token_urlsafe(32)
        elif not username or not password:
            raise MetasploitError(
                "Both MSFAUTO_METASPLOIT_USERNAME and "
                "MSFAUTO_METASPLOIT_PASSWORD must be set together."
            )

        child_env = os.environ.copy()
        # Current Metasploit msfrpcd accepts these environment variables, avoiding
        # password exposure in process arguments and command-line listings.
        child_env["MSF_RPC_USER"] = username
        child_env["MSF_RPC_PASS"] = password
        command = [executable, "-f", "-a", host, "-p", str(port)]
        if scheme == "http":
            command.append("-S")

        self._log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                env=child_env,
                start_new_session=True,
            )
        except OSError as exc:
            self._log.close()
            self._log = None
            raise MetasploitError(f"Unable to start msfrpcd: {exc}") from exc

        self.started = True
        try:
            self._wait_until_ready(host, port)
        except Exception:
            self.stop()
            raise
        return username, password

    def stop(self) -> None:
        process = self.process
        self.process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        self.started = False
        if self._log is not None:
            self._log.close()
            self._log = None
