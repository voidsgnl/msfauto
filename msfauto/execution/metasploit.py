from __future__ import annotations

import json
from threading import Event
from time import monotonic

from .manager import CheckRequest, CheckResult
from ..integrations.metasploit import MetasploitClient, MetasploitError


# These modules perform bounded service identification only. Do not broaden this
# list based solely on a module's "scanner" path or a user-supplied module name.
SAFE_AUXILIARY_MODULES = frozenset(
    {
        "auxiliary/scanner/ftp/ftp_version",
        "auxiliary/scanner/http/http_version",
        "auxiliary/scanner/mysql/mysql_version",
        "auxiliary/scanner/postgres/postgres_version",
        "auxiliary/scanner/smb/smb_version",
        "auxiliary/scanner/ssh/ssh_version",
        "auxiliary/scanner/ssl/ssl_version",
        "auxiliary/scanner/telnet/telnet_version",
    }
)


class MetasploitSafeAdapter:
    """Execute a narrow allowlist of passive service-identification modules."""

    def __init__(
        self,
        client: MetasploitClient,
        timeout: float = 60.0,
        poll_interval: float = 0.5,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Metasploit adapter timeout must be positive.")
        if poll_interval <= 0:
            raise ValueError("Metasploit adapter poll interval must be positive.")
        self.client = client
        self.timeout = timeout
        self.poll_interval = poll_interval

    def run(self, request: CheckRequest, cancel: Event) -> CheckResult:
        if cancel.is_set():
            return CheckResult("cancelled", "Check was cancelled before Metasploit dispatch.")
        if request.risk != "non-invasive":
            return CheckResult("unsupported", "Metasploit adapter only accepts non-invasive actions.")
        if request.protocol != "tcp":
            return CheckResult("unsupported", "Allowlisted Metasploit checks require TCP.")
        if request.module_name not in SAFE_AUXILIARY_MODULES:
            return CheckResult(
                "unsupported",
                "This Metasploit module is not in MSFAuto's service-identification allowlist.",
            )

        module_path = request.module_name.removeprefix("auxiliary/")
        try:
            metadata = self.client.module_info("auxiliary", module_path)
            if metadata.get("stance") != "passive":
                return CheckResult(
                    "unsupported",
                    "Metasploit did not identify this module as passive; execution was blocked.",
                )
            job_id, run_uuid = self.client.execute_auxiliary(
                module_path,
                {"RHOSTS": request.target, "RPORT": request.port},
            )
            deadline = monotonic() + self.timeout
            while monotonic() < deadline:
                if cancel.is_set():
                    self._stop_job(job_id)
                    return CheckResult("cancelled", "Metasploit check was cancelled.")
                result = self.client.module_results(run_uuid)
                status = result.get("status")
                if status in {"ready", "running"}:
                    cancel.wait(self.poll_interval)
                    continue
                if status == "completed":
                    payload = json.dumps(
                        {"uuid": run_uuid, "result": result.get("result")},
                        sort_keys=True,
                        default=str,
                    )
                    return CheckResult(
                        "completed",
                        "Metasploit service-identification check completed.",
                        output=payload,
                    )
                if status == "errored":
                    detail = str(result.get("error") or "Metasploit reported an execution error.")
                    return CheckResult(
                        "failed",
                        "Metasploit service-identification check failed.",
                        "metasploit-module-error",
                        json.dumps({"uuid": run_uuid, "error": detail}, sort_keys=True),
                    )
                return CheckResult(
                    "failed",
                    "Metasploit returned an unrecognized module-result state.",
                    "metasploit-invalid-result",
                )

            self._stop_job(job_id)
            return CheckResult(
                "failed",
                "Metasploit check exceeded the configured execution timeout.",
                "metasploit-timeout",
            )
        except MetasploitError:
            return CheckResult(
                "failed",
                "Metasploit RPC could not complete the approved service-identification check.",
                "metasploit-rpc-error",
            )

    def _stop_job(self, job_id: int) -> None:
        try:
            self.client.stop_job(job_id)
        except MetasploitError:
            # The job may already have completed or disappeared. The original
            # cancellation/timeout remains the authoritative outcome.
            pass
