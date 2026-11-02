from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Event, Lock
from typing import Protocol
from uuid import uuid4

from ..storage.models import CheckJob, JobEvent, ScopePolicy, utc_now


class JobError(ValueError):
    """Raised when a safe check cannot be scheduled."""


@dataclass(frozen=True)
class CheckRequest:
    workspace: str
    target: str
    port: int
    protocol: str
    module_name: str
    approval_id: str = ""


@dataclass(frozen=True)
class CheckResult:
    status: str
    message: str
    error: str = ""


class CheckAdapter(Protocol):
    def run(self, request: CheckRequest, cancel: Event) -> CheckResult:
        ...


class DeterministicSafeAdapter:
    """Safe, non-invasive classifier for MVP checks."""

    def run(self, request: CheckRequest, cancel: Event) -> CheckResult:
        if cancel.is_set():
            return CheckResult("cancelled", "Check was cancelled before execution.")
        if request.protocol not in {"tcp", "udp"}:
            return CheckResult("skipped", f"Protocol {request.protocol} is not supported by safe checks.")
        if "fail" in request.module_name:
            return CheckResult("failed", "Safe check failed during adapter evaluation.", "simulated-failure")
        if "scanner/" in request.module_name:
            return CheckResult("completed", "Safe check completed (deterministic adapter).")
        return CheckResult("unsupported", "No safe non-invasive adapter supports this module yet.")


class JobManager:
    """Small bounded job manager for future non-invasive check adapters."""

    def __init__(
        self,
        policy: ScopePolicy,
        max_workers: int = 2,
        adapter: CheckAdapter | None = None,
        approval_store=None,
    ) -> None:
        if max_workers < 1:
            raise JobError("max_workers must be at least one.")
        self.policy = policy
        self.adapter = adapter or DeterministicSafeAdapter()
        self.approval_store = approval_store
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, CheckJob] = {}
        self._events: dict[str, list[JobEvent]] = {}
        self._cancel: dict[str, Event] = {}
        self._futures: dict[str, Future[None]] = {}
        self._lock = Lock()

    def _authorization_error(self, request: CheckRequest) -> str:
        from ipaddress import ip_address

        if self.approval_store is None:
            return "Execution blocked: no approval store is configured."
        if not request.approval_id:
            return "Execution blocked: the request has no approval identifier."
        approval = self.approval_store.get_approval(request.approval_id)
        if approval is None:
            return "Execution blocked: no persisted approval exists for this action."
        if (
            approval.decision != "approved"
            or approval.action_id != request.approval_id
            or approval.workspace != request.workspace
            or approval.target != request.target
            or approval.port != request.port
            or approval.protocol != request.protocol
            or approval.module_name != request.module_name
        ):
            return "Execution blocked: the persisted approval does not match this request."
        try:
            address = ip_address(request.target)
        except ValueError:
            return f"Invalid target address: {request.target}"
        if not self.policy.permits_address(address):
            return f"Target is outside the configured scope: {request.target}"
        if not self.policy.permits_port(request.port):
            return f"Port is outside the configured scope: {request.port}"
        return ""

    def submit(self, request: CheckRequest) -> str:
        from ipaddress import ip_address

        authorization_error = self._authorization_error(request)
        if authorization_error:
            raise JobError(authorization_error)
        job_id = uuid4().hex
        job = CheckJob(
            job_id, request.workspace, request.target, request.port, request.protocol,
            request.module_name, "queued", utc_now(),
        )
        with self._lock:
            self._jobs[job_id] = job
            self._events[job_id] = [JobEvent(job_id, utc_now(), "info", "Job queued.")]
            self._cancel[job_id] = Event()
            self._futures[job_id] = self._executor.submit(self._run_check, job_id, request)
        return job_id

    def _run_check(self, job_id: str, request: CheckRequest) -> None:
        with self._lock:
            queued = self._jobs[job_id]
            self._jobs[job_id] = replace(queued, status="running")
            self._events[job_id].append(JobEvent(job_id, utc_now(), "info", "Job running."))
            cancel = self._cancel[job_id]
        authorization_error = self._authorization_error(request)
        if authorization_error:
            result = CheckResult("failed", authorization_error, "authorization-failed")
        else:
            result = self.adapter.run(request, cancel)
        with self._lock:
            job = self._jobs[job_id]
            self._jobs[job_id] = replace(
                job,
                status=result.status,
                finished_at=utc_now(),
                error=result.error,
            )
            self._events[job_id].append(
                JobEvent(job_id, utc_now(), "info" if result.status == "completed" else "warning", result.message)
            )

    def cancel(self, job_id: str) -> None:
        with self._lock:
            if job_id not in self._jobs:
                raise JobError(f"Unknown job: {job_id}")
            self._cancel[job_id].set()
            job = self._jobs[job_id]
            if job.status in {"queued", "running"}:
                self._jobs[job_id] = replace(job, status="cancelled", finished_at=utc_now())
                self._events[job_id].append(JobEvent(job_id, utc_now(), "info", "Job cancelled."))

    def get(self, job_id: str) -> CheckJob:
        with self._lock:
            if job_id not in self._jobs:
                raise JobError(f"Unknown job: {job_id}")
            return self._jobs[job_id]

    def wait(self, job_id: str, timeout: float | None = None) -> CheckJob:
        with self._lock:
            future = self._futures.get(job_id)
        if future is None:
            raise JobError(f"Unknown job: {job_id}")
        future.result(timeout=timeout)
        return self.get(job_id)

    def events(self, job_id: str) -> tuple[JobEvent, ...]:
        with self._lock:
            if job_id not in self._events:
                raise JobError(f"Unknown job: {job_id}")
            return tuple(self._events[job_id])

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)
