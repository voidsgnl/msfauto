from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from threading import Event, Lock
from typing import Protocol
from uuid import uuid4

from .models import CheckJob, JobEvent, ScopePolicy, utc_now


class JobError(ValueError):
    """Raised when a safe check cannot be scheduled."""


@dataclass(frozen=True)
class CheckRequest:
    workspace: str
    target: str
    port: int
    protocol: str
    module_name: str


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

    def __init__(self, policy: ScopePolicy, max_workers: int = 2, adapter: CheckAdapter | None = None) -> None:
        if max_workers < 1:
            raise JobError("max_workers must be at least one.")
        self.policy = policy
        self.adapter = adapter or DeterministicSafeAdapter()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, CheckJob] = {}
        self._events: dict[str, list[JobEvent]] = {}
        self._cancel: dict[str, Event] = {}
        self._futures: dict[str, Future[None]] = {}
        self._lock = Lock()

    def submit(self, request: CheckRequest) -> str:
        from ipaddress import ip_address

        try:
            address = ip_address(request.target)
        except ValueError as exc:
            raise JobError(f"Invalid target address: {request.target}") from exc
        if not self.policy.permits_address(address):
            raise JobError(f"Target is outside the configured scope: {request.target}")
        if not self.policy.permits_port(request.port):
            raise JobError(f"Port is outside the configured scope: {request.port}")
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
