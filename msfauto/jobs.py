from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from threading import Event, Lock
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


class JobManager:
    """Small bounded job manager for future non-invasive check adapters."""

    def __init__(self, policy: ScopePolicy, max_workers: int = 2) -> None:
        if max_workers < 1:
            raise JobError("max_workers must be at least one.")
        self.policy = policy
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
            self._futures[job_id] = self._executor.submit(self._run_placeholder, job_id)
        return job_id

    def _run_placeholder(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            self._jobs[job_id] = CheckJob(**{**job.__dict__, "status": "unsupported"})
            self._events[job_id].append(
                JobEvent(job_id, utc_now(), "warning", "No check adapter is enabled in this MVP.")
            )

    def cancel(self, job_id: str) -> None:
        with self._lock:
            if job_id not in self._jobs:
                raise JobError(f"Unknown job: {job_id}")
            self._cancel[job_id].set()
            job = self._jobs[job_id]
            if job.status in {"queued", "running"}:
                self._jobs[job_id] = CheckJob(**{**job.__dict__, "status": "cancelled", "finished_at": utc_now()})
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
