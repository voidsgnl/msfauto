from dataclasses import dataclass


@dataclass(frozen=True)
class JobEvent:
    job_id: str
    timestamp: str
    level: str
    message: str


@dataclass(frozen=True)
class CheckJob:
    job_id: str
    workspace: str
    target: str
    port: int
    protocol: str
    module_name: str
    status: str
    started_at: str
    finished_at: str = ""
    error: str = ""
