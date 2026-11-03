"""Policy-bounded job execution."""
from .manager import (
    CheckRequest,
    CheckResult,
    DeterministicSafeAdapter,
    JobError,
    JobManager,
)
from .metasploit import MetasploitSafeAdapter, SAFE_AUXILIARY_MODULES
from .output import (
    MAX_ADAPTER_OUTPUT_BYTES,
    AdapterOutputError,
    sanitize_adapter_output,
)

__all__ = [
    "MAX_ADAPTER_OUTPUT_BYTES",
    "AdapterOutputError",
    "CheckRequest",
    "CheckResult",
    "DeterministicSafeAdapter",
    "JobError",
    "JobManager",
    "MetasploitSafeAdapter",
    "SAFE_AUXILIARY_MODULES",
    "sanitize_adapter_output",
]
