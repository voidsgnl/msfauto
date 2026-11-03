"""Policy-bounded job execution."""
from .manager import (
    CheckRequest,
    CheckResult,
    DeterministicSafeAdapter,
    JobError,
    JobManager,
)
from .metasploit import SAFE_AUXILIARY_MODULES, MetasploitSafeAdapter
from .output import (
    AdapterOutputError,
    MAX_ADAPTER_OUTPUT_BYTES,
    sanitize_adapter_output,
)

__all__ = [
    "AdapterOutputError",
    "CheckRequest",
    "CheckResult",
    "DeterministicSafeAdapter",
    "JobError",
    "JobManager",
    "MAX_ADAPTER_OUTPUT_BYTES",
    "MetasploitSafeAdapter",
    "SAFE_AUXILIARY_MODULES",
    "sanitize_adapter_output",
]
