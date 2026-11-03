"""Execution adapters and durable lifecycle primitives."""

from .lifecycle import (
    EXECUTION_STATES,
    TERMINAL_STATES,
    ExploitExecution,
    ExploitExecutionError,
    ExploitExecutionEvent,
    begin_exploit_dispatch,
    finish_exploit_execution,
    mark_dispatch_uncertain,
    mark_exploit_running,
    prepare_exploit_execution,
    recover_interrupted_dispatches,
    reconcile_uncertain_execution,
    request_exploit_cancellation,
)
from .manager import (
    CheckRequest,
    CheckResult,
    DeterministicSafeAdapter,
    JobError,
    JobManager,
)
from .metasploit import SAFE_AUXILIARY_MODULES, MetasploitSafeAdapter
from .output import (
    MAX_ADAPTER_OUTPUT_BYTES,
    AdapterOutputError,
    sanitize_adapter_output,
)

__all__ = [
    "EXECUTION_STATES",
    "MAX_ADAPTER_OUTPUT_BYTES",
    "SAFE_AUXILIARY_MODULES",
    "TERMINAL_STATES",
    "AdapterOutputError",
    "CheckRequest",
    "CheckResult",
    "DeterministicSafeAdapter",
    "ExploitExecution",
    "ExploitExecutionError",
    "ExploitExecutionEvent",
    "JobError",
    "JobManager",
    "MetasploitSafeAdapter",
    "begin_exploit_dispatch",
    "finish_exploit_execution",
    "mark_dispatch_uncertain",
    "mark_exploit_running",
    "prepare_exploit_execution",
    "recover_interrupted_dispatches",
    "reconcile_uncertain_execution",
    "request_exploit_cancellation",
    "sanitize_adapter_output",
]
