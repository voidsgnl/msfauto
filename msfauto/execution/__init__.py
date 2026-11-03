"""Execution adapters and durable lifecycle primitives."""

from .exploit_dispatch import (
    ExploitDispatchError,
    ExploitDispatchUncertain,
    MetasploitExploitDispatcher,
)
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
    reconcile_uncertain_execution,
    recover_interrupted_dispatches,
    request_exploit_cancellation,
)
from .reconciliation import (
    ExploitPollResult,
    ExploitReconciliationError,
    MetasploitExploitReconciler,
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
    "ExploitDispatchError",
    "ExploitDispatchUncertain",
    "ExploitExecution",
    "ExploitExecutionError",
    "ExploitExecutionEvent",
    "ExploitPollResult",
    "ExploitReconciliationError",
    "JobError",
    "JobManager",
    "MetasploitExploitDispatcher",
    "MetasploitExploitReconciler",
    "MetasploitSafeAdapter",
    "begin_exploit_dispatch",
    "finish_exploit_execution",
    "mark_dispatch_uncertain",
    "mark_exploit_running",
    "prepare_exploit_execution",
    "reconcile_uncertain_execution",
    "recover_interrupted_dispatches",
    "request_exploit_cancellation",
    "sanitize_adapter_output",
]
