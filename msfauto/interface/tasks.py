from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from queue import Queue
from threading import Event, RLock
from typing import Callable, TypeVar
from uuid import uuid4

T = TypeVar("T")


@dataclass(frozen=True)
class TaskEvent:
    task_id: str
    message: str
    level: str = "info"


@dataclass
class ConsoleTask:
    task_id: str
    name: str
    status: str = "queued"
    cancellable: bool = False
    cancel_event: Event = field(default_factory=Event)
    events: Queue[TaskEvent] = field(default_factory=Queue)
    future: Future[object] | None = None
    result: object | None = None
    error: str = ""


class TaskManager:
    """Small in-process task registry for responsive console workflows."""

    def __init__(self, workers: int = 2) -> None:
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="msfauto")
        self._tasks: dict[str, ConsoleTask] = {}
        self._lock = RLock()
        self._closed = False

    def submit(
        self,
        name: str,
        operation: Callable[[Event, Callable[[str, str], None]], T],
        *,
        cancellable: bool = False,
    ) -> ConsoleTask:
        with self._lock:
            if self._closed:
                raise RuntimeError("Task manager is closed.")
            task = ConsoleTask(uuid4().hex[:12], name, cancellable=cancellable)
            self._tasks[task.task_id] = task

        def emit(message: str, level: str = "info") -> None:
            task.events.put(TaskEvent(task.task_id, message, level))

        def run() -> T:
            task.status = "running"
            emit(f"{name} started.", "info")
            try:
                result = operation(task.cancel_event, emit)
                task.result = result
                task.status = "cancelled" if task.cancel_event.is_set() else "completed"
                emit(f"{name} {task.status}.", "warning" if task.status == "cancelled" else "success")
                return result
            except Exception as exc:
                task.error = str(exc)
                task.status = "failed"
                emit(f"{name} failed: {exc}", "error")
                raise

        task.future = self._pool.submit(run)
        return task

    def get(self, task_id: str) -> ConsoleTask | None:
        with self._lock:
            return self._tasks.get(task_id)

    def list(self) -> tuple[ConsoleTask, ...]:
        with self._lock:
            return tuple(self._tasks.values())

    def cancel(self, task_id: str) -> bool:
        task = self.get(task_id)
        if task is None or not task.cancellable or task.status not in {"queued", "running"}:
            return False
        task.cancel_event.set()
        task.status = "cancelling"
        task.events.put(TaskEvent(task_id, "Cancellation requested; waiting for a safe checkpoint.", "warning"))
        return True

    def close(self) -> None:
        with self._lock:
            self._closed = True
        self._pool.shutdown(wait=True, cancel_futures=False)
