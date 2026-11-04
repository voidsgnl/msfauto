import io
import unittest
from threading import Event
from contextlib import redirect_stdout

from msfauto.cli import display_next_steps
from msfauto.interface.tasks import TaskManager
from msfauto.scope import build_policy
from msfauto.storage.models import Workspace


class OnboardingTests(unittest.TestCase):
    def test_next_steps_explain_the_workflow(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            display_next_steps(Workspace("lab", build_policy(["192.168.56.0/24"])))

        text = output.getvalue()
        self.assertIn("Type 'help'", text)


class ConsoleTaskTests(unittest.TestCase):
    def test_task_streams_events_and_stores_result(self) -> None:
        manager = TaskManager(workers=1)
        try:
            task = manager.submit(
                "sample",
                lambda _cancel, emit: (emit("phase one"), 42)[1],
            )
            assert task.future is not None
            self.assertEqual(task.future.result(timeout=2), 42)
            self.assertEqual(task.status, "completed")
            messages = []
            while not task.events.empty():
                messages.append(task.events.get_nowait().message)
            self.assertIn("sample started.", messages)
            self.assertIn("phase one", messages)
            self.assertIn("sample completed.", messages)
        finally:
            manager.close()

    def test_task_records_failure(self) -> None:
        manager = TaskManager(workers=1)
        try:
            def fail(_cancel, _emit):
                raise RuntimeError("expected failure")

            task = manager.submit("failing", fail)
            assert task.future is not None
            with self.assertRaisesRegex(RuntimeError, "expected failure"):
                task.future.result(timeout=2)
            self.assertEqual(task.status, "failed")
            self.assertEqual(task.error, "expected failure")
        finally:
            manager.close()

    def test_cancellation_is_cooperative_and_opt_in(self) -> None:
        manager = TaskManager(workers=1)
        started = Event()
        try:
            task = manager.submit(
                "cooperative",
                lambda cancel, _emit: (started.set(), cancel.wait(2))[1],
                cancellable=True,
            )
            self.assertTrue(started.wait(2))
            self.assertTrue(manager.cancel(task.task_id))
            assert task.future is not None
            task.future.result(timeout=2)
            self.assertEqual(task.status, "cancelled")
            self.assertTrue(task.cancel_event.is_set())

            protected = manager.submit("protected", lambda _cancel, _emit: None)
            self.assertFalse(manager.cancel(protected.task_id))
            assert protected.future is not None
            protected.future.result(timeout=2)
        finally:
            manager.close()
