import io
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from threading import Event

from rich.console import Console

from msfauto.cli import display_next_steps
from msfauto.enumeration.models import ServiceObservation
from msfauto.interface.shell import CommandShell
from msfauto.interface.tasks import TaskManager
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore
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

    def test_cancelled_operation_exception_keeps_cancelled_status(self) -> None:
        manager = TaskManager(workers=1)
        started = Event()
        try:
            def operation(cancel, _emit):
                started.set()
                cancel.wait(2)
                raise RuntimeError("scanner stopped")

            task = manager.submit("cancelled", operation, cancellable=True)
            self.assertTrue(started.wait(2))
            self.assertTrue(manager.cancel(task.task_id))
            assert task.future is not None
            with self.assertRaisesRegex(RuntimeError, "scanner stopped"):
                task.future.result(timeout=2)
            self.assertEqual(task.status, "cancelled")
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



class ObservationConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = WorkspaceStore(Path(self.tempdir.name) / "workspace.sqlite3")
        self.workspace = Workspace("lab", build_policy(["127.0.0.1"]))
        self.shell = CommandShell(self.store, self.workspace)
        self.shell.mode = "discovery"
        self.observations = (
            ServiceObservation(
                observation_id="observation-abc123",
                workspace="lab",
                target="127.0.0.1",
                port=465,
                transport="tcp",
                protocol="smtp",
                kind="smtp_capabilities",
                status="completed",
                attributes={"greeting": "220 mail.example ESMTP", "capabilities": ["SIZE", "STARTTLS"]},
                confidence=8,
                observed_at="2026-11-04T10:00:00+00:00",
            ),
            ServiceObservation(
                observation_id="observation-def456",
                workspace="lab",
                target="127.0.0.2",
                port=22,
                transport="tcp",
                protocol="ssh",
                kind="ssh_banner",
                status="completed",
                attributes={"banner": "SSH-2.0-OpenSSH_9.8"},
                confidence=9,
                observed_at="2026-11-04T10:01:00+00:00",
            ),
        )
        self.store.save_service_observations(self.observations)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_observations_list_is_available_in_discovery_mode(self):
        output = io.StringIO()
        self.shell.console = Console(file=output)
        self.shell.execute("observations list")
        rendered = output.getvalue()
        self.assertIn("observa", rendered)
        self.assertIn("127.0.0.1", rendered)
        self.assertIn("smtp_capabilities", rendered)

    def test_observations_host_filters_to_exact_target(self):
        output = io.StringIO()
        self.shell.console = Console(file=output)
        self.shell.execute("observations host 127.0.0.1")
        rendered = output.getvalue()
        self.assertIn("observation-a", rendered)
        self.assertNotIn("22/tcp", rendered)
        self.assertIn("465/tcp", rendered)

    def test_observations_show_resolves_prefix_and_displays_attributes(self):
        output = io.StringIO()
        self.shell.console = Console(file=output)
        self.shell.execute("observations show observation-abc")
        rendered = output.getvalue()
        self.assertIn("mail.example", rendered)
        self.assertIn("STARTTLS", rendered)

    def test_observations_show_rejects_ambiguous_prefix(self):
        output = io.StringIO()
        self.shell.console = Console(file=output)
        self.shell.execute("observations show observation-")
        self.assertIn("ambiguous", output.getvalue().casefold())
