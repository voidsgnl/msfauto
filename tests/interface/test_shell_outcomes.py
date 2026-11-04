import tempfile
import unittest
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from msfauto.interface.shell import CommandShell


class FakeStore:
    def __init__(self, path):
        self.path = path
        self.execution = SimpleNamespace(
            execution_id="execution-1", workspace="lab", state="completed"
        )

    def get_exploit_execution(self, execution_id):
        return self.execution if execution_id == self.execution.execution_id else None


class ExploitOutcomeShellTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = FakeStore(Path(self.temp_dir.name) / "workspace.sqlite3")
        self.shell = CommandShell(self.store, SimpleNamespace(name="lab"))
        self.output = StringIO()
        self.shell.console = Console(
            file=self.output, force_terminal=False, color_system=None
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_record_command_passes_explicit_target_evidence_to_validator(self):
        assessment = SimpleNamespace(
            assessment_id="assessment-1", verdict="confirmed"
        )
        with patch("msfauto.interface.shell.ExploitOutcomeValidator") as validator_type:
            validator_type.return_value.record.return_value = assessment
            self.shell.execute(
                'exploits outcome record execution-1 confirmed '
                'module-check "SSH banner probe" proof-1 analyst '
                '"Expected target banner observed"'
            )

        validator_type.return_value.record.assert_called_once_with(
            "execution-1",
            verdict="confirmed",
            verifier="module-check",
            method="SSH banner probe",
            evidence_ids=("proof-1",),
            actor="analyst",
            rationale="Expected target banner observed",
        )
        self.assertIn("Framework execution state was not changed", self.output.getvalue())

    def test_outcome_list_is_limited_to_execution_in_active_workspace(self):
        assessment = SimpleNamespace(
            assessment_id="assessment-1",
            verdict="inconclusive",
            verifier="analyst",
            method="evidence review",
            evidence_ids=(),
            actor="operator",
            assessed_at="2026-11-04T10:00:00+00:00",
        )
        with patch("msfauto.interface.shell.ExploitOutcomeValidator") as validator_type:
            validator_type.return_value.get_for_execution.return_value = (assessment,)
            self.shell.execute("exploits outcome list execution-1")

        validator_type.return_value.get_for_execution.assert_called_once_with(
            "execution-1"
        )
        self.assertIn("inconclusive", self.output.getvalue())

    def test_outcome_command_rejects_execution_from_another_workspace(self):
        self.store.execution.workspace = "other"
        with patch("msfauto.interface.shell.ExploitOutcomeValidator") as validator_type:
            self.shell.execute("exploits outcome list execution-1")

        validator_type.assert_not_called()
        self.assertIn("not found in this workspace", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
