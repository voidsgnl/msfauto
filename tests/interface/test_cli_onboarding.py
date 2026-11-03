import io
import unittest
from contextlib import redirect_stdout

from msfauto.cli import display_next_steps
from msfauto.scope import build_policy
from msfauto.storage.models import Workspace


class OnboardingTests(unittest.TestCase):
    def test_next_steps_explain_the_workflow(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            display_next_steps(Workspace("lab", build_policy(["192.168.56.0/24"])))

        text = output.getvalue()
        self.assertIn("Run Nmap automatically", text)
        self.assertIn("Build a read-only assessment plan", text)
        self.assertIn("Run bounded non-invasive checks", text)
        self.assertIn("Open the dashboard", text)
