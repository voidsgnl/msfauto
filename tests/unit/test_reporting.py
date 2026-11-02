import json
import os
import sys
import tempfile
import unittest
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from msfauto.cli import main
from msfauto.evidence import EvidenceCollector
from msfauto.findings import create_finding
from msfauto.reporting import ReportError, build_report, write_report
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import Host, Service, Workspace


class ReportingTests(unittest.TestCase):
    def test_json_report_is_workspace_scoped_and_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WorkspaceStore(root / "workspaces.sqlite3")
            store.save(Workspace("lab", build_policy(["192.168.56.0/24"], "22")))
            store.save(Workspace("other", build_policy(["10.0.0.0/8"])))
            store.save_hosts(
                "lab",
                (Host(ip_address("192.168.56.10"), "up", "lab-host", (
                    Service(22, "tcp", "open", "ssh", "OpenSSH", "9.0"),
                )),),
            )
            record = EvidenceCollector(store).collect(
                "lab", "unit-test", "192.168.56.10", "text/plain",
                "password=hunter2 observed", b"evidence",
                {"api_token": "do-not-export", "port": 22},
            )
            create_finding(
                store, "lab", "SSH service observed",
                "Review the service configuration.", evidence_ids=(record.evidence_id,),
            )
            EvidenceCollector(store).collect(
                "other", "unit-test", "10.0.0.1", "text/plain",
                "Other workspace artifact", b"other",
            )

            report = build_report(store, "lab")
            destination = write_report(store, "lab", "json", root / "report.json")
            saved = json.loads(destination.read_text(encoding="utf-8"))

            self.assertEqual(report["summary"]["hosts"], 1)
            self.assertEqual(report["summary"]["findings"], 1)
            self.assertEqual(report["summary"]["evidence_records"], 1)
            self.assertEqual(report["evidence"][0]["integrity"], "verified")
            self.assertEqual(saved["evidence"][0]["metadata"]["api_token"], "[REDACTED]")
            self.assertIn("[REDACTED]", saved["evidence"][0]["summary"])
            self.assertNotIn("do-not-export", destination.read_text(encoding="utf-8"))
            self.assertNotIn("10.0.0.1", destination.read_text(encoding="utf-8"))

    def test_markdown_report_includes_integrity_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WorkspaceStore(root / "workspaces.sqlite3")
            store.save(Workspace("lab", build_policy(["192.168.56.0/24"])))
            record = EvidenceCollector(store).collect(
                "lab", "unit-test", "192.168.56.10", "text/plain",
                "Observed response", b"original",
            )
            Path(record.artifact_path).write_bytes(b"modified")

            destination = write_report(store, "lab", "markdown", root / "report.md")
            rendered = destination.read_text(encoding="utf-8")

            self.assertIn("Evidence integrity failures", rendered)
            self.assertIn("| Evidence ID | Type | Target | Integrity | SHA-256 |", rendered)
            self.assertIn("| failed |", rendered)
            self.assertIn("not, by themselves, proof of a vulnerability", rendered)


    def test_cli_exports_workspace_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WorkspaceStore(root / "workspaces.sqlite3")
            store.save(Workspace("lab", build_policy(["192.168.56.0/24"])))
            output = root / "cli-report.json"
            with (
                patch.dict(os.environ, {"MSFAUTO_HOME": directory}),
                patch.object(
                    sys, "argv",
                    ["msfauto", "--workspace", "lab", "--report", "json", "--report-output", str(output)],
                ),
            ):
                result = main()

            self.assertEqual(result, 0)
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["workspace"]["name"], "lab")

    def test_report_requires_matching_extension_and_existing_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspaces.sqlite3")
            with self.assertRaisesRegex(ReportError, "Workspace not found"):
                build_report(store, "missing")
            store.save(Workspace("lab", build_policy(["192.168.56.0/24"])))
            with self.assertRaisesRegex(ReportError, "must use the .json extension"):
                write_report(store, "lab", "json", Path(directory) / "report.md")


if __name__ == "__main__":
    unittest.main()
