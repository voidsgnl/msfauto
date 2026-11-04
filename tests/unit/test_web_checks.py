import tempfile
import unittest
from pathlib import Path

from msfauto.enumeration.models import ServiceObservation
from msfauto.storage import WorkspaceStore
from msfauto.vulnerability.web_checks import (
    inspect_web_configuration,
    record_web_configuration_findings,
)


class PassiveWebCheckTests(unittest.TestCase):
    def observation(self, *, protocol="https", headers=None, target="192.0.2.10", port=443):
        return ServiceObservation(
            observation_id="http-app",
            workspace="lab",
            target=target,
            port=port,
            transport="tcp",
            protocol=protocol,
            kind="http_application",
            status="completed",
            attributes={
                "status_code": 200,
                "headers": headers or {"server": "nginx/1.24.0"},
                "title": "Example",
            },
            confidence=8,
        )

    def test_https_missing_headers_and_server_disclosure_are_passive_findings(self):
        results = inspect_web_configuration((self.observation(),))
        ids = {item.check_id for item in results}
        self.assertEqual(ids, {
            "missing-content-security-policy", "missing-nosniff",
            "missing-referrer-policy", "missing-hsts",
            "server-version-disclosure",
        })
        self.assertTrue(all(item.severity in {"info", "low"} for item in results))

    def test_present_headers_suppress_missing_control_findings(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
            "strict-transport-security": "max-age=31536000",
            "server": "nginx",
        }
        self.assertEqual(inspect_web_configuration((self.observation(headers=headers),)), ())

    def test_http_does_not_report_missing_hsts(self):
        results = inspect_web_configuration((
            self.observation(protocol="http", port=80),
        ))
        self.assertNotIn("missing-hsts", {item.check_id for item in results})

    def test_findings_are_evidence_linked_and_deduplicated_by_endpoint_and_check(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspace.sqlite3")
            observations = (self.observation(),)
            first = record_web_configuration_findings("lab", observations, store)
            second = record_web_configuration_findings("lab", observations, store)
            self.assertEqual(len(first), 5)
            self.assertEqual(second, ())
            saved = store.get_findings("lab")
            self.assertEqual(len(saved), 5)
            self.assertTrue(all(item.status == "potential" for item in saved))
            self.assertTrue(all(item.evidence_ids for item in saved))
            self.assertTrue(all(
                store.get_evidence(item.evidence_ids[0]).target == "192.0.2.10"
                for item in saved
            ))


if __name__ == "__main__":
    unittest.main()
