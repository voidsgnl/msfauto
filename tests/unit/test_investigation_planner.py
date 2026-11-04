import unittest

from msfauto.assessment.investigation import build_investigation_steps, plan_service_investigation
from msfauto.enumeration.models import ServiceObservation
from msfauto.storage.models import Service


def observation(protocol: str, status: str, attributes: dict[str, object] | None = None):
    return ServiceObservation(
        observation_id="obs-1", workspace="lab", target="192.0.2.10",
        port=443, transport="tcp", protocol=protocol,
        kind=f"{protocol}_response", status=status, attributes=attributes or {},
    )


class InvestigationPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.web = Service(443, "tcp", "open", "https", "nginx", "1.24", tunnel="ssl")

    def test_missing_observation_recommends_identification(self) -> None:
        step = plan_service_investigation("192.0.2.10", self.web, ())
        self.assertEqual(step.state, "INSUFFICIENT")
        self.assertEqual(step.action, "manual_service_identification")
        self.assertFalse(step.automated)

    def test_failed_observation_does_not_recommend_automatic_retry(self) -> None:
        item = observation("tls", "failed", {
            "error_stage": "tls_handshake", "failure_explanation": "Handshake timed out.",
        })
        step = plan_service_investigation("192.0.2.10", self.web, (item,))
        self.assertEqual(step.state, "NEEDS_REVIEW")
        self.assertEqual(step.action, "inspect_incomplete_observation:tls_handshake")
        self.assertIn("No automatic retry", step.rationale)

    def test_web_fingerprint_selects_technology_review(self) -> None:
        item = observation("http_application", "completed", {
            "title": "Example", "technologies": [{"name": "Next.js", "confidence": 9}],
        })
        step = plan_service_investigation("192.0.2.10", self.web, (item,))
        self.assertEqual(step.state, "READY")
        self.assertEqual(step.action, "review_technology_specific_checks")
        self.assertIn("Next.js", step.rationale)
        self.assertIn("Metasploit", step.expected_evidence)

    def test_successful_http_app_evidence_takes_precedence_over_tls_failure(self) -> None:
        tls_failure = observation("tls", "failed", {"error": "handshake timeout"})
        app_success = observation("http_application", "completed", {
            "title": "Portal", "technologies": [{"name": "React", "confidence": 8}],
        })
        step = plan_service_investigation(
            "192.0.2.10", self.web, (tls_failure, app_success),
        )
        self.assertEqual(step.action, "review_technology_specific_checks")
        self.assertIn("React", step.rationale)

    def test_unfingerprinted_web_app_needs_surface_mapping(self) -> None:
        item = observation("http_application", "completed", {"title": "Portal"})
        step = plan_service_investigation("192.0.2.10", self.web, (item,))
        self.assertEqual(step.state, "NEEDS_REVIEW")
        self.assertEqual(step.action, "map_web_application_surface")

    def test_build_steps_prioritizes_review_and_skips_closed_ports(self) -> None:
        failed = observation("tls", "failed", {"error": "timeout"})
        closed = Service(25, "tcp", "closed", "smtp")
        steps = build_investigation_steps(
            (("192.0.2.10", self.web), ("192.0.2.10", closed)), (failed,),
        )
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].state, "NEEDS_REVIEW")


if __name__ == "__main__":
    unittest.main()
