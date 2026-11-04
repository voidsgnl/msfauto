from __future__ import annotations

from dataclasses import dataclass

from ..enumeration.models import ServiceObservation
from ..storage.models import Service


@dataclass(frozen=True)
class InvestigationStep:
    """Evidence-driven next step for one discovered service; never dispatches work."""

    target: str
    port: int
    transport: str
    service: str
    state: str
    action: str
    rationale: str
    expected_evidence: str
    automated: bool = False


def _is_web_service(service: Service, observations: tuple[ServiceObservation, ...]) -> bool:
    label = f"{service.name} {service.product}".lower()
    return (
        "http" in label
        or service.port in {80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9443}
        or any(item.protocol in {"http", "https", "http_application"} for item in observations)
    )


def plan_service_investigation(
    target: str,
    service: Service,
    observations: tuple[ServiceObservation, ...],
) -> InvestigationStep:
    """Choose one explainable next step from persisted evidence, without probing."""
    endpoint = tuple(
        item for item in observations
        if item.target == target and item.port == service.port
        and item.transport == service.protocol
    )
    web_service = _is_web_service(service, endpoint)
    app_observation = next(
        (
            item for item in endpoint
            if item.protocol == "http_application" and item.status == "completed"
        ),
        None,
    ) if web_service else None
    # A successful application response is more useful than a failed TLS-only
    # side observation on the same HTTPS endpoint.
    latest = app_observation or (endpoint[0] if endpoint else None)
    fingerprint = " ".join(
        value for value in (service.product, service.version, service.name) if value
    ) or "unidentified service"

    if latest is None:
        return InvestigationStep(
            target, service.port, service.protocol, fingerprint, "INSUFFICIENT",
            "manual_service_identification",
            "No protocol observation is stored for this open service.",
            "A confirmed protocol identity, product, version, and service-specific response.",
        )

    attrs = latest.attributes or {}
    if latest.status in {"failed", "partial"}:
        stage = str(attrs.get("error_stage") or "protocol response")
        detail = str(
            attrs.get("failure_explanation") or attrs.get("error")
            or "The response did not provide complete evidence."
        )
        return InvestigationStep(
            target, service.port, service.protocol, fingerprint, "NEEDS_REVIEW",
            f"inspect_incomplete_observation:{stage}",
            f"The {stage} stage did not complete: {detail} No automatic retry is scheduled.",
            "Operator-reviewed failure context and a decision whether to adjust the bounded protocol timeout or investigate manually.",
        )

    if latest.status == "unsupported":
        return InvestigationStep(
            target, service.port, service.protocol, fingerprint, "NEEDS_REVIEW",
            "manual_protocol_investigation",
            str(attrs.get("reason") or "No dedicated protocol adapter is available."),
            "A verified service fingerprint and protocol-specific evidence.",
        )

    if _is_web_service(service, endpoint):
        app_observation = next(
            (item for item in endpoint if item.protocol == "http_application"),
            None,
        )
        if app_observation is None:
            return InvestigationStep(
                target, service.port, service.protocol, fingerprint, "INSUFFICIENT",
                "collect_web_application_fingerprint",
                "The service appears to be HTTP(S), but no HTML application fingerprint is recorded.",
                "HTTP status, redirect chain, page title, server/runtime hints, technologies, and bounded resource references.",
            )
        app_attrs = app_observation.attributes or {}
        technologies = app_attrs.get("technologies", [])
        technology_names = [
            str(item.get("name")) for item in technologies
            if isinstance(item, dict) and item.get("name")
        ] if isinstance(technologies, list) else []
        title = str(app_attrs.get("title") or "").strip()
        if technology_names:
            return InvestigationStep(
                target, service.port, service.protocol, fingerprint, "READY",
                "review_technology_specific_checks",
                "Application fingerprint evidence identifies: " + ", ".join(technology_names[:6]) + ".",
                "Version/configuration indicators and technology-specific exposure evidence for selecting applicable Metasploit auxiliary/check modules.",
            )
        return InvestigationStep(
            target, service.port, service.protocol, fingerprint, "NEEDS_REVIEW",
            "map_web_application_surface",
            "An HTTP application response was captured, but no reliable framework or CMS identity was established."
            + (f" Page title: {title}." if title else ""),
            "Same-origin routes, forms, linked assets, framework markers, and authentication entry points.",
        )

    if latest.status == "completed":
        return InvestigationStep(
            target, service.port, service.protocol, fingerprint, "READY",
            "correlate_service_evidence",
            "A protocol response is available; correlate its product/version and capabilities with vulnerability intelligence and relevant Metasploit module requirements.",
            "Exact product/version identity, affected-version evidence, module prerequisites, and check support.",
        )

    return InvestigationStep(
        target, service.port, service.protocol, fingerprint, "INSUFFICIENT",
        "review_service_observation",
        f"Observation status '{latest.status}' does not provide a supported automated next step.",
        "A reviewed service observation and a documented follow-up action.",
    )


def build_investigation_steps(
    services: tuple[tuple[str, Service], ...],
    observations: tuple[ServiceObservation, ...],
) -> tuple[InvestigationStep, ...]:
    """Build one deterministic next-step recommendation per open service."""
    steps = [
        plan_service_investigation(target, service, observations)
        for target, service in services
        if service.state == "open"
    ]
    priority = {"NEEDS_REVIEW": 0, "INSUFFICIENT": 1, "READY": 2}
    steps.sort(key=lambda item: (priority.get(item.state, 3), item.target, item.port))
    return tuple(steps)
