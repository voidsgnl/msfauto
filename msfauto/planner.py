from __future__ import annotations

from .models import AssessmentPlan, Host, ModuleMetadata, Recommendation


def _module_text(module: ModuleMetadata) -> str:
    metadata = " ".join(str(value) for value in module.metadata.values())
    return f"{module.module_name} {metadata}".lower()


def build_plan(
    workspace: str,
    hosts: tuple[Host, ...],
    modules: tuple[ModuleMetadata, ...],
) -> AssessmentPlan:
    recommendations: list[Recommendation] = []
    for host in hosts:
        for service in host.services:
            if service.state != "open":
                continue
            service_terms = {service.name.lower(), service.product.lower()}
            service_terms.discard("")
            for module in modules:
                text = _module_text(module)
                matches = sorted(term for term in service_terms if term in text)
                if not matches:
                    continue
                confidence = min(95, 55 + (20 if service.name and service.name in text else 0) + (10 if service.product and service.product in text else 0))
                reason = (
                    f"Open {service.protocol}/{service.port} service '{service.name or 'unknown'}' "
                    f"(product: {service.product or 'unknown'}) "
                    f"matches module metadata terms: {', '.join(matches)}."
                )
                recommendations.append(
                    Recommendation(
                        target=str(host.address),
                        port=service.port,
                        protocol=service.protocol,
                        module_type=module.module_type,
                        module_name=module.module_name,
                        confidence=confidence,
                        reason=reason,
                    )
                )
    recommendations.sort(key=lambda item: (-item.confidence, item.target, item.port, item.module_name))
    return AssessmentPlan(workspace=workspace, recommendations=tuple(recommendations))
