from __future__ import annotations

from dataclasses import dataclass, field

from ..integrations.metasploit import MetasploitClient


@dataclass(frozen=True)
class AuxiliaryModuleCandidate:
    """Read-only Metasploit auxiliary metadata matched to an observed technology."""

    module_name: str
    technology: str
    rank: str
    description: str
    check_supported: bool
    required_options: tuple[str, ...]
    options: dict[str, object] = field(default_factory=dict)


def discover_web_auxiliary_modules(
    client: MetasploitClient,
    technologies: tuple[str, ...],
    *,
    max_technologies: int = 3,
    max_modules: int = 8,
) -> tuple[AuxiliaryModuleCandidate, ...]:
    """Find a bounded set of technology-relevant auxiliary modules; never execute them.

    Search terms come only from observed technology names. Results are restricted
    to auxiliary modules and enriched with exact framework metadata/options.
    """
    if not 1 <= max_technologies <= 5 or not 1 <= max_modules <= 20:
        raise ValueError("Metasploit module discovery limits are outside the allowed bounds.")

    candidates: list[AuxiliaryModuleCandidate] = []
    seen: set[str] = set()
    terms = tuple(dict.fromkeys(
        term.strip() for term in technologies if isinstance(term, str) and term.strip()
    ))[:max_technologies]

    for technology in terms:
        results = client.search_modules(technology)
        for result in results:
            if str(result.get("type", "")).casefold() != "auxiliary":
                continue
            raw_name = result.get("fullname") or result.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            module_name = raw_name.removeprefix("auxiliary/").strip()
            if not module_name or module_name in seen:
                continue
            seen.add(module_name)

            metadata, options = client.fetch_module_metadata("auxiliary", module_name)
            if metadata.get("type") not in (None, "auxiliary"):
                continue
            required = tuple(
                str(name) for name, details in options.items()
                if isinstance(details, dict) and details.get("required") is True
            )
            candidates.append(AuxiliaryModuleCandidate(
                module_name=module_name,
                technology=technology,
                rank=str(metadata.get("rank") or result.get("rank") or "unknown").casefold(),
                description=str(metadata.get("description") or result.get("description") or ""),
                check_supported=metadata.get("check") is True,
                required_options=required,
                options=options,
            ))
            if len(candidates) >= max_modules:
                return tuple(candidates)

    return tuple(candidates)
