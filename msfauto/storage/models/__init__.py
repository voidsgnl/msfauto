"""Persistent and domain records used across MSFAuto."""

from .assessment import (
    AssessmentEvent, AssessmentPlan, AssessmentRun, DiscoveryRun,
    ModuleMetadata, Recommendation,
)
from .base import IPAddress, IPNetwork, utc_now
from .job import CheckJob, JobEvent
from .service import Service
from .target import Host
from .workspace import ScopePolicy, Workspace

__all__ = [
    "IPAddress", "IPNetwork", "utc_now", "ScopePolicy", "Workspace",
    "Service", "Host", "DiscoveryRun", "ModuleMetadata", "Recommendation",
    "AssessmentPlan", "AssessmentRun", "AssessmentEvent", "JobEvent", "CheckJob",
]
