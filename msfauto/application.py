"""Compatibility exports; application orchestration lives in :mod:`msfauto.core`."""
from .core.orchestrator import AssessmentApplication, WorkflowError

__all__ = ["AssessmentApplication", "WorkflowError"]
