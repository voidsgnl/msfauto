"""Compatibility exports; job execution lives in :mod:`msfauto.execution`."""
from .execution import CheckRequest, JobError, JobManager, SafeCheckAdapter

__all__ = ["CheckRequest", "JobError", "JobManager", "SafeCheckAdapter"]
