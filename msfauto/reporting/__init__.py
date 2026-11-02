"""Workspace-scoped assessment report generation."""

from .generator import ReportError, build_report, write_report

__all__ = ["ReportError", "build_report", "write_report"]
