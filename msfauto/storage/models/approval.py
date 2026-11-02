from __future__ import annotations

from dataclasses import dataclass

from .base import utc_now


@dataclass(frozen=True)
class ActionApproval:
    action_id: str
    workspace: str
    target: str
    port: int
    protocol: str
    module_name: str
    decision: str
    approver: str
    decided_at: str = ""
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.decision not in {"approved", "rejected"}:
            raise ValueError("Approval decision must be 'approved' or 'rejected'.")
        if not self.action_id or not self.workspace or not self.target or not self.module_name:
            raise ValueError("Approval records require an action, workspace, target, and module.")
        if not self.approver.strip():
            raise ValueError("An approver identity is required.")
        if not self.decided_at:
            object.__setattr__(self, "decided_at", utc_now())
