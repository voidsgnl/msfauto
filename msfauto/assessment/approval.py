from __future__ import annotations

import hashlib
import json

from ..storage.models import ActionApproval, Recommendation


def action_id(workspace: str, recommendation: Recommendation) -> str:
    """Stable identity for the exact recommendation being reviewed."""
    payload = {
        "workspace": workspace,
        "target": recommendation.target,
        "port": recommendation.port,
        "protocol": recommendation.protocol,
        "module_type": recommendation.module_type,
        "module_name": recommendation.module_name,
        "risk": recommendation.risk,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def record_decision(
    store,
    workspace: str,
    recommendation: Recommendation,
    decision: str,
    approver: str,
    rationale: str = "",
) -> ActionApproval:
    record = ActionApproval(
        action_id=action_id(workspace, recommendation),
        workspace=workspace,
        target=recommendation.target,
        port=recommendation.port,
        protocol=recommendation.protocol,
        module_name=f"{recommendation.module_type}/{recommendation.module_name}",
        decision=decision,
        approver=approver,
        rationale=rationale,
    )
    store.save_approval(record)
    return record
