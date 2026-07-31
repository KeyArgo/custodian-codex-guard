"""Compatibility imports for approval primitives now owned by Kernel."""

from custodian.guard_core.approvals import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    action_digest,
)

__all__ = ["ApprovalError", "ApprovalRecord", "ApprovalStore", "action_digest"]
