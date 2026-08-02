"""Compatibility imports for the Paladin bridge, now owned by Kernel."""

from custodian.guard_core.paladin_bridge import (
    credential_guidance,
    git_helpers,
    paladin_available,
    refs_in_arguments,
    status_summary,
    vault_configured,
    vault_path,
    wire_git_helper,
)

__all__ = [
    "credential_guidance",
    "git_helpers",
    "paladin_available",
    "refs_in_arguments",
    "status_summary",
    "vault_configured",
    "vault_path",
    "wire_git_helper",
]
