"""Codex integration around the harness-neutral Kernel guard."""
from __future__ import annotations

from typing import Any

from custodian.guard_core.guard import (
    ActionKind,
    GuardDecision,
    _inferred_kind,
    evaluate_action as _evaluate_action,
)


def evaluate_action(
    *,
    tool: str,
    action_kind: str,
    arguments: dict[str, Any] | None,
    workspace: str,
    intent: str = "",
    forbidden_paths: list[str] | None = None,
    allow_paths: list[str] | None = None,
    allow_broad_workspace: bool = False,
) -> GuardDecision:
    """Evaluate an action and add optional Codex/Paladin guidance."""
    decision = _evaluate_action(
        tool=tool,
        action_kind=action_kind,
        arguments=arguments,
        workspace=workspace,
        intent=intent,
        forbidden_paths=forbidden_paths,
        allow_paths=allow_paths,
        allow_broad_workspace=allow_broad_workspace,
    )
    if decision.verdict != "escalation_required":
        return decision
    try:
        from . import paladin_bridge

        kind = ActionKind(decision.action_kind)
        if (kind is ActionKind.CREDENTIAL
                or paladin_bridge.refs_in_arguments(arguments or {})):
            guidance = paladin_bridge.credential_guidance(arguments or {})
            if guidance:
                return GuardDecision(
                    verdict=decision.verdict,
                    action_kind=decision.action_kind,
                    reason=decision.reason + guidance,
                    band=decision.band,
                    enforcement_required=decision.enforcement_required,
                    warnings=decision.warnings,
                )
    except Exception:
        pass
    return decision


__all__ = ["ActionKind", "GuardDecision", "evaluate_action"]
