"""Dependency-free stdio MCP server for Custodian Codex Guard."""
from __future__ import annotations

import hmac
import json
import os
import sys
import time
from importlib import metadata
from pathlib import Path
from typing import Any

from .approvals import ApprovalError, ApprovalStore
from .guard import ActionKind
from .receipts import ReceiptChain
from custodian.control.ledger_access_policy import LedgerAccessPolicy
from custodian.control.settings import ControlSettingsStore
# The harness-neutral evaluation engine (evaluate_guard_action and its
# notification/summary helpers) moved to custodian.guard_core.evaluation so
# every guard adapter (Codex, Claude, OpenCode) can reach it without
# depending on this package -- see
# tests/test_architecture_boundaries.py::test_no_guard_imports_another_guard.
# Imported (not re-implemented) here so this module's own MCP handlers, and
# any external caller still importing these names from this exact path
# (already-published codex-guard behavior), keep working unchanged.
from custodian.guard_core.evaluation import (
    NOTABLE_ACTION_KINDS,
    _state_dir,
    evaluate_guard_action,
    notification_line,
    open_gate_summary,
)


def _server_version() -> str:
    """Return the version of the installed distribution serving this process."""
    try:
        return metadata.version("custodian-codex-guard")
    except metadata.PackageNotFoundError:
        # Source checkouts are useful for development handshakes, but only an
        # installed release has authoritative package metadata.
        return "source"


def _text_result(value: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    settings = ControlSettingsStore(_state_dir() / "control-settings.json").load()
    if (
        settings.visibility == "quiet"
        and value.get("verdict") in {"autonomous", "approved"}
        and "receipt" in value
    ):
        # Keep the machine-enforced decision and evidence, but omit explanatory
        # prose that merely tells the model an ordinary gate passed. Hooks are
        # already silent for allowed actions; this makes direct MCP use match.
        value = {
            key: value[key] for key in (
                "verdict", "action_kind", "enforcement_required", "receipt",
            ) if key in value
        }
    return {
        "content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}],
        "structuredContent": value,
        "isError": is_error,
    }


TOOLS = [
    {
        "name": "guard_action",
        "description": (
            "Evaluate a proposed Codex action before execution. A result of "
            "escalation_required is not permission; obtain human approval first."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["tool", "action_kind", "arguments", "workspace", "requester"],
            "properties": {
                "tool": {"type": "string", "minLength": 1},
                "action_kind": {"type": "string", "enum": [k.value for k in ActionKind]},
                "arguments": {"type": "object"},
                "workspace": {"type": "string", "minLength": 1},
                "intent": {"type": "string"},
                "session_id": {"type": "string"},
                "requester": {"type": "string", "minLength": 1},
                "policy_version": {"type": "string"},
                "approval_id": {"type": "string"},
            },
        },
    },
    {
        "name": "verify_receipts",
        "description": "Verify the HMAC hash chain for all local Codex Guard receipts.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
    },
    {
        "name": "wait_for_approval",
        "description": (
            "Wait for the human operator to approve or deny one exact pending "
            "action. The authenticated approval record must match the supplied "
            "approval ID, action digest, requester, and Codex harness."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["approval_id", "action_digest", "requester"],
            "properties": {
                "approval_id": {"type": "string", "minLength": 1},
                "action_digest": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                },
                "requester": {"type": "string", "minLength": 1, "maxLength": 128},
                "timeout_seconds": {
                    "type": "number",
                    "exclusiveMinimum": 0,
                    "maximum": 3600,
                    "default": 300,
                },
            },
        },
    },
    {
        "name": "list_receipts",
        "description": (
            "List recent Codex Guard decision receipts. No harness sees any "
            "receipts by default, including its own -- the operator must "
            "explicitly grant this harness visibility into a target_harness "
            "(see `custodian console`'s ledger-access grants) before this "
            "returns anything. Value-free: no arguments, prompts, or secret "
            "values, ever."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target_harness": {"type": "string", "maxLength": 64},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
        },
    },
]


def wait_for_approval(
    args: dict[str, Any],
    *,
    harness: str = "codex",
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> dict[str, Any]:
    """Wait portably for an authenticated, action-bound approval decision.

    Polling avoids platform-specific filesystem notification APIs and works on
    Windows, macOS, and Linux. Each read verifies the record's HMAC before any
    status is trusted. The approval remains unconsumed for the subsequent exact
    ``guard_action`` replay.
    """
    approval_id = str(args.get("approval_id", ""))
    digest = str(args.get("action_digest", ""))
    requester = str(args.get("requester", ""))
    try:
        timeout = float(args.get("timeout_seconds", 300))
    except (TypeError, ValueError) as exc:
        raise ApprovalError("timeout_seconds must be a number") from exc
    if not (0 < timeout <= 3600):
        raise ApprovalError("timeout_seconds must be greater than 0 and at most 3600")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ApprovalError("invalid action digest")
    if not requester or len(requester) > 128:
        raise ApprovalError("requester must contain 1 to 128 characters")
    if not harness or len(harness) > 64:
        raise ApprovalError("invalid harness identity")

    store = ApprovalStore(_state_dir())
    deadline = monotonic() + timeout
    while True:
        record = store.get(approval_id)  # authenticates the HMAC on every poll
        if not hmac.compare_digest(record.action_digest, digest):
            raise ApprovalError("approval belongs to a different action")
        if not hmac.compare_digest(record.requester, requester):
            raise ApprovalError("approval belongs to a different requester")
        if not hmac.compare_digest(record.harness, harness):
            raise ApprovalError("approval belongs to a different harness")

        now = time.time()
        if now > record.expires_at:
            return {
                "verdict": "expired",
                "approval_id": approval_id,
                "action_digest": digest,
            }
        if record.status == "approved":
            return {
                "verdict": "approved",
                "approval_id": approval_id,
                "action_digest": digest,
                "next_step": (
                    "Retry guard_action once with this approval_id and the exact "
                    "same action arguments."
                ),
            }
        if record.status == "denied":
            return {
                "verdict": "denied",
                "approval_id": approval_id,
                "action_digest": digest,
            }
        if record.status != "pending":
            raise ApprovalError(f"approval cannot be waited on in status {record.status!r}")

        remaining = deadline - monotonic()
        if remaining <= 0:
            return {
                "verdict": "timeout",
                "approval_id": approval_id,
                "action_digest": digest,
            }
        sleep(min(0.25, remaining, max(0.01, record.expires_at - now)))



def list_receipts_for(args: dict[str, Any], *, harness: str = "codex") -> dict[str, Any]:
    """List recent receipts visible to `harness`. `target_harness` in args
    defaults to the caller's own harness, but no harness -- including its
    own -- is visible without an explicit ledger_access_policy grant; an
    ungranted request is a clear denial, not a silent empty list -- this
    mirrors how the rest of this module surfaces policy denials (see
    guard.py's reason strings) rather than letting an ungranted caller
    wonder if the target harness simply has no history.
    """
    if not harness or len(harness) > 64:
        raise ValueError("invalid harness identity")
    model = os.environ.get("CUSTODIAN_TRUSTED_MODEL_ID", "*")
    target = str(args.get("target_harness") or harness)[:64]
    limit = int(args.get("limit") or 50)
    policy = LedgerAccessPolicy(_state_dir() / "ledger-access-policy.json")
    if not policy.can_view(harness=harness, model=model, target_harness=target):
        return {
            "error": (f"{harness!r} is not granted visibility into {target!r}'s receipts -- "
                      "ask the operator to add a ledger access grant via `custodian console`"),
            "harness": harness, "target_harness": target,
        }
    chain = ReceiptChain(_state_dir())
    records = chain.list_visible(policy, harness=harness, model=model, limit=limit)
    if target != harness:
        records = [r for r in records if r.get("harness", "unknown") == target]
    return {"harness": harness, "target_harness": target, "receipts": records, "count": len(records)}


def handle(method: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "custodian-codex-guard",
                "version": _server_version(),
            },
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        chain = ReceiptChain(_state_dir())
        if name == "guard_action":
            decision = evaluate_guard_action(args, harness="codex")
            return _text_result(decision, is_error=decision.get("verdict") == "denied")
        if name == "wait_for_approval":
            try:
                decision = wait_for_approval(args, harness="codex")
                return _text_result(
                    decision,
                    is_error=decision.get("verdict") in {"denied", "expired"},
                )
            except ApprovalError as exc:
                return _text_result(
                    {"verdict": "denied", "reason": str(exc)},
                    is_error=True,
                )
        if name == "verify_receipts":
            try:
                count = chain.verify()
                return _text_result({"valid": True, "receipts": count})
            except Exception as exc:
                return _text_result({"valid": False, "reason": str(exc)}, is_error=True)
        if name == "list_receipts":
            result = list_receipts_for(args, harness="codex")
            return _text_result(result, is_error="error" in result)
        return _text_result({"error": f"unknown tool: {name}"}, is_error=True)
    if method.startswith("notifications/"):
        return None
    raise ValueError(f"method not found: {method}")


def main() -> int:
    for raw in sys.stdin:
        request: Any = None
        try:
            request = json.loads(raw)
            request_id = request.get("id")
            result = handle(request.get("method", ""), request.get("params") or {})
            if request_id is None or result is None:
                continue
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id") if isinstance(request, dict) else None,
                "error": {"code": -32603, "message": str(exc)},
            }
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
