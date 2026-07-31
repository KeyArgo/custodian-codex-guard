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

from .approvals import ApprovalError, ApprovalStore, action_digest
from .guard import ActionKind, evaluate_action
from .receipts import ReceiptChain
from custodian.control.policy import ApprovalPolicy, Proposal
from custodian.control.filesystem_policy import FilesystemPolicy
from custodian.control.ledger_access_policy import LedgerAccessPolicy
from custodian.control.settings import ControlSettingsStore
from custodian.control.gate_policy import GateContext, GatePolicy
from custodian.control.action_gates import gates_for as _gates_for
from custodian.adapters.builtin._paths import path_values, resolve as canonicalize


_RECOVERY_TOOL_SUFFIXES = (
    "guard_action", "verify_receipts", "list_receipts",
    "_get_app_permissions", "_update_app_permissions",
    "custodian_settings", "gate_settings",
)
def _effective_workspace(declared: str, arguments: dict[str, Any]) -> str:
    """Prefer a tool's concrete working directory over the session root."""
    nested = arguments.get("workdir", arguments.get("cwd"))
    if not isinstance(nested, str) or not nested.strip():
        return declared
    candidate = Path(nested).expanduser()
    if not candidate.is_absolute():
        candidate = Path(declared).expanduser() / candidate
    try:
        return str(candidate.resolve())
    except (OSError, RuntimeError, ValueError):
        return nested


def _argument_paths(arguments: dict[str, Any], workspace: str) -> list[str]:
    try:
        result = []
        for raw in path_values(arguments):
            if not os.path.isabs(os.path.expanduser(raw)):
                raw = str(Path(workspace) / raw)
            resolved = canonicalize(raw)
            if resolved not in result:
                result.append(resolved)
        return result
    except (OSError, RuntimeError, TypeError, ValueError):
        return []


def _recovery_tool(tool: str) -> bool:
    normalized = tool.strip().lower()
    return any(normalized.endswith(suffix) for suffix in _RECOVERY_TOOL_SUFFIXES)


def _server_version() -> str:
    """Return the version of the installed distribution serving this process."""
    try:
        return metadata.version("custodian-codex-guard")
    except metadata.PackageNotFoundError:
        # Source checkouts are useful for development handshakes, but only an
        # installed release has authoritative package metadata.
        return "source"


def _state_dir() -> Path:
    configured = os.environ.get("CUSTODIAN_CODEX_GUARD_STATE_DIR")
    return Path(configured).expanduser() if configured else Path.home() / ".custodian"


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


def evaluate_guard_action(args: dict[str, Any], *, harness: str = "codex") -> dict[str, Any]:
    """Evaluate one exact proposal for any supported harness.

    Harness identity is supplied by the trusted adapter, never by model tool
    arguments. Operator policy is applied to every action, including otherwise
    autonomous reads/writes, so an explicit deny/ask rule cannot be skipped.
    """
    if not harness or len(harness) > 64:
        raise ValueError("invalid harness identity")
    chain = ReceiptChain(_state_dir())
    try:
        model = os.environ.get("CUSTODIAN_TRUSTED_MODEL_ID", "*")
        requested_kind = str(args.get("action_kind", ""))
        declared_workspace = str(args.get("workspace", ""))
        tool_arguments = args.get("arguments")
        if not isinstance(tool_arguments, dict):
            tool_arguments = {}
        workspace = _effective_workspace(declared_workspace, tool_arguments)
        session_id = str(args.get("session_id", "default"))
        paths = _argument_paths(tool_arguments, workspace)
        path = paths[0] if paths else ""
        gate_policy = GatePolicy(_state_dir() / "gate-policy.json")
        filesystem_gate = (
            "filesystem_read" if requested_kind == "read" else "filesystem_write"
        )
        explicit_broad_allow = any(
            (
                mode == "allow"
                and not rule_id.startswith("default:")
                and scope in {"path", "project"}
            )
            for mode, rule_id, scope in (
                gate_policy.decide(GateContext(
                    gate=filesystem_gate, harness=harness,
                    tool=str(args.get("tool", "")), session_id=session_id,
                    project=workspace, path=candidate_path,
                ))
                for candidate_path in (paths or [""])
            )
        )
        access = "read" if requested_kind == "read" else "write"
        fs_config = FilesystemPolicy(_state_dir() / "filesystem-policy.json").fence_config(
            harness=harness, model=model, access=access,
            inherited_allow=[workspace],
            # `~/.codex` (and `~/.claude`) hold the guard's own hook wiring and
            # policy; fencing them here stops a bash redirect like
            # `echo ... >> ~/.codex/config.toml` from disabling the guard the way
            # only an apply_patch write was already caught (guard.py
            # _SENSITIVE_WRITE_PATH). Self-protection, not user data.
            # OpenCode's guard plugin lives under `~/.config/opencode/plugins/`
            # (XDG convention, unlike Codex/Claude's direct dotfile homes) --
            # see opencode_guard/cli.py's _plugin_path(). Same bash-redirect
            # self-disable risk applies there too. This literal doesn't
            # follow a custom $XDG_CONFIG_HOME override, matching the other
            # entries here, which are also plain literals.
            inherited_deny=["~/.ssh", "~/.aws", "~/.config/gcloud", "~/.kube",
                            "~/.codex", "~/.claude", "~/.config/opencode"],
        )
        decision = evaluate_action(
            tool=args.get("tool", ""), action_kind=requested_kind,
            arguments=tool_arguments, workspace=workspace,
            intent=args.get("intent", ""), forbidden_paths=fs_config["forbidden_paths"],
            allow_paths=fs_config["allow_paths"],
            allow_broad_workspace=(
                fs_config["source"] != "harness-default"
                or _recovery_tool(str(args.get("tool", "")))
                or explicit_broad_allow
            ),
        ).to_dict()
        decision["declared_workspace"] = declared_workspace
        decision["effective_workspace"] = workspace
        decision["filesystem_policy"] = {
            "harness": harness, "model": model, "source": fs_config["source"],
            "enforcement": fs_config["enforcement"],
        }
        control_settings = ControlSettingsStore(
            _state_dir() / "control-settings.json"
        ).load()
        if (
            decision["verdict"] == "denied"
            and control_settings.enforcement_for(harness) == "open"
        ):
            observed_reason = decision["reason"]
            decision.update(
                verdict="autonomous",
                reason=(
                    "open monitor mode observed a mandatory detector finding; "
                    "execution is allowed"
                ),
                band="L1",
                monitor_observation=observed_reason,
            )
        requester = args["requester"]
        proposal_digest = action_digest(
            tool=args["tool"], action_kind=decision["action_kind"],
            arguments=tool_arguments, workspace=workspace,
            requester=requester,
            policy_version=args.get("policy_version", "default"),
        )
        proposal = Proposal(
            adapter=harness, action_kind=decision["action_kind"],
            tool=args["tool"], requester=requester, workspace=workspace,
        )
        legacy_mode, legacy_rule_id = ApprovalPolicy(
            _state_dir() / "approval-policy.json"
        ).decide(proposal)

        entered = []
        for gate in _gates_for(
            tool=args["tool"], kind=decision["action_kind"],
            arguments=tool_arguments, workspace=workspace, paths=paths,
        ):
            candidate_paths = paths if gate in {
                "filesystem_read", "filesystem_write", "outside_workspace",
            } and paths else [""]
            candidates = [
                gate_policy.decide(GateContext(
                    gate=gate, harness=harness, tool=args["tool"],
                    session_id=session_id, project=workspace,
                    path=candidate_path, action_digest=proposal_digest,
                ))
                for candidate_path in candidate_paths
            ]
            priority = {"allow": 0, "ask": 1, "block": 2}
            gate_mode, gate_rule_id, scope = max(
                candidates, key=lambda item: priority[item[0]]
            )
            entered.append({
                "gate": gate, "mode": gate_mode, "rule_id": gate_rule_id,
                "scope": scope,
            })
        decision["gates"] = entered
        decision["notification"] = {
            "event": "gate_decision",
            "tool": str(args["tool"])[:128],
            "destination": path or workspace,
            "result": decision["verdict"],
            "controls": ["Block", "Ask next time", "Allow for session", "Settings"],
        }

        # Mandatory adapter denials always win. Granular block/ask/allow is
        # next. A stored legacy rule remains effective during migration.
        blocked = next((g for g in entered if g["mode"] == "block"), None)
        asked = next((g for g in entered if g["mode"] == "ask"), None)
        if decision["verdict"] != "denied" and blocked:
            decision.update(
                verdict="denied", reason=f"{blocked['gate']} gate is blocked",
                policy_rule_id=blocked["rule_id"], policy_scope=blocked["scope"],
                band="L4",
            )
        elif decision["verdict"] != "denied" and legacy_mode == "deny":
            decision.update(verdict="denied", reason="blocked by operator policy",
                            policy_rule_id=legacy_rule_id)
        elif decision["verdict"] != "denied" and asked:
            decision.update(verdict="escalation_required",
                            reason=f"{asked['gate']} gate requires approval",
                            policy_rule_id=asked["rule_id"],
                            policy_scope=asked["scope"], band="L3")
        elif (
            decision["verdict"] != "denied"
            and legacy_mode == "ask"
            and legacy_rule_id
        ):
            decision.update(
                verdict="escalation_required",
                reason="matching legacy operator policy requires approval",
                policy_rule_id=legacy_rule_id, band="L3",
            )
        elif (
            decision["verdict"] == "escalation_required"
            and legacy_mode == "auto"
            and legacy_rule_id
        ):
            # Preserve explicit legacy auto-rule evidence during migration:
            # the exact action is still minted, approved, and consumed below.
            pass
        elif decision["verdict"] == "escalation_required":
            # The old action band escalated this action, but every granular
            # gate that applies is explicitly/default allowed.
            decision.update(
                verdict="autonomous",
                reason="all entered gates allow this action with auditing",
                band="L1",
            )

        if decision["verdict"] == "escalation_required":
            digest = proposal_digest
            store = ApprovalStore(_state_dir())
            approval_id = args.get("approval_id")
            # Hook-based harnesses can't replay an approval_id through a tool
            # call, so bind the identical re-run to an out-of-band operator
            # approval by its digest instead. Only ever finds an approval the
            # operator already granted for this exact action + requester.
            if not approval_id:
                approval_id = store.find_approved(digest=digest, requester=requester)
            if approval_id:
                store.consume(approval_id, digest=digest, requester=requester)
                decision.update(verdict="approved",
                                reason="exact action approved once by the human operator",
                                approval_id=approval_id)
            elif legacy_mode == "auto" and legacy_rule_id:
                exact = store.request(digest=digest, requester=requester, harness=harness)
                store.approve(exact.approval_id, approved_by=f"policy:{legacy_rule_id}",
                              expected_digest=digest)
                store.consume(exact.approval_id, digest=digest, requester=requester)
                decision.update(verdict="approved",
                                reason="exact action approved by scoped operator policy",
                                approval_id=exact.approval_id,
                                policy_rule_id=legacy_rule_id)
            else:
                pending = store.request(digest=digest, requester=requester, harness=harness)
                decision.update(
                    approval_id=pending.approval_id, action_digest=digest,
                    approval_expires_at=pending.expires_at,
                    next_step=("Open `custodian console`, or ask the operator to run: "
                               f"custodian-codex approve {pending.approval_id} --digest {digest}"),
                )
        decision["notification"]["result"] = decision["verdict"]
        receipt = chain.append(decision, tool=args.get("tool", ""),
                               session_id=session_id, harness=harness)
        decision["receipt"] = {"timestamp": receipt["ts"], "chain_mac": receipt["mac"]}
        return decision
    except ApprovalError as exc:
        denied = {"verdict": "denied", "reason": str(exc),
                  "action_kind": str(args.get("action_kind", "unknown")),
                  "band": "L4", "enforcement_required": True}
        receipt = chain.append(denied, tool=args.get("tool", ""),
                               session_id=args.get("session_id", "default"), harness=harness)
        denied["receipt"] = {"timestamp": receipt["ts"], "chain_mac": receipt["mac"]}
        return denied
    except Exception as exc:
        denied = {
            "verdict": "denied",
            "reason": f"guard evaluation failed closed ({type(exc).__name__})",
            "action_kind": str(args.get("action_kind", "unknown")),
            "band": "L4",
            "enforcement_required": True,
        }
        try:
            receipt = chain.append(
                denied, tool=str(args.get("tool", "")),
                session_id=str(args.get("session_id", "default")),
                harness=harness,
            )
            denied["receipt"] = {
                "timestamp": receipt["ts"], "chain_mac": receipt["mac"],
            }
        except Exception:
            pass
        return denied


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
