# Custodian Guard for Codex

*(OpenAI Build Week, July 2026)*

A capability firewall for coding agents. Codex can inspect, test, and edit
inside an approved workspace; credential use, network operations, destructive
commands, production changes, money movement, and governance changes stop at a
human-approval boundary. Every decision produces a value-free HMAC hash-chained
receipt. Classification is deterministic — typed action-kind rules over the
tool name and arguments, not a model call — so a mislabeled or adversarial
proposal can't talk its way past the boundary by re-describing itself.

This is the Build Week contribution specifically: the Codex-facing MCP server,
the policy bridge, the receipts CLI, and the governance skill. It depends on
[`custodian-kernel`](https://github.com/KeyArgo/custodian-kernel) — the
policy engine, adapter pipeline, and approval/filesystem/ledger-access
policies — which is agent-agnostic and predates this Build Week.

This plugin is generic. It does not know about any particular website, IDE,
or operator. A site or IDE is a client of the MCP boundary, never part of the
kernel.

## Install for judging

Python 3.11 or later:

```bash
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
custodian-codex setup
custodian-codex doctor
```

`pip install -e .` pulls in `custodian-kernel>=0.4.0,<0.5` automatically —
nothing else to install first. Start a new Codex thread after `setup` so it
loads the plugin. The plugin manifest is at
`plugins/custodian-codex-guard/.codex-plugin/plugin.json`; its governance
skill is at `plugins/custodian-codex-guard/skills/govern-codex/SKILL.md`.

If the integration itself is broken, the operator — not the model — can run
`custodian-codex disable`. This removes the Codex plugin while deliberately
preserving receipts and approvals for diagnosis; `custodian-codex setup`
restores it. Start a new Codex thread after either change.

## Sixty-second proof

```bash
python scripts/codex-guard-demo.py
pytest -q tests/
```

The demo performs no network calls and changes no external state. It shows a
safe test and workspace edit passing, `.env` access being denied, deliberately
misclassified delete/deploy commands being independently upgraded to human
escalation, a valid receipt chain, and rejection after receipt tampering.
106 tests cover the full threat model.

## Enforcement contract

`guard_action` returns `autonomous`, `escalation_required`, `approved`, or
`denied`. An escalation is never permission. The model can create a pending
request but cannot approve it; the operator runs the returned
`custodian-codex approve ID --digest DIGEST` outside the model tool boundary.
Approval binds the exact tool, effective risk class, arguments, resolved
workspace, requester, and policy version — any change requires a fresh
request, never a reused approval ID.

No harness — including Codex itself — can read the receipt ledger by
default, not even its own history. Visibility is only ever an explicit
operator grant. The agent being governed is exactly the party a denial log
exists to constrain; letting it read its own denial history would turn the
ledger into an oracle it could probe to learn the enforcement boundary and
route around it.

## What's in this repo vs. the kernel

- **Here:** `custodian/codex_guard/` (MCP server, risk classification,
  receipts, approvals, CLI), `plugins/custodian-codex-guard/` (Codex plugin
  manifest + governance skill), tests, judge demo script.
- **In `custodian-kernel`:** the adapter pipeline (workspace/secret/prompt-
  injection/egress guards), `ApprovalPolicy`, `FilesystemPolicy`,
  `LedgerAccessPolicy` — the policy engine every action is actually checked
  against.

See [`docs/CODEX_GUARD.md`](docs/CODEX_GUARD.md) for the full judge guide.
