# Custodian Codex Guard

### A second opinion before Codex touches your machine.

Codex Guard evaluates every routed Codex action before it runs. Reads, writes,
shell commands, network calls, credentials, releases, and destructive
operations all pass through policy that the model cannot rewrite.

When an action is safe, Codex continues normally. When an action needs you,
Custodian creates an authenticated, single-use approval bound to the exact
tool, arguments, workspace, requester, and policy version. Change any of those
details and the approval no longer matches.

[Watch the two-minute demo](https://youtu.be/lnIwDIbzZf0).

## Why it exists

Agent permissions are useful, but they answer only one question: may this tool
run? Custodian asks the questions around it:

- Is the declared workspace a real project rather than a home directory or
  filesystem root?
- Does this command cross a network, credential, production, or money
  boundary?
- Has the operator approved this exact action?
- Can we prove afterward what the guard decided without storing the secret or
  prompt that caused it?

Codex Guard supplements Codex's sandbox and approval system. It does not
replace operating-system isolation.

## Install

Version 0.1.3 is available as a GitHub release. It depends on Custodian Kernel
0.4.2.

Install from PyPI:

```bash
pipx install custodian-codex-guard
custodian-codex setup
custodian-codex doctor
```

`setup` installs the packaged Codex plugin, registers the MCP server with the
exact Python interpreter, and installs the `PreToolUse` enforcement hook. Run
it from any directory; a source checkout is not required.

On Linux distributions that enforce PEP 668, use `pipx` or a virtual
environment. Do not use `--break-system-packages`.

## What happens on a tool call

```text
Codex proposes an action
        |
        v
PreToolUse hook classifies and evaluates it
        |
        +-- autonomous or previously approved --> Codex continues
        |
        +-- approval required --> exact action is held for the operator
        |
        +-- denied --> Codex receives a hard block with the reason
        |
        v
Custodian appends a value-free, authenticated receipt
```

The hook fails closed. A malformed event, missing session identity, invalid
workspace, broken approval record, or unexpected verdict becomes a denial.

## Operator commands

```bash
custodian-codex setup
custodian-codex doctor
custodian-codex status
custodian-codex approve latest
custodian-codex deny latest
```

The normal approval path is automatic: Custodian waits for the authenticated
operator decision and the agent can resume without you returning to the chat
to announce that you approved it.

## Gate behavior

The shared Custodian control plane supports open monitoring and protected
operation:

```bash
custodian gates status
custodian gates open
custodian gates protect
custodian gates notifications quiet
```

Open mode records and optionally announces routed actions. Protected mode
requires approval for configured consequential classes. Receipts remain
enabled in both modes.

## Data and uninstall behavior

Removing the Python package does not delete policy, approvals, receipts, gate
preferences, or vault data. Remove the hook before uninstalling:

```bash
custodian-codex hook-uninstall
python -m pip uninstall custodian-codex-guard
```

## Release status

The 0.1.3 release has passed the full monorepo suite, clean-wheel smoke
tests, strict artifact validation, and qualification on Linux and Windows.
macOS qualification remains pending.

Custodian is alpha software and has not received a third-party security audit.
Read [SECURITY.md](SECURITY.md) before using it for consequential actions.

## Links

- [Source](https://github.com/KeyArgo/custodian-codex-guard)
- [Custodian Kernel](https://github.com/KeyArgo/custodian-kernel)
- [Documentation](https://getcustodian.xyz/docs)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
